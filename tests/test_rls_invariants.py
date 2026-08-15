"""Forcing functions for the RLS remediation.

The original defect was NOT a missing ``SET ROLE``. It was that nothing could
detect its absence: dbdccfd's commit message asserted "The app connects / tests
SET ROLE to this", the diff never implemented the app half, and the suite —
which did ``SET ROLE`` in its own fixture — reported tenant isolation as
verified while production served every request as a superuser that bypassed
RLS entirely.

These tests exist so that specific class of drift cannot recur silently. Each
one fails loudly if an assumption the design rests on stops being true.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from sqlalchemy import event, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session as BaseSession

from app.config import Settings, settings
from app.db.policies import TENANT_TABLES
from app.db.tenant_context import TENANT_GUC, TenantSession, set_tenant_context
from app.db.tenant_guard import MissingTenantContextError

SRC = Path(__file__).parent.parent / "src" / "app"


def _python_files() -> list[Path]:
    return [p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts]


# ------------------------------------------------- 1. connection identity


@pytest.mark.asyncio
async def test_app_role_is_neither_superuser_nor_bypassrls(db_session):
    """The role the app connects as must not be able to bypass RLS.

    THE test of the set. A superuser or a BYPASSRLS role ignores every policy
    unconditionally — FORCE ROW LEVEL SECURITY does not override that — so the
    entire tenant-isolation layer is inert no matter how correct the policies
    are. This is the assertion that would have contradicted dbdccfd's commit
    message on day one.

    Runs against the session the suite actually uses, so it also proves the
    harness is exercising the enforced path rather than simulating it.
    """
    row = (
        await db_session.execute(
            text(
                "SELECT current_user, "
                "       (SELECT rolsuper FROM pg_roles WHERE rolname = current_user), "
                "       (SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user)"
            )
        )
    ).one()
    current_user, is_super, bypasses = row
    assert not is_super, (
        f"the app connects as {current_user!r}, a SUPERUSER — RLS policies are "
        "bypassed unconditionally and tenant isolation is inert"
    )
    assert not bypasses, (
        f"the app connects as {current_user!r}, which has BYPASSRLS — RLS "
        "policies are bypassed and tenant isolation is inert"
    )


def test_configured_app_role_is_not_the_owner():
    """DATABASE_URL and MIGRATION_DATABASE_URL must not converge on one role.

    Migrations need the owner (DDL + CREATE ROLE); the app must not have it.
    Skipped until the split is configured so this lands green pre-cutover.
    """
    if not settings.MIGRATION_DATABASE_URL:
        pytest.skip("MIGRATION_DATABASE_URL not configured yet (pre-cutover)")
    app_user = make_url(settings.DATABASE_URL).username
    owner_user = make_url(settings.MIGRATION_DATABASE_URL).username
    if app_user == owner_user:
        pytest.skip(
            "DATABASE_URL still points at the owner — expected until the "
            "cutover flips it to the app role"
        )
    assert app_user == settings.APP_DB_USER


# ------------------------------------------------- 2. no unguarded statement paths


def test_no_engine_level_connect_or_begin_in_src():
    """Every runtime statement must go through a Session.

    The tenant guard hooks ``do_orm_execute``, which only fires for
    Session-mediated statements. An ``engine.connect()`` / ``engine.begin()``
    would execute outside the guard entirely — and under RLS a connection with
    no tenant context returns zero rows silently rather than raising.
    """
    offenders: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in ("connect", "begin"):
                continue
            obj = node.func.value
            # db.begin() / session.begin() is a Session transaction — fine.
            # engine.connect() / engine.begin() is not.
            name = getattr(obj, "id", None) or getattr(obj, "attr", None) or ""
            if "engine" in name.lower():
                offenders.append(f"{path.relative_to(SRC.parent.parent)}:{node.lineno} {name}.{node.func.attr}()")
    assert not offenders, (
        "engine-level connect()/begin() bypasses the tenant guard:\n  "
        + "\n  ".join(offenders)
    )


def test_no_text_statement_names_a_tenant_table():
    """No raw ``text()`` SQL may target a tenant table.

    The guard identifies tenant tables by ORM mapper, which a ``text()``
    statement has none of. Today every tenant-table access is an ORM statement
    (the only ``text()`` SQL in the app is the tenant GUC, a health probe and a
    DDL index predicate), so the guard's coverage is complete. This keeps it
    that way instead of maintaining a list of documented exceptions.
    """
    pattern = re.compile(r"""text\(\s*f?["']([^"']{4,})["']""")
    tenant = re.compile(r"\b(" + "|".join(TENANT_TABLES) + r")\b", re.I)
    offenders: list[str] = []
    for path in _python_files():
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            for sql in pattern.findall(line):
                if tenant.search(sql):
                    offenders.append(
                        f"{path.relative_to(SRC.parent.parent)}:{lineno}: {sql[:70]}"
                    )
    assert not offenders, (
        "raw text() SQL against a tenant table is invisible to the tenant "
        "guard:\n  " + "\n  ".join(offenders)
    )


# ------------------------------------------------- 3. one setter


def test_no_direct_tenant_guc_assignment_outside_the_setter():
    """``app.current_org_id`` may only be set by ``set_tenant_context``.

    Under the after_begin re-apply, a site that issues the SET but forgets to
    record the session intent works until the request's first commit and then
    silently loses tenant context — a subtler failure than never setting it.
    One setter writing both halves is what makes them inseparable.
    """
    allowed = {"db/tenant_context.py", "db/policies.py", "db/__init__.py"}
    guc = re.compile(r"(SET\s+app\.current_org_id|set_config\(\s*'app\.current_org_id)")
    offenders: list[str] = []

    for path in _python_files():
        rel = str(path.relative_to(SRC))
        if rel in allowed:
            continue
        tree = ast.parse(path.read_text())
        # Docstrings legitimately DESCRIBE the GUC (audit.py, the consumers).
        # Only real string literals count, so collect docstring nodes to skip.
        docstrings = {
            id(node.body[0].value)
            for node in ast.walk(tree)
            if isinstance(
                node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            )
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        }
        for node in ast.walk(tree):
            if id(node) in docstrings:
                continue
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                literal = node.value
            elif isinstance(node, ast.JoinedStr):  # f-string
                literal = "".join(
                    v.value
                    for v in node.values
                    if isinstance(v, ast.Constant) and isinstance(v.value, str)
                )
            else:
                continue
            if guc.search(literal):
                offenders.append(f"{rel}:{node.lineno}: {literal.strip()[:70]}")

    assert not offenders, (
        "set the tenant GUC via app.db.tenant_context.set_tenant_context "
        "instead:\n  " + "\n  ".join(offenders)
    )


# ------------------------------------------------- 4. listener scoping


def test_no_globally_registered_session_listeners():
    """Tenant listeners must be on TenantSession, never on ``orm.Session``.

    A listener on the base class applies to every session in the process. The
    harness builds an engine per test, so a globally-registered handler leaks
    across tests — and while proving this design out, exactly that masked the
    failure under test: a stale ``after_begin`` from a previous engine kept
    applying the GUC for an engine configured not to, and the drift case
    appeared to pass.
    """
    leaked = {
        name: fns
        for name in ("do_orm_execute", "after_begin", "after_commit", "after_flush")
        if (fns := _listeners_on_base(name))
    }
    assert not leaked, (
        f"session listeners registered globally on orm.Session: {leaked}. "
        "Register them on TenantSession instead — a base-class listener "
        "applies to every session in the process and leaks across tests."
    )


def _listeners_on_base(name: str) -> list[str]:
    """Listeners registered directly on ``orm.Session`` for ``name``.

    Reads ``dispatch.<event>._clslevel``, a dict keyed by the class the
    listener was registered on: a handler bound to TenantSession appears under
    TenantSession, one bound to the base appears under Session (and also
    propagates into every subclass, which is the leak).

    That attribute is private. If it ever disappears this raises rather than
    returning nothing — a forcing function that silently stops checking is the
    exact failure mode this file exists to prevent.
    """
    dispatch = getattr(BaseSession.dispatch, name, None)
    if dispatch is None:
        return []
    clslevel = getattr(dispatch, "_clslevel", None)
    if clslevel is None:
        raise AssertionError(
            f"cannot introspect listeners for {name!r}: SQLAlchemy's private "
            "dispatch._clslevel is gone. Update this check — do not let it "
            "silently pass."
        )
    return [
        getattr(fn, "__name__", repr(fn))
        for cls, fns in clslevel.items()
        if cls is BaseSession
        for fn in fns
    ]


# ------------------------------------------------- 5. guard behaviour


def test_tenant_guard_default_is_enabled():
    """The kill-switch defaults ON.

    A silently-disabled guard is the same failure class as the decorative GUC
    it replaces, so the default must never drift to off.
    """
    assert Settings.model_fields["TENANT_GUARD_ENABLED"].default is True


@pytest.mark.asyncio
async def test_guard_raises_on_tenant_query_without_context(db_session):
    """A tenant-table read with no tenant context raises, not returns empty."""
    from app.models.projects import Project
    from sqlalchemy import select

    db_session.info.clear()  # simulate a call site that never set context
    with pytest.raises(MissingTenantContextError) as exc:
        await db_session.execute(select(Project))
    assert "projects" in str(exc.value)


@pytest.mark.asyncio
async def test_guard_allows_tenant_query_with_context(db_session):
    """The healthy path is unaffected — no false positives."""
    from uuid import uuid4

    from sqlalchemy import select

    from app.models.identity import Organization
    from app.models.projects import Project

    org = Organization(name="Guard Org", slug=f"guard-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await set_tenant_context(db_session, org.id)
    assert (await db_session.execute(select(Project))).scalars().all() == []


@pytest.mark.asyncio
async def test_write_without_tenant_context_is_rejected_by_the_database(db_session):
    """Writes are covered by the policy, not by the guard.

    ``do_orm_execute`` does NOT fire for unit-of-work flush INSERTs (verified),
    so ``session.add()`` + flush is outside the guard. That is not a hole: the
    policy's WITH CHECK clause rejects an INSERT whose organization_id does not
    match the GUC, so a write without tenant context raises an RLS violation
    rather than writing another tenant's row. Reads are the silent case and are
    the guard's job; writes fail closed at the database.
    """
    from uuid import uuid4

    from app.models.identity import Organization
    from app.models.projects import Project

    org = Organization(name="NoCtx Org", slug=f"noctx-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()

    db_session.info.clear()  # no tenant context
    db_session.add(
        Project(
            organization_id=org.id,
            name="orphan",
            target_url="https://noctx.example",
            root_domain="noctx.example",
        )
    )
    with pytest.raises(Exception) as exc:
        await db_session.flush()
    assert "row-level security" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_tenant_guc_is_set_by_the_helper(db_session):
    """The helper actually applies the GUC, not just the session intent."""
    from uuid import uuid4

    from app.models.identity import Organization

    org = Organization(name="GUC Org", slug=f"guc-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await set_tenant_context(db_session, org.id)

    live = (
        await db_session.execute(text(f"SELECT current_setting('{TENANT_GUC}', true)"))
    ).scalar()
    assert live == str(org.id)


def test_tenant_listeners_are_registered_on_tenant_session():
    """Positive counterpart: the listeners exist where they are supposed to."""
    from app.db.tenant_context import _reapply_tenant_guc
    from app.db.tenant_guard import _check_tenant_context

    assert event.contains(TenantSession, "after_begin", _reapply_tenant_guc)
    assert event.contains(TenantSession, "do_orm_execute", _check_tenant_context)
