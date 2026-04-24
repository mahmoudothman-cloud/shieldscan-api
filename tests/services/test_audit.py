"""Tests for app.services.audit — Sub-task 2.3.2."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.identity import Organization, User
from app.services.audit import (
    ALL_ACTION_ENUMS,
    AuditDetails,
    AuthAction,
    ProjectAction,
    audit,
)
from tests.conftest import use_org


async def _make_org_and_user(db_session):
    org = Organization(name="Org X", slug=f"orgx-{uuid4().hex[:8]}")
    user = User(
        email=f"{uuid4().hex[:8]}@example.com",
        hashed_password="x",
        full_name="Test User",
    )
    db_session.add_all([org, user])
    await db_session.flush()
    await use_org(db_session, org.id)
    return org, user


# ---------------------------------------------------------------- enum


def test_auth_action_enum_covers_m23_events():
    """All events M2.3 endpoints must emit."""
    for name in (
        "USER_REGISTERED",
        "LOGIN_SUCCESS",
        "LOGIN_FAILURE",
        "LOGOUT",
        "TOKEN_REFRESHED",
        "TOKEN_REVOKED",
    ):
        assert hasattr(AuthAction, name), f"missing M2.3 action {name}"


def test_auth_action_enum_reserves_later_m2_events():
    """Reserved values locked in now so the enum doesn't churn as
    later M2 endpoints (password reset, email verification, API
    key events) arrive."""
    for name in (
        "PASSWORD_CHANGED",
        "EMAIL_VERIFIED",
        "EMAIL_VERIFICATION_SENT",
        "PASSWORD_RESET_REQUESTED",
        "PASSWORD_RESET_COMPLETED",
        "API_KEY_CREATED",
        "API_KEY_REVOKED",
    ):
        assert hasattr(AuthAction, name), f"missing reserved action {name}"


def test_auth_action_values_are_dotted_strings():
    """The audit contract: stored value is the dotted string, not the
    enum name. SIEM queries and log consumers depend on this exact
    format — renaming a value is a breaking change."""
    assert AuthAction.USER_REGISTERED.value == "user.registered"
    assert AuthAction.LOGIN_SUCCESS.value == "auth.login.success"
    assert AuthAction.LOGIN_FAILURE.value == "auth.login.failure"
    assert AuthAction.API_KEY_REVOKED.value == "auth.api_key.revoked"
    # Every value must contain a dot — catches accidental underscore values.
    for action in AuthAction:
        assert "." in action.value, f"{action.name} must use dotted-string value"


def test_auth_action_values_are_unique():
    values = [a.value for a in AuthAction]
    assert len(values) == len(set(values))


# ---------------------------------------------------------------- ProjectAction (Task 3.2 audit-split)


def test_project_action_enum_covers_m31_and_m32_events():
    """Pin the M3 events that are emitted today (Task 3.1 back-fill +
    3.2 verification)."""
    for name in (
        "PROJECT_CREATED",
        "PROJECT_UPDATED",
        "PROJECT_ARCHIVED",
        "PROJECT_DOMAIN_VERIFIED",
        "PROJECT_DOMAIN_VERIFICATION_FAILED",
    ):
        assert hasattr(ProjectAction, name), f"missing {name}"


def test_project_action_values_are_dotted_strings():
    for action in ProjectAction:
        assert "." in action.value, (
            f"{action.name} must use dotted-string value; got {action.value!r}"
        )
    assert ProjectAction.PROJECT_DOMAIN_VERIFIED.value == "project.domain.verified"


def test_action_enum_values_are_globally_disjoint():
    """Load-bearing regression guard for the audit-enum split.

    If this test fails: a string value is duplicated across two
    action enums (e.g. AuthAction.X.value == ProjectAction.Y.value).
    The audit_logs.action column accepts strings from any enum, so
    a duplicate value would make queries ambiguous about which
    domain the event belongs to.

    Auto-grows: ALL_ACTION_ENUMS in src/app/services/audit.py is
    the single registry. Adding a new enum (e.g. ScanAction) plus
    appending it to ALL_ACTION_ENUMS extends this test's coverage
    automatically.
    """
    all_values: list[str] = []
    for enum_class in ALL_ACTION_ENUMS:
        all_values.extend(e.value for e in enum_class)
    duplicates = [v for v in set(all_values) if all_values.count(v) > 1]
    assert not duplicates, (
        f"Action enum values must be globally unique across "
        f"{[c.__name__ for c in ALL_ACTION_ENUMS]}; duplicates: {duplicates}"
    )


def test_action_enum_registry_lists_all_known_enums():
    """ALL_ACTION_ENUMS must contain every action enum defined in
    audit.py. Catches a future engineer adding a new enum but
    forgetting to register it (which would silently bypass the
    disjointness check)."""
    from app.services import audit as audit_module
    from enum import Enum as _Enum

    declared_enums = {
        obj
        for name, obj in vars(audit_module).items()
        if isinstance(obj, type)
        and issubclass(obj, _Enum)
        and name.endswith("Action")
    }
    registered = set(ALL_ACTION_ENUMS)
    missing = declared_enums - registered
    assert not missing, (
        f"action enums declared but NOT in ALL_ACTION_ENUMS: "
        f"{[e.__name__ for e in missing]} — add them to the registry"
    )


# ---------------------------------------------------------------- audit()


@pytest.mark.asyncio
async def test_audit_writes_row_with_all_fields(db_session):
    org, user = await _make_org_and_user(db_session)

    target_id = uuid4()
    details: AuditDetails = {"reason": "test", "token_jti": str(uuid4())}
    row = await audit(
        db_session,
        organization_id=org.id,
        actor_id=user.id,
        action=AuthAction.LOGIN_FAILURE,
        resource_type="user",
        resource_id=target_id,
        ip_address="203.0.113.7",
        user_agent="pytest/1.0",
        details=details,
    )
    assert row.id is not None
    assert row.organization_id == org.id
    assert row.actor_id == user.id
    assert row.action == "auth.login.failure"
    assert row.resource_type == "user"
    assert row.resource_id == target_id
    # INET on asyncpg comes back as str — we only passed a bare IP.
    assert str(row.ip_address).startswith("203.0.113.7")
    assert row.user_agent == "pytest/1.0"
    assert row.details == {"reason": "test", "token_jti": details["token_jti"]}


@pytest.mark.asyncio
async def test_audit_writes_minimal_row(db_session):
    """actor_id None (system event), no resource_id, no ip/ua, no details."""
    org, _ = await _make_org_and_user(db_session)

    row = await audit(
        db_session,
        organization_id=org.id,
        actor_id=None,
        action=AuthAction.USER_REGISTERED,
        resource_type="user",
    )
    assert row.actor_id is None
    assert row.resource_id is None
    assert row.ip_address is None
    assert row.user_agent is None
    assert row.details is None


@pytest.mark.asyncio
async def test_audit_stores_details_as_jsonb_dict(db_session):
    """Round-trip through Postgres: dict in -> dict out with identical keys."""
    org, user = await _make_org_and_user(db_session)

    details: AuditDetails = {
        "reason": "wrong_password",
        "target_user_id": str(uuid4()),
    }
    await audit(
        db_session,
        organization_id=org.id,
        actor_id=user.id,
        action=AuthAction.LOGIN_FAILURE,
        resource_type="user",
        details=details,
    )

    # Re-read from DB to prove the JSONB round-trip.
    result = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "auth.login.failure")
    )
    row = result.scalar_one()
    assert row.details == dict(details)


@pytest.mark.asyncio
async def test_audit_does_not_dedupe_within_transaction(db_session):
    """Regression guard: two identical audit() calls in the same
    transaction produce two rows. Idempotency is the caller's
    responsibility, not the helper's — documented in the module
    docstring. Changing this behavior is a design decision, not a
    silent refactor.
    """
    org, user = await _make_org_and_user(db_session)

    for _ in range(2):
        await audit(
            db_session,
            organization_id=org.id,
            actor_id=user.id,
            action=AuthAction.LOGIN_SUCCESS,
            resource_type="user",
            resource_id=user.id,
        )

    result = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "auth.login.success")
    )
    rows = result.scalars().all()
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_audit_created_at_is_utc_aware(db_session):
    org, user = await _make_org_and_user(db_session)

    row = await audit(
        db_session,
        organization_id=org.id,
        actor_id=user.id,
        action=AuthAction.LOGOUT,
        resource_type="user",
    )
    assert isinstance(row.created_at, datetime)
    assert row.created_at.tzinfo is not None
    assert row.created_at.utcoffset().total_seconds() == 0


@pytest.mark.asyncio
async def test_audit_returns_the_persisted_row(db_session):
    """Callers needing the audit id (e.g. for correlation with trace
    spans) can get it directly from the return value."""
    org, user = await _make_org_and_user(db_session)

    row = await audit(
        db_session,
        organization_id=org.id,
        actor_id=user.id,
        action=AuthAction.TOKEN_REFRESHED,
        resource_type="user",
    )
    assert row.id is not None
    # And it's queryable in the same session.
    found = await db_session.get(AuditLog, row.id)
    assert found is not None
    assert found.id == row.id
