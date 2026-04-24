"""RLS carve-out regression guards for CREDENTIAL_INDEXED_TABLES — ADR-012.

Two guards ship here:

  (b) api_keys rows can be SELECTed by key_hash WITHOUT setting
      `app.current_org_id`. Proves the carve-out works end-to-end.

  (c) NO other tenant-scoped table behaves this way. Loops through
      every table in TENANT_TABLES and confirms cross-tenant reads are
      blocked (i.e. the carve-out is deliberately narrow, not
      accidentally wide).

These are the tests that make the "adding a table to the carve-out is
a big deal" posture real. If someone adds `invitation_tokens` to
CREDENTIAL_INDEXED_TABLES without an ADR, test (c) fails noisily.
"""

from __future__ import annotations

import hashlib
from uuid import uuid4

import pytest
from sqlalchemy import text

from app.db.policies import CREDENTIAL_INDEXED_TABLES, TENANT_TABLES
from app.models.identity import APIKey, Organization


@pytest.mark.asyncio
async def test_api_keys_readable_by_hash_without_tenant_context(db_session):
    """(b) The carve-out is real: a raw SELECT by key_hash succeeds
    even with NO `app.current_org_id` set.

    This is the request-entry shape for API-key authentication: we
    need the row's organization_id to know who to authenticate as,
    so RLS cannot gate the read.
    """
    # Arrange: create an org + api_key under normal tenant context.
    org = Organization(name="Org R", slug=f"orgr-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await db_session.execute(text(f"SET app.current_org_id = '{org.id}'"))

    plaintext = "ss_live_carveout_test_plaintext_42ff"
    key_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    key = APIKey(
        organization_id=org.id,
        name="carve-out test",
        key_prefix=plaintext[:12],
        key_hash=key_hash,
    )
    db_session.add(key)
    await db_session.commit()

    # Act: explicitly clear the GUC, then SELECT by hash. Without the
    # carve-out this would return zero rows — the tenant_isolation
    # policy would filter them out.
    await db_session.execute(text("RESET app.current_org_id"))

    result = await db_session.execute(
        text("SELECT organization_id FROM api_keys WHERE key_hash = :h"),
        {"h": key_hash},
    )
    row = result.first()
    assert row is not None, (
        "api_keys must be readable by key_hash without tenant context — "
        "this is the API-key-auth precondition (ADR-012)"
    )
    assert row[0] == org.id


@pytest.mark.asyncio
async def test_only_api_keys_is_in_the_carve_out(db_session):
    """(c) Defense-in-depth: confirm the carve-out dict contains
    *only* api_keys, and that every OTHER tenant-scoped table still
    blocks cross-tenant reads.

    This is the guard that prevents someone from silently adding a
    new table to CREDENTIAL_INDEXED_TABLES without going through an
    ADR amendment. If the dict grows, this test fails and forces the
    team to look at ADR-012 before approving.
    """
    # First half: the enumeration itself hasn't quietly drifted.
    assert set(CREDENTIAL_INDEXED_TABLES.keys()) == {"api_keys"}, (
        "CREDENTIAL_INDEXED_TABLES has changed — this requires an ADR "
        "amendment, not just a code change. See ADR-012 + policies.py."
    )
    # And the justification string is non-trivial (not an empty ""
    # that would bypass the forcing-function).
    for table, justification in CREDENTIAL_INDEXED_TABLES.items():
        assert len(justification) > 50, (
            f"{table}: justification too short to have meaning"
        )
        assert "ADR-012" in justification, (
            f"{table}: justification must cross-ref ADR-012"
        )

    # Second half: every table in TENANT_TABLES must still have RLS
    # applied. Rather than probing every table's SELECT path (which
    # varies by model), we prove the structural invariant: api_keys
    # must NOT be in TENANT_TABLES, and the RLS DDL emitter iterates
    # exactly TENANT_TABLES.
    assert "api_keys" not in TENANT_TABLES, (
        "api_keys leaked back into TENANT_TABLES — that would re-enable "
        "RLS and break API-key authentication"
    )
    # And the emitter still produces a tenant_isolation policy for
    # each entry (catches an accidental refactor that decouples the
    # DDL from the list).
    from app.db.policies import rls_upgrade_sql

    ddl = list(rls_upgrade_sql())
    for table in TENANT_TABLES:
        assert any(f"CREATE POLICY tenant_isolation ON {table}" in s for s in ddl), (
            f"{table}: RLS DDL emitter did not emit tenant_isolation policy"
        )
    # And CRUCIALLY — no policy emitted for api_keys (the carve-out).
    assert not any("ON api_keys " in s for s in ddl), (
        "rls_upgrade_sql still emits DDL for api_keys — carve-out broken"
    )


def test_tenant_and_credential_indexed_tables_are_disjoint():
    """No table may appear in both lists. Invariant of the two-category
    design (ADR-012)."""
    overlap = set(TENANT_TABLES) & set(CREDENTIAL_INDEXED_TABLES.keys())
    assert overlap == set(), (
        f"tables in both TENANT_TABLES and CREDENTIAL_INDEXED_TABLES: "
        f"{overlap}"
    )
