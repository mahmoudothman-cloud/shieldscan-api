"""Regression tests for email case-normalization (Task 2.5 Commit 1a).

Three layers, three tests — defense-in-depth:

  (1) Schema validator (Pydantic)   -> test_register_rejects_mixed_case_duplicate
      Catches case-varied duplicates at HTTP boundary via the rate of
      their normalized form.

  (2) Orchestrator boundary         -> test_login_accepts_mixed_case_of_registered_email
      Login request's email is normalized so `User.email == req.email`
      matches regardless of input case.

  (3) DB CHECK constraint           -> test_db_rejects_non_normalized_email_insert
      Catches ORM bypass (raw SQL, direct INSERT, future SECURITY DEFINER
      function) that skips the schema + orchestrator layers.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.models.identity import Organization
from app.db.tenant_context import set_tenant_context


def _register_payload(email: str, *, org: str = "Co"):
    return {
        "email": email,
        "password": "Secure-Pass-123",
        "full_name": "X",
        "organization_name": org,
    }


@pytest.mark.asyncio
async def test_register_rejects_mixed_case_duplicate(client, db_session):
    """Register `Alice@example.com`, then `ALICE@example.com` — the
    second must be treated as a duplicate (both normalize to the same
    canonical form). Generic 400 per no-enumeration policy.
    """
    r1 = await client.post(
        "/v1/auth/register",
        json=_register_payload("Alice@example.com", org="First"),
    )
    assert r1.status_code == 201, r1.text
    # Stored form is the canonical lowercased version.
    assert r1.json()["user"]["email"] == "alice@example.com"

    r2 = await client.post(
        "/v1/auth/register",
        json=_register_payload("ALICE@example.com", org="Second"),
        headers={"CF-Connecting-IP": "203.0.113.42"},  # dodge IP rate limit
    )
    assert r2.status_code == 400
    assert r2.json()["detail"] == "registration_failed"

    # Note: asserting the DB row count here is complicated by the
    # shared-session test harness (an aborted outer tx after the
    # second register's IntegrityError). The HTTP response on r1
    # already proves the canonical form was stored: `r1.json()
    # ["user"]["email"] == "alice@example.com"`. That UserResponse
    # is serialized from the ORM row post-commit, so the DB has
    # exactly that value. r2's generic 400 proves the duplicate
    # check fired. No further DB introspection needed.


@pytest.mark.asyncio
async def test_login_accepts_mixed_case_of_registered_email(
    client, existing_user
):
    """User registered as `existing@test.com` (all-lowercase via the
    fixture). Login with mixed-case input must still succeed — email
    is normalized before the DB lookup.
    """
    user, password = existing_user
    # Verify the user so login isn't blocked by email_verified=False.
    user.email_verified = True

    r = await client.post(
        "/v1/auth/login",
        json={"email": "EXISTING@test.com", "password": password},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "access_token" in body
    assert body["user"]["email"] == "existing@test.com"


@pytest.mark.asyncio
async def test_db_rejects_non_normalized_email_insert(db_session):
    """Raw SQL bypasses schema + orchestrator. The DB CHECK constraint
    is the last line of defense — any future code path that inserts
    directly (admin scripts, data migrations, SECURITY DEFINER funcs)
    must also fail for non-normalized email.
    """
    # Set up a tenant context so the non-tenant `users` table insert
    # works (users is not RLS-scoped but we keep the session clean).
    org = Organization(name="CheckOrg", slug=f"checkorg-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await set_tenant_context(db_session, org.id)

    with pytest.raises(IntegrityError):
        await db_session.execute(
            text(
                "INSERT INTO users (id, email, hashed_password, full_name, "
                "email_verified, created_at, updated_at) "
                "VALUES (:id, :email, 'x', 'Bypass User', false, now(), now())"
            ),
            {"id": uuid4(), "email": "ALICE@example.com"},
        )
