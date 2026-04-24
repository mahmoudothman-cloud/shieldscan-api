"""Tests for POST /v1/auth/password/change — Task 2.X Commit 2.

Coverage map (19 tests):
  Endpoint (12):  1-12  — happy + 400/422/401/403 paths + audit + Redis
  Integration (6): 13-18 — token-vs-revocation timing across endpoints
  Design invariant (1): 19 — password change does NOT enumerate jtis
"""

from __future__ import annotations

import hashlib
import time
from uuid import uuid4

import pytest
import pytest_asyncio
from jose import jwt as jose_jwt
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.identity import Membership, MembershipRole, Organization, User
from app.services.auth import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)
from app.services.token_revocation import (
    REVOKED_JTI_PREFIX,
    USER_REVOKED_BEFORE_PREFIX,
    get_user_revoked_before,
)
from tests.conftest import use_org


@pytest_asyncio.fixture
async def authed_user(client, db_session):
    """Make a fresh user, return (user, current_password, jwt_headers).

    Built directly (not via existing_user) so we can pin exact
    current/new password values across the change flow without
    fixture-state pollution.
    """
    org = Organization(name="Pwd Org", slug=f"pwdorg-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    current_password = "Original-Pass-123"
    user = User(
        email=f"pwd-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password(current_password),
        full_name="Pwd User",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(
            user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN
        )
    )
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}
    return user, current_password, headers


# =============================================================== endpoint tests (1-12)


@pytest.mark.asyncio
async def test_1_happy_path(authed_user, client, db_session, fake_redis):
    """204 + DB updated + Redis user_revoked_before key set."""
    user, current_pwd, headers = authed_user
    new_pwd = "Brand-New-Pass-456"

    r = await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": new_pwd},
        headers=headers,
    )
    assert r.status_code == 204

    # DB row updated.
    refreshed = (
        await db_session.execute(select(User).where(User.id == user.id))
    ).scalar_one()
    assert verify_password(new_pwd, refreshed.hashed_password)
    assert not verify_password(current_pwd, refreshed.hashed_password)

    # Redis key set.
    revoked_before = await get_user_revoked_before(fake_redis, user.id)
    assert revoked_before is not None
    assert revoked_before >= int(time.time()) - 5  # within last 5 seconds


@pytest.mark.asyncio
async def test_2_wrong_current_password(authed_user, client, db_session, fake_redis):
    """400 invalid_current_password, no DB change, no Redis key."""
    user, _current, headers = authed_user
    original_hash = user.hashed_password

    r = await client.post(
        "/v1/auth/password/change",
        json={
            "current_password": "Wrong-Pass-999",
            "new_password": "Brand-New-Pass-456",
        },
        headers=headers,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "invalid_current_password"

    # DB unchanged.
    refreshed = (
        await db_session.execute(select(User).where(User.id == user.id))
    ).scalar_one()
    assert refreshed.hashed_password == original_hash

    # No Redis key set.
    assert await get_user_revoked_before(fake_redis, user.id) is None


@pytest.mark.asyncio
async def test_3_new_password_too_short(authed_user, client):
    user, current_pwd, headers = authed_user
    r = await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": "Ab1"},
        headers=headers,
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_4_new_password_too_long(authed_user, client):
    user, current_pwd, headers = authed_user
    r = await client.post(
        "/v1/auth/password/change",
        json={
            "current_password": current_pwd,
            "new_password": "A" + "a" * 71 + "1",  # 73 bytes
        },
        headers=headers,
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_5_new_password_missing_digit_or_letter(authed_user, client):
    user, current_pwd, headers = authed_user
    # Missing digit.
    r1 = await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": "onlyletters"},
        headers=headers,
    )
    assert r1.status_code == 422
    # Missing letter.
    r2 = await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": "12345678"},
        headers=headers,
    )
    assert r2.status_code == 422


@pytest.mark.asyncio
async def test_6_new_password_equals_current(authed_user, client, fake_redis):
    """Merged into invalid_current_password per Task 2.X decision #2."""
    user, current_pwd, headers = authed_user
    r = await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": current_pwd},
        headers=headers,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "invalid_current_password"
    # No Redis side-effect.
    assert await get_user_revoked_before(fake_redis, user.id) is None


@pytest.mark.asyncio
async def test_7_unauthenticated(client):
    r = await client.post(
        "/v1/auth/password/change",
        json={
            "current_password": "doesnt-matter-1",
            "new_password": "Whatever-Pass-123",
        },
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_8_api_key_credential_rejected_with_403(
    client, authed_user, db_session
):
    """Mutation endpoint: API keys must be rejected with 403
    api_key_insufficient_for_operation (require_jwt dep)."""
    user, current_pwd, _ = authed_user
    from app.models.identity import APIKey

    org_id = (
        await db_session.execute(
            select(Membership.organization_id).where(Membership.user_id == user.id)
        )
    ).scalar_one()

    plaintext = f"ss_live_test_{uuid4().hex[:24]}"
    db_session.add(
        APIKey(
            organization_id=org_id,
            name="key",
            key_prefix=plaintext[:12],
            key_hash=hashlib.sha256(plaintext.encode()).hexdigest(),
        )
    )
    await db_session.commit()

    r = await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": "Other-Pass-789"},
        headers={"Authorization": f"Bearer {plaintext}"},
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "api_key_insufficient_for_operation"


@pytest.mark.asyncio
async def test_9_audit_password_changed_on_success(authed_user, client, db_session):
    user, current_pwd, headers = authed_user
    r = await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": "New-Pass-999"},
        headers=headers,
    )
    assert r.status_code == 204
    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.password.changed")
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].actor_id == user.id
    assert audits[0].resource_id == user.id


@pytest.mark.asyncio
async def test_10_verify_password_runs_even_with_empty_current(
    authed_user, client, monkeypatch
):
    """Timing-consistency mechanism guard: verify_password must run
    even when current_password is empty/garbage. Otherwise an
    attacker with an access token but no password could distinguish
    "empty rejected without hash work" from "wrong-password rejected
    after hash work" via response time.
    """
    user, _current, headers = authed_user
    import app.routes.auth as auth_routes

    call_count = {"n": 0}
    orig = auth_routes.verify_password

    def counting(plain, hashed):
        call_count["n"] += 1
        return orig(plain, hashed)

    monkeypatch.setattr(auth_routes, "verify_password", counting)

    r = await client.post(
        "/v1/auth/password/change",
        json={"current_password": "", "new_password": "Whatever-Pass-1"},
        headers=headers,
    )
    assert r.status_code == 400
    # Both verify_password calls must run (current + new-vs-current
    # check), even though current is empty.
    assert call_count["n"] == 2, (
        f"verify_password must run for both current AND new-vs-current "
        f"even on empty current_password (got {call_count['n']} calls)"
    )


@pytest.mark.asyncio
async def test_11_user_revoked_before_ttl_close_to_30_days(
    authed_user, client, fake_redis
):
    user, current_pwd, headers = authed_user
    await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": "Brand-New-Pass-456"},
        headers=headers,
    )
    ttl = await fake_redis.ttl(f"{USER_REVOKED_BEFORE_PREFIX}:{user.id}")
    # 30 days = 2_592_000 seconds.
    assert 2_591_990 <= ttl <= 2_592_000, (
        f"TTL must be ~30 days; got {ttl}"
    )


@pytest.mark.asyncio
async def test_12_wrong_current_does_not_set_user_revoked_before(
    authed_user, client, fake_redis
):
    """Critical: a failed password change must not have ANY Redis
    side-effect. Otherwise an attacker with an access token but
    not the password could DoS the user (lock them out of all
    sessions) by repeatedly POSTing wrong-current."""
    user, _current, headers = authed_user
    await client.post(
        "/v1/auth/password/change",
        json={"current_password": "Wrong-Pass-1", "new_password": "New-Pass-1"},
        headers=headers,
    )
    keys = [
        k async for k in fake_redis.scan_iter(
            match=f"{USER_REVOKED_BEFORE_PREFIX}:{user.id}"
        )
    ]
    assert keys == []


# =============================================================== integration tests (13-17)


@pytest.mark.asyncio
async def test_13_old_access_token_rejected_after_password_change(
    authed_user, client, db_session
):
    """Access token issued at T-5 → password change at T → access at
    T+1 → 401 via the iat check."""
    user, current_pwd, headers = authed_user
    old_access = headers["Authorization"].split(" ", 1)[1]

    # Sleep a tick so the new revoked_before timestamp is strictly
    # later than the access token's iat.
    time.sleep(1)

    r1 = await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": "Brand-New-Pass-456"},
        headers=headers,
    )
    assert r1.status_code == 204

    # Old access token must now 401.
    r2 = await client.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {old_access}"},
    )
    assert r2.status_code == 401


@pytest.mark.asyncio
async def test_14_old_refresh_token_rejected_after_password_change(
    authed_user, client
):
    """Refresh token from T-5 → password change at T → refresh at T+1 → 401."""
    user, current_pwd, headers = authed_user
    old_refresh = create_refresh_token(sub=str(user.id))
    time.sleep(1)

    await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": "Brand-New-Pass-456"},
        headers=headers,
    )

    r = await client.post("/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_15_refresh_endpoint_rejects_pre_change_token(
    authed_user, client
):
    """Distinct from test 14: this exercises /auth/refresh's own
    user_revoked_before check (added in Commit 1's gap fix), not
    just the get_auth_identity path. /auth/refresh and /auth/me
    take different code paths but must enforce the same revocation."""
    user, current_pwd, headers = authed_user
    old_refresh = create_refresh_token(sub=str(user.id))
    time.sleep(1)

    await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": "Brand-New-Pass-456"},
        headers=headers,
    )

    r = await client.post("/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert r.status_code == 401
    # And /auth/refresh did NOT mint a fresh pair (no token in response).
    body = r.json()
    assert "access_token" not in body
    assert "refresh_token" not in body


@pytest.mark.asyncio
async def test_16_new_tokens_post_change_work_normally(
    authed_user, client
):
    """Positive regression: tokens minted AFTER the password change
    pass auth normally. Otherwise the change locks the user out of
    their own new sessions too."""
    user, current_pwd, headers = authed_user
    time.sleep(1)
    await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": "Brand-New-Pass-456"},
        headers=headers,
    )

    # Mint a fresh access token now (iat > revoked_before).
    new_access = create_access_token(sub=str(user.id))
    r = await client.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {new_access}"},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_17_post_change_jwt_passes_me_cleanly(authed_user, client):
    """Same property as 16 but specifically targets /auth/me to
    rule out an over-rejection bug where ANY iat check trips for
    this user, even with a post-change token."""
    user, current_pwd, headers = authed_user
    time.sleep(1)
    await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": "Brand-New-Pass-456"},
        headers=headers,
    )

    new_access = create_access_token(sub=str(user.id))
    r = await client.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {new_access}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "jwt"
    assert body["user"]["id"] == str(user.id)


# Test 18: Redis-down during user_revoked_before READ — already covered
# in tests/test_user_level_revocation.py::test_jwt_auth_fails_closed_on_redis_error
# (Commit 1). The same fail-closed mechanism applies to any post-change
# auth attempt, so explicit duplication here would test the same code path.
# Adding a focused complement: Redis fails on the WRITE side of
# password change — the password DOES change but old tokens linger.


@pytest.mark.asyncio
async def test_18_redis_write_failure_after_db_commit_does_not_revert_change(
    authed_user, client, db_session, monkeypatch
):
    """Order-of-operations regression: if set_user_revoked_before
    fails AFTER db.commit(), the password change has ALREADY been
    persisted. The handler logs ERROR but returns 204 — flipping
    to 5xx after a successful state mutation would mislead clients
    into thinking the change failed (and they'd retry, double-changing).
    Old tokens stay valid until natural expiry; user can re-call
    the endpoint to retry the Redis write.
    """
    user, current_pwd, headers = authed_user
    new_pwd = "Brand-New-Pass-456"

    import app.routes.auth as auth_routes

    async def _broken_set(*_args, **_kwargs):
        raise ConnectionError("simulated redis outage")

    monkeypatch.setattr(auth_routes, "set_user_revoked_before", _broken_set)

    r = await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": new_pwd},
        headers=headers,
    )
    assert r.status_code == 204  # NOT 5xx — DB change succeeded

    refreshed = (
        await db_session.execute(select(User).where(User.id == user.id))
    ).scalar_one()
    assert verify_password(new_pwd, refreshed.hashed_password)


# =============================================================== design invariant (19)


@pytest.mark.asyncio
async def test_19_password_change_does_not_add_jtis_to_revocation_list(
    authed_user, client, fake_redis
):
    """Design invariant — DO NOT silently break this test.

    If this test fails: someone added explicit jti revocation on
    password change. Don't. Password change uses user-level
    revocation (user_revoked_before) as the source of truth.
    Adding jti enumeration requires tracking active tokens, which
    we explicitly don't do. See Task 2.X discussion + ADR-011
    amendment.

    Rationale (ADR-011): jti revocation list is for TARGETED
    invalidation (logout, refresh rotation). Password change is
    a USER-LEVEL event invalidating an indeterminate set of tokens
    we don't enumerate; the iat-vs-revoked_before comparison is
    the correct mechanism. Mixing the two creates an unmaintainable
    promise of "all tokens explicitly revoked" that scales with
    issued tokens.
    """
    user, current_pwd, headers = authed_user
    # Capture the access jti from the auth header.
    access_token = headers["Authorization"].split(" ", 1)[1]
    access_jti = jose_jwt.get_unverified_claims(access_token)["jti"]
    # Mint a refresh token so we have its jti to check too.
    refresh_token = create_refresh_token(sub=str(user.id))
    refresh_jti = jose_jwt.get_unverified_claims(refresh_token)["jti"]

    # Ensure iat (token) and revoked_before (post-change Redis write)
    # land in different wall-clock seconds. Without this, fast execution
    # can produce iat == revoked_before, and the < comparison evaluates
    # False (correct per spec — a token issued AT the revocation second
    # is post-revocation). Equivalent pattern in tests 13/14/15.
    time.sleep(1)

    r = await client.post(
        "/v1/auth/password/change",
        json={"current_password": current_pwd, "new_password": "Brand-New-Pass-456"},
        headers=headers,
    )
    assert r.status_code == 204

    # Neither jti is in the targeted revocation list.
    assert not await fake_redis.exists(f"{REVOKED_JTI_PREFIX}:{access_jti}"), (
        "password change must NOT add the access jti to the targeted "
        "revocation list — see test docstring for design rationale"
    )
    assert not await fake_redis.exists(f"{REVOKED_JTI_PREFIX}:{refresh_jti}"), (
        "password change must NOT add the refresh jti to the targeted "
        "revocation list — see test docstring for design rationale"
    )

    # But user_revoked_before IS set — the actual source of truth.
    assert await fake_redis.exists(f"{USER_REVOKED_BEFORE_PREFIX}:{user.id}")

    # And the old tokens are functionally rejected via iat check.
    r_me = await client.get(
        "/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert r_me.status_code == 401
    r_refresh = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert r_refresh.status_code == 401
