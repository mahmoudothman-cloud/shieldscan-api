"""End-to-end tests for /v1/auth/forgot-password + /v1/auth/reset-password
— Task 2.Y."""

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
from app.services.password_reset import PASSWORD_RESET_PREFIX
from app.services.token_revocation import (
    REVOKED_JTI_PREFIX,
    USER_REVOKED_BEFORE_PREFIX,
)
from tests.conftest import use_org


def _extract_token(body: str) -> str:
    return body.split("token=", 1)[1].split()[0]


@pytest_asyncio.fixture
async def reset_user(client, db_session, email_service_stub):
    """Fresh user + cleared outbox so reset-flow assertions are clean.

    Yields (user, current_password). Email is verified=False by
    default (matches the typical "user can't log in" reset scenario);
    individual tests flip it where needed.
    """
    org = Organization(name="Reset Org", slug=f"resetorg-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    current_password = "Original-Pass-123"
    user = User(
        email=f"reset-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password(current_password),
        full_name="Reset User",
        email_verified=False,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(
            user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN
        )
    )
    await db_session.commit()
    email_service_stub.clear()
    return user, current_password


# =============================================================== /forgot-password


@pytest.mark.asyncio
async def test_1_forgot_unverified_user_sends_email(
    client, reset_user, email_service_stub, db_session
):
    user, _ = reset_user
    r = await client.post("/v1/auth/forgot-password", json={"email": user.email})
    assert r.status_code == 200
    assert r.json() == {
        "detail": "password_reset_email_sent_if_account_exists"
    }
    assert len(email_service_stub.outbox) == 1
    assert email_service_stub.outbox[0].to == user.email
    assert email_service_stub.outbox[0].template == "password_reset"

    # Audit row recorded.
    audits = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "auth.password.reset.requested"
            )
        )
    ).scalars().all()
    assert len(audits) == 1


@pytest.mark.asyncio
async def test_2_forgot_verified_user_sends_email(
    client, reset_user, email_service_stub, db_session
):
    """Verification status is irrelevant to reset flow — both
    verified and unverified users can reset."""
    user, _ = reset_user
    user.email_verified = True
    await db_session.commit()

    r = await client.post("/v1/auth/forgot-password", json={"email": user.email})
    assert r.status_code == 200
    assert len(email_service_stub.outbox) == 1


@pytest.mark.asyncio
async def test_3_forgot_nonexistent_email_generic_200_no_send(
    client, email_service_stub
):
    """Enumeration protection: nonexistent emails see the same body
    as existent ones, no email sent."""
    r = await client.post(
        "/v1/auth/forgot-password", json={"email": "nobody@nowhere.tld"}
    )
    assert r.status_code == 200
    assert r.json() == {
        "detail": "password_reset_email_sent_if_account_exists"
    }
    assert email_service_stub.outbox == []


@pytest.mark.asyncio
async def test_4_forgot_rate_limit_per_email_silent_drop(
    client, reset_user, email_service_stub
):
    user, _ = reset_user
    for _ in range(3):
        r = await client.post(
            "/v1/auth/forgot-password", json={"email": user.email}
        )
        assert r.status_code == 200
    assert len(email_service_stub.outbox) == 3

    r = await client.post(
        "/v1/auth/forgot-password", json={"email": user.email}
    )
    assert r.status_code == 200  # generic — silent drop
    assert r.json() == {
        "detail": "password_reset_email_sent_if_account_exists"
    }
    assert len(email_service_stub.outbox) == 3  # unchanged


@pytest.mark.asyncio
async def test_5_forgot_rate_limit_per_ip_silent_drop(
    client, db_session, email_service_stub
):
    """Per-IP limit (10/hr) trips on the 11th attempt regardless of
    target email — even nonexistent ones."""
    for i in range(10):
        r = await client.post(
            "/v1/auth/forgot-password",
            json={"email": f"phantom{i}@t.co"},
            headers={"CF-Connecting-IP": "198.51.100.5"},
        )
        assert r.status_code == 200

    r = await client.post(
        "/v1/auth/forgot-password",
        json={"email": "phantom11@t.co"},
        headers={"CF-Connecting-IP": "198.51.100.5"},
    )
    assert r.status_code == 200  # silent drop
    assert r.json() == {
        "detail": "password_reset_email_sent_if_account_exists"
    }


@pytest.mark.asyncio
async def test_6_forgot_re_request_idempotent_new_token_replaces_old(
    client, reset_user, email_service_stub, fake_redis
):
    """Each /forgot-password call mints a fresh token. Tokens
    coexist in Redis until their TTL or single-use; the latest
    issued one (in the latest email) is the one users will click
    in practice. Both should be valid until consumed."""
    user, _ = reset_user

    await client.post("/v1/auth/forgot-password", json={"email": user.email})
    first_token = _extract_token(email_service_stub.outbox[0].body)

    await client.post("/v1/auth/forgot-password", json={"email": user.email})
    second_token = _extract_token(email_service_stub.outbox[1].body)

    assert first_token != second_token
    # Both keys exist independently in Redis.
    keys = [k async for k in fake_redis.scan_iter(
        match=f"{PASSWORD_RESET_PREFIX}:*"
    )]
    assert len(keys) == 2


@pytest.mark.asyncio
async def test_7_forgot_rate_limits_nonexistent_emails_equally(
    client, fake_redis
):
    """Enumeration-protection mechanism pin (mirrors Task 2.5's
    test_resend_rate_limits_nonexistent_emails_equally). The per-
    email rate limiter must INCR for nonexistent accounts too —
    otherwise its trip signal is an existence oracle."""
    for _ in range(4):
        r = await client.post(
            "/v1/auth/forgot-password",
            json={"email": "phantom@ghost.example"},
        )
        assert r.status_code == 200

    keys = [k async for k in fake_redis.scan_iter(
        match="ratelimit:forgot_password_email:phantom@ghost.example:*"
    )]
    assert len(keys) == 1
    count = int(await fake_redis.get(keys[0]))
    assert count >= 3, (
        f"forgot-password rate limiter must INCR for nonexistent emails "
        f"(got count={count})"
    )


# =============================================================== /reset-password


@pytest.mark.asyncio
async def test_8_reset_happy_path(
    client, reset_user, email_service_stub, db_session, fake_redis
):
    user, current_pwd = reset_user
    new_pwd = "Brand-New-Reset-Pass-456"

    # Initiate.
    await client.post("/v1/auth/forgot-password", json={"email": user.email})
    token = _extract_token(email_service_stub.outbox[0].body)

    # Consume.
    r = await client.post(
        "/v1/auth/reset-password",
        json={"token": token, "new_password": new_pwd},
    )
    assert r.status_code == 204

    # DB updated.
    refreshed = (
        await db_session.execute(select(User).where(User.id == user.id))
    ).scalar_one()
    assert verify_password(new_pwd, refreshed.hashed_password)
    assert not verify_password(current_pwd, refreshed.hashed_password)

    # user_revoked_before set.
    assert await fake_redis.exists(f"{USER_REVOKED_BEFORE_PREFIX}:{user.id}")


@pytest.mark.asyncio
async def test_9_reset_invalid_token_returns_400(client):
    r = await client.post(
        "/v1/auth/reset-password",
        json={"token": "totally_not_a_real_token_xyz", "new_password": "Whatever-Pass-1"},
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "invalid_or_expired_token"


@pytest.mark.asyncio
async def test_10_reset_token_for_deleted_user_returns_400(
    client, fake_redis
):
    """Token in Redis points to a user_id that doesn't exist in DB.
    Constructed via Redis-plant (per Task 2.5 pattern — direct User
    deletion fires the audit_logs append-only trigger)."""
    ghost_id = str(uuid4())
    token = "ss_reset_ghost_plaintext"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    await fake_redis.set(
        f"{PASSWORD_RESET_PREFIX}:{token_hash}", ghost_id, ex=3600
    )

    r = await client.post(
        "/v1/auth/reset-password",
        json={"token": token, "new_password": "Anything-Pass-1"},
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "invalid_or_expired_token"


@pytest.mark.asyncio
async def test_11_reset_token_is_single_use(
    client, reset_user, email_service_stub
):
    user, _ = reset_user
    await client.post("/v1/auth/forgot-password", json={"email": user.email})
    token = _extract_token(email_service_stub.outbox[0].body)

    r1 = await client.post(
        "/v1/auth/reset-password",
        json={"token": token, "new_password": "First-Reset-Pass-1"},
    )
    assert r1.status_code == 204

    r2 = await client.post(
        "/v1/auth/reset-password",
        json={"token": token, "new_password": "Second-Reset-Pass-2"},
    )
    assert r2.status_code == 400


@pytest.mark.asyncio
async def test_12_old_access_token_rejected_after_reset(
    client, reset_user, email_service_stub
):
    """Access token issued pre-reset → 401 after reset (via the
    user_revoked_before iat check from Task 2.X)."""
    user, _ = reset_user
    old_access = create_access_token(sub=str(user.id))
    time.sleep(1)  # ensure reset's now_ts > old_access.iat

    await client.post("/v1/auth/forgot-password", json={"email": user.email})
    token = _extract_token(email_service_stub.outbox[0].body)
    await client.post(
        "/v1/auth/reset-password",
        json={"token": token, "new_password": "After-Reset-Pass-1"},
    )

    r = await client.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {old_access}"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_13_old_refresh_token_rejected_after_reset(
    client, reset_user, email_service_stub
):
    user, _ = reset_user
    old_refresh = create_refresh_token(sub=str(user.id))
    time.sleep(1)

    await client.post("/v1/auth/forgot-password", json={"email": user.email})
    token = _extract_token(email_service_stub.outbox[0].body)
    await client.post(
        "/v1/auth/reset-password",
        json={"token": token, "new_password": "After-Reset-Pass-2"},
    )

    r = await client.post(
        "/v1/auth/refresh", json={"refresh_token": old_refresh}
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_14_reset_new_password_policy_violation_returns_422(
    client, reset_user, email_service_stub
):
    user, _ = reset_user
    await client.post("/v1/auth/forgot-password", json={"email": user.email})
    token = _extract_token(email_service_stub.outbox[0].body)

    # Too short.
    r1 = await client.post(
        "/v1/auth/reset-password",
        json={"token": token, "new_password": "Ab1"},
    )
    assert r1.status_code == 422

    # Missing digit.
    r2 = await client.post(
        "/v1/auth/reset-password",
        json={"token": token, "new_password": "onlyletters"},
    )
    assert r2.status_code == 422


@pytest.mark.asyncio
async def test_15_reset_writes_audit_password_reset_completed(
    client, reset_user, email_service_stub, db_session
):
    user, _ = reset_user
    await client.post("/v1/auth/forgot-password", json={"email": user.email})
    token = _extract_token(email_service_stub.outbox[0].body)
    await client.post(
        "/v1/auth/reset-password",
        json={"token": token, "new_password": "Audit-Test-Pass-1"},
    )

    audits = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "auth.password.reset.completed"
            )
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].actor_id == user.id


@pytest.mark.asyncio
async def test_16_reset_consumption_rate_limited_at_20_per_ip_hour(
    client, reset_user, email_service_stub, fake_redis
):
    """Per-IP rate limit on the consumption endpoint (20/hr) — guards
    against high-volume token-guessing attempts even though the
    base64url space is too large to brute-force in practice."""
    user, _ = reset_user
    ip = "198.51.100.42"

    # Mint enough tokens to fire 20 valid attempts (just to keep the
    # limiter signal clean from the body-validation noise).
    for i in range(20):
        await client.post(
            "/v1/auth/forgot-password",
            json={"email": user.email},
            headers={"CF-Connecting-IP": "10.0.0.1"},  # different IP for forgot
        )
    # 20 reset attempts from the SAME IP — all should pass the limiter
    # (each one is invalid as a token, but limiter trip is what matters).
    for i in range(20):
        await client.post(
            "/v1/auth/reset-password",
            json={"token": f"bad_token_{i}", "new_password": "Some-Password-1"},
            headers={"CF-Connecting-IP": ip},
        )

    # 21st from same IP → 429.
    r = await client.post(
        "/v1/auth/reset-password",
        json={"token": "another_bad", "new_password": "Some-Password-1"},
        headers={"CF-Connecting-IP": ip},
    )
    assert r.status_code == 429
    assert r.json()["detail"] == "rate_limit_exceeded"


# =============================================================== design invariant


@pytest.mark.asyncio
async def test_17_reset_does_not_add_jtis_to_revocation_list(
    client, reset_user, email_service_stub, fake_redis
):
    """Design invariant — DO NOT silently break this test.

    If this test fails: someone added explicit jti revocation on
    password reset. Don't. Reset uses user-level revocation
    (user_revoked_before) as the source of truth, mirroring
    /password/change. Adding jti enumeration requires tracking
    active tokens, which we explicitly don't do. See Task 2.Y
    discussion + ADR-011 + Task 2.X test 19.
    """
    user, _ = reset_user
    # Mint tokens whose jtis we'll check against.
    access_token = create_access_token(sub=str(user.id))
    access_jti = jose_jwt.get_unverified_claims(access_token)["jti"]
    refresh_token = create_refresh_token(sub=str(user.id))
    refresh_jti = jose_jwt.get_unverified_claims(refresh_token)["jti"]

    # Run the reset flow.
    await client.post("/v1/auth/forgot-password", json={"email": user.email})
    reset_token = _extract_token(email_service_stub.outbox[0].body)
    r = await client.post(
        "/v1/auth/reset-password",
        json={"token": reset_token, "new_password": "Invariant-Test-Pass-1"},
    )
    assert r.status_code == 204

    # Neither jti is in the targeted revocation list.
    assert not await fake_redis.exists(f"{REVOKED_JTI_PREFIX}:{access_jti}"), (
        "password reset must NOT add the access jti to the targeted "
        "revocation list — see test docstring for design rationale"
    )
    assert not await fake_redis.exists(f"{REVOKED_JTI_PREFIX}:{refresh_jti}"), (
        "password reset must NOT add the refresh jti to the targeted "
        "revocation list — see test docstring for design rationale"
    )
    # But user_revoked_before IS set.
    assert await fake_redis.exists(f"{USER_REVOKED_BEFORE_PREFIX}:{user.id}")


@pytest.mark.asyncio
async def test_18_reset_does_not_change_email_verified_status(
    client, reset_user, email_service_stub, db_session
):
    """Design invariant — DO NOT silently break this test.

    If this test fails: someone added auto-verification on reset.
    That's a policy change (user-visible behavior). Confirm it's
    intentional and add an ADR or DRIFT-LOG entry with reasoning
    before landing it.

    Rationale: password reset proves mailbox ownership (same
    mechanism as email verification) but the two are deliberately
    distinct user intents. Auto-verifying on reset silently changes
    account state, conflates two flows, and complicates future
    email-change flows. See Task 2.Y DRIFT-LOG entry.
    """
    user, _ = reset_user
    assert user.email_verified is False  # precondition

    await client.post("/v1/auth/forgot-password", json={"email": user.email})
    token = _extract_token(email_service_stub.outbox[0].body)
    r = await client.post(
        "/v1/auth/reset-password",
        json={"token": token, "new_password": "Invariant-Pass-2"},
    )
    assert r.status_code == 204

    refreshed = (
        await db_session.execute(select(User).where(User.id == user.id))
    ).scalar_one()
    assert refreshed.email_verified is False, (
        "password reset must NOT auto-verify email — see test "
        "docstring for design rationale"
    )
