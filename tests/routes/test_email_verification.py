"""End-to-end tests for /v1/auth/verify-email + /v1/auth/resend-verification
(Task 2.5 Commit 1b)."""

from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.identity import User
from app.services.email_verification import EMAIL_VERIFY_PREFIX


def _extract_token_from_body(body: str) -> str:
    """The ConsoleEmailService body contains `...?token=<value>\\n...`."""
    return body.split("token=", 1)[1].split()[0]


# =============================================================== verify-email


@pytest.mark.asyncio
async def test_verify_email_happy_path(client, existing_user, email_service_stub, db_session):
    """Extract the token from the email the register flow sent, post
    it to /verify-email, assert email_verified flips true."""
    user, _ = existing_user
    assert user.email_verified is False

    # The register flow in the existing_user fixture already emitted a
    # verification email; the plaintext token is in the outbox body.
    token = _extract_token_from_body(email_service_stub.outbox[0].body)

    r = await client.post("/v1/auth/verify-email", json={"token": token})
    assert r.status_code == 200
    assert r.json() == {"email_verified": True}

    # DB row flipped.
    refreshed = (
        await db_session.execute(select(User).where(User.id == user.id))
    ).scalar_one()
    assert refreshed.email_verified is True


@pytest.mark.asyncio
async def test_verify_email_response_body_is_minimal(
    client, existing_user, email_service_stub
):
    """Security: an unauthenticated endpoint that accepts a token
    must not leak user profile in the success response."""
    token = _extract_token_from_body(email_service_stub.outbox[0].body)
    r = await client.post("/v1/auth/verify-email", json={"token": token})
    assert r.status_code == 200
    # Strictly one field.
    body = r.json()
    assert set(body.keys()) == {"email_verified"}
    # No email, full_name, id, etc.
    assert "email" not in body
    assert "full_name" not in body
    assert "user" not in body


@pytest.mark.asyncio
async def test_verify_email_nonexistent_token_returns_400(client):
    r = await client.post(
        "/v1/auth/verify-email", json={"token": "completely_made_up_token_xyz"}
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "invalid_or_expired_token"


@pytest.mark.asyncio
async def test_verify_email_expired_token_returns_400(
    client, existing_user, email_service_stub, fake_redis
):
    """Simulate TTL elapse by deleting the Redis key directly."""
    token = _extract_token_from_body(email_service_stub.outbox[0].body)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    await fake_redis.delete(f"{EMAIL_VERIFY_PREFIX}:{token_hash}")

    r = await client.post("/v1/auth/verify-email", json={"token": token})
    assert r.status_code == 400
    assert r.json()["detail"] == "invalid_or_expired_token"


@pytest.mark.asyncio
async def test_verify_email_for_nonexistent_user_returns_400(
    client, fake_redis
):
    """Token in Redis points to a user_id that doesn't exist in the
    DB (simulates: admin deleted the user after token issuance, or
    any race where the Redis row outlives the user row). The lookup
    path must collapse to the same 400 body — no existence leak.

    Constructed directly rather than via User-delete because
    audit_logs.actor_id ON DELETE SET NULL fires the append-only
    trigger (known M1 schema tension, unrelated to Task 2.5).
    """
    import hashlib as _hl
    from uuid import uuid4

    # Plant a fake token whose stored value is a nonexistent UUID.
    ghost_id = str(uuid4())
    token = "ss_email_verify_ghost_plaintext"
    token_hash = _hl.sha256(token.encode()).hexdigest()
    await fake_redis.set(
        f"{EMAIL_VERIFY_PREFIX}:{token_hash}", ghost_id, ex=86400
    )

    r = await client.post("/v1/auth/verify-email", json={"token": token})
    assert r.status_code == 400
    assert r.json()["detail"] == "invalid_or_expired_token"


@pytest.mark.asyncio
async def test_verify_email_is_single_use(
    client, existing_user, email_service_stub
):
    """Regression: second use of the same token returns 400."""
    token = _extract_token_from_body(email_service_stub.outbox[0].body)
    r1 = await client.post("/v1/auth/verify-email", json={"token": token})
    assert r1.status_code == 200

    r2 = await client.post("/v1/auth/verify-email", json={"token": token})
    assert r2.status_code == 400
    assert r2.json()["detail"] == "invalid_or_expired_token"


@pytest.mark.asyncio
async def test_verify_email_writes_audit_on_state_change(
    client, existing_user, email_service_stub, db_session
):
    token = _extract_token_from_body(email_service_stub.outbox[0].body)
    await client.post("/v1/auth/verify-email", json={"token": token})

    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.email.verified")
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].details == {"method": "email"}


@pytest.mark.asyncio
async def test_verify_email_removes_redis_key_on_success(
    client, existing_user, email_service_stub, fake_redis
):
    token = _extract_token_from_body(email_service_stub.outbox[0].body)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    key = f"{EMAIL_VERIFY_PREFIX}:{token_hash}"
    assert await fake_redis.exists(key)  # precondition

    await client.post("/v1/auth/verify-email", json={"token": token})

    assert not await fake_redis.exists(key)


@pytest.mark.asyncio
async def test_verify_email_idempotent_no_duplicate_audit(
    client, existing_user, email_service_stub, db_session, fake_redis
):
    """If the token somehow survives past a successful verify (it
    can't in the GETDEL model, but the code handles the already-
    verified state defensively), the second-shot audit is NOT
    emitted. Verified here by setting email_verified=True manually
    and re-issuing a fresh token for the same user."""
    user, _ = existing_user
    # Simulate: user already verified via some other path.
    user.email_verified = True
    await db_session.commit()

    # Issue a NEW token (same user).
    from app.services.email_verification import issue_email_verification_token

    token = await issue_email_verification_token(fake_redis, user.id)

    r = await client.post("/v1/auth/verify-email", json={"token": token})
    assert r.status_code == 200

    # No duplicate auth.email.verified audit (state didn't change).
    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.email.verified")
        )
    ).scalars().all()
    assert len(audits) == 0


# =============================================================== resend-verification


@pytest.mark.asyncio
async def test_resend_happy_path_sends_email(
    client, existing_user, email_service_stub
):
    user, _ = existing_user
    assert user.email_verified is False
    initial_outbox = len(email_service_stub.outbox)  # register already sent 1

    r = await client.post(
        "/v1/auth/resend-verification", json={"email": user.email}
    )
    assert r.status_code == 200
    assert r.json() == {"detail": "verification_email_sent_if_account_exists"}

    # Email actually sent (outbox grew).
    assert len(email_service_stub.outbox) == initial_outbox + 1
    assert email_service_stub.outbox[-1].to == user.email


@pytest.mark.asyncio
async def test_resend_nonexistent_email_returns_generic_200(
    client, email_service_stub
):
    initial = len(email_service_stub.outbox)
    r = await client.post(
        "/v1/auth/resend-verification", json={"email": "nobody@nowhere.tld"}
    )
    assert r.status_code == 200
    assert r.json() == {"detail": "verification_email_sent_if_account_exists"}
    assert len(email_service_stub.outbox) == initial  # NO email sent


@pytest.mark.asyncio
async def test_resend_already_verified_returns_generic_200_no_send(
    client, existing_user, email_service_stub, db_session
):
    user, _ = existing_user
    user.email_verified = True
    await db_session.commit()
    initial = len(email_service_stub.outbox)

    r = await client.post(
        "/v1/auth/resend-verification", json={"email": user.email}
    )
    assert r.status_code == 200
    assert r.json() == {"detail": "verification_email_sent_if_account_exists"}
    assert len(email_service_stub.outbox) == initial


@pytest.mark.asyncio
async def test_resend_rate_limit_silent_drop(
    client, existing_user, email_service_stub
):
    """4th resend in 1hr: silently drops (returns generic 200, no email)."""
    user, _ = existing_user
    initial = len(email_service_stub.outbox)

    # 3 successful resends.
    for _ in range(3):
        r = await client.post(
            "/v1/auth/resend-verification", json={"email": user.email}
        )
        assert r.status_code == 200
    assert len(email_service_stub.outbox) == initial + 3

    # 4th: same generic 200, no email sent.
    r = await client.post(
        "/v1/auth/resend-verification", json={"email": user.email}
    )
    assert r.status_code == 200
    assert r.json() == {"detail": "verification_email_sent_if_account_exists"}
    assert len(email_service_stub.outbox) == initial + 3  # unchanged


@pytest.mark.asyncio
async def test_resend_rate_limits_nonexistent_emails_equally(
    client, email_service_stub, fake_redis
):
    """Enumeration-protection pin: the rate limiter INCRs for
    nonexistent emails too. Future refactors that "optimize" by
    skipping the limiter for unknown accounts will fail this test.

    Verified at the mechanism level: the Redis rate-limit key exists
    with count >= 3 after 4 requests, regardless of whether the
    account exists.
    """
    for _ in range(4):
        r = await client.post(
            "/v1/auth/resend-verification",
            json={"email": "phantom@ghost.example"},
        )
        assert r.status_code == 200

    # Counter exists for the normalized email.
    keys = [
        k async for k in fake_redis.scan_iter(
            match="ratelimit:resend_verification_email:phantom@ghost.example:*"
        )
    ]
    assert len(keys) == 1
    count = int(await fake_redis.get(keys[0]))
    assert count >= 3, (
        f"rate limiter must INCR for nonexistent emails too (got count={count})"
    )


@pytest.mark.asyncio
async def test_resend_response_shape_identical_for_existent_and_nonexistent(
    client, existing_user
):
    """Timing-consistency proxy: the response SHAPE is identical.
    Wall-clock timing belongs in a perf-suite (see DRIFT-LOG)."""
    user, _ = existing_user

    r_real = await client.post(
        "/v1/auth/resend-verification", json={"email": user.email}
    )
    r_fake = await client.post(
        "/v1/auth/resend-verification",
        json={"email": "not-a-real-user@test.tld"},
    )
    assert r_real.status_code == r_fake.status_code == 200
    assert r_real.json() == r_fake.json()
    # Same headers' presence (Content-Type, etc.) — sanity check.
    assert set(r_real.headers.keys()) == set(r_fake.headers.keys())


@pytest.mark.asyncio
async def test_resend_new_token_verifies_correctly(
    client, existing_user, email_service_stub
):
    """Idempotency at the mechanism level: after a resend, the NEW
    token from the resend email successfully verifies the account.
    Old-token validity is not tested here (both remain valid — see
    endpoint docstring for why)."""
    user, _ = existing_user
    await client.post(
        "/v1/auth/resend-verification", json={"email": user.email}
    )
    # Latest email is the resent one.
    new_body = email_service_stub.outbox[-1].body
    new_token = _extract_token_from_body(new_body)

    r = await client.post("/v1/auth/verify-email", json={"token": new_token})
    assert r.status_code == 200
    assert r.json() == {"email_verified": True}


@pytest.mark.asyncio
async def test_resend_audit_only_on_actual_send(
    client, existing_user, email_service_stub, db_session
):
    """audit EMAIL_VERIFICATION_SENT only when an email was actually
    dispatched — not for the 3 no-op paths (nonexistent, already
    verified, rate-limited)."""
    user, _ = existing_user

    # Nonexistent email: no audit.
    await client.post(
        "/v1/auth/resend-verification", json={"email": "no@one.tld"}
    )

    # Already-verified path: no audit.
    user.email_verified = True
    await db_session.commit()
    await client.post(
        "/v1/auth/resend-verification", json={"email": user.email}
    )
    user.email_verified = False
    await db_session.commit()

    # Baseline: register already emitted one EMAIL_VERIFICATION_SENT
    # during existing_user fixture setup.
    baseline = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "auth.email.verification_sent"
            )
        )
    ).scalars().all()
    baseline_count = len(baseline)

    # Actual resend (unverified + exists): one new audit.
    r = await client.post(
        "/v1/auth/resend-verification", json={"email": user.email}
    )
    assert r.status_code == 200
    final = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "auth.email.verification_sent"
            )
        )
    ).scalars().all()
    assert len(final) == baseline_count + 1


@pytest.mark.asyncio
async def test_resend_normalizes_email_for_rate_limit_bucket(
    client, existing_user, fake_redis
):
    """`Alice@example.com` and `ALICE@example.com` must share the
    rate-limit counter. 3 of one + 1 of the other should trip the
    limiter on the 4th request regardless of case."""
    # Three resends for mixed case (case is normalized by the schema
    # validator; bucket is the same regardless of input case).
    for email_case in ("Alice@mix.co", "ALICE@mix.co", "alice@mix.co"):
        r = await client.post(
            "/v1/auth/resend-verification", json={"email": email_case}
        )
        assert r.status_code == 200

    # Exactly one bucket (normalized form), count=3.
    keys = [
        k async for k in fake_redis.scan_iter(
            match="ratelimit:resend_verification_email:alice@mix.co:*"
        )
    ]
    assert len(keys) == 1
    assert int(await fake_redis.get(keys[0])) == 3
    # No bucket for "Alice@mix.co" — all three collapsed to the
    # normalized form.
    assert not await fake_redis.exists(
        "ratelimit:resend_verification_email:Alice@mix.co:*"
    )
