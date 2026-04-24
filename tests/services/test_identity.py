"""Tests for app.services.identity — Sub-task 2.3.3."""

from __future__ import annotations

import hashlib
import pytest
import pytest_asyncio
from fakeredis import aioredis as fakeredis_aio
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.identity import Membership, MembershipRole, Organization, User
from app.services.audit import AuthAction
from app.services.email import ConsoleEmailService
from app.services.email_verification import EMAIL_VERIFY_PREFIX, TOKEN_TTL_SECONDS
from app.services.identity import (
    EmailAlreadyRegistered,
    MAX_PASSWORD_BYTES,
    MAX_SLUG_ATTEMPTS,
    SlugGenerationFailed,
    register_identity,
)


@pytest_asyncio.fixture
async def redis_client():
    client = fakeredis_aio.FakeRedis(decode_responses=True)
    try:
        yield client
    finally:
        await client.flushall()
        await client.aclose()


@pytest.fixture
def email_service():
    return ConsoleEmailService()


# ---------------------------------------------------------------- happy path


@pytest.mark.asyncio
async def test_register_creates_org_user_membership_audit(
    db_session, redis_client, email_service
):
    user = await register_identity(
        db_session,
        redis_client,
        email_service,
        email="alice@example.com",
        password="Secure-Passw0rd!",
        full_name="Alice Example",
        organization_name="Alice Co",
        ip_address="203.0.113.7",
        user_agent="pytest/1.0",
    )

    # User created + hashed password stored
    assert user.id is not None
    assert user.email == "alice@example.com"
    assert user.hashed_password != "Secure-Passw0rd!"
    assert user.email_verified is False

    # Exactly one Org with slugified name
    orgs = (await db_session.execute(select(Organization))).scalars().all()
    assert len(orgs) == 1
    assert orgs[0].slug == "alice-co"

    # Membership with ADMIN role
    ms = (await db_session.execute(select(Membership))).scalars().all()
    assert len(ms) == 1
    assert ms[0].role == MembershipRole.ADMIN
    assert ms[0].user_id == user.id
    assert ms[0].organization_id == orgs[0].id

    # Two audit rows with correct actions
    audits = (
        (await db_session.execute(select(AuditLog).order_by(AuditLog.created_at)))
        .scalars()
        .all()
    )
    assert [a.action for a in audits] == [
        AuthAction.USER_REGISTERED.value,
        AuthAction.EMAIL_VERIFICATION_SENT.value,
    ]
    for a in audits:
        assert a.actor_id == user.id
        assert a.organization_id == orgs[0].id
        assert str(a.ip_address).startswith("203.0.113.7")
        assert a.user_agent == "pytest/1.0"


@pytest.mark.asyncio
async def test_verification_details_contains_no_token_or_hash(
    db_session, redis_client, email_service
):
    """Audit logs live 7 years; verification tokens live 24h. Storing
    any portion of the token hash in details would be long-lived noise.
    """
    await register_identity(
        db_session, redis_client, email_service,
        email="b@ex.com", password="Secret1!abc",
        full_name="B", organization_name="B Co",
    )
    r = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "auth.email.verification_sent")
    )
    row = r.scalar_one()
    assert row.details == {"method": "email"}
    # Belt-and-braces: no sha256 substring anywhere in the stored detail.
    assert "token" not in row.details
    assert "hash" not in row.details


# ---------------------------------------------------------------- redis token


@pytest.mark.asyncio
async def test_verification_token_stored_in_redis_with_ttl(
    db_session, redis_client, email_service
):
    await register_identity(
        db_session, redis_client, email_service,
        email="c@ex.com", password="Secret1!abc",
        full_name="C", organization_name="C Co",
    )

    # Exactly one email_verify:<hash> key, with TTL near 24h.
    keys = [k async for k in redis_client.scan_iter(match=f"{EMAIL_VERIFY_PREFIX}:*")]
    assert len(keys) == 1
    key = keys[0]
    assert key.startswith(f"{EMAIL_VERIFY_PREFIX}:")
    # Shape: email_verify:{64-hex}
    hash_part = key.split(":", 1)[1]
    assert len(hash_part) == 64
    int(hash_part, 16)  # valid hex

    ttl = await redis_client.ttl(key)
    assert 0 < ttl <= TOKEN_TTL_SECONDS


@pytest.mark.asyncio
async def test_email_body_contains_token_whose_hash_is_the_redis_key(
    db_session, redis_client, email_service
):
    """End-to-end proof that the plaintext in the email matches the
    hash stored in Redis — i.e. the user can actually verify."""
    await register_identity(
        db_session, redis_client, email_service,
        email="d@ex.com", password="Secret1!abc",
        full_name="D", organization_name="D Co",
    )
    assert len(email_service.outbox) == 1
    msg = email_service.outbox[0]
    assert msg.template == "verify_email"
    assert "token=" in msg.body

    # Extract the token from the emitted URL.
    token = msg.body.split("token=", 1)[1].split()[0]
    expected_key = f"{EMAIL_VERIFY_PREFIX}:{hashlib.sha256(token.encode()).hexdigest()}"
    value = await redis_client.get(expected_key)
    assert value is not None  # key exists → user can verify


# ---------------------------------------------------------------- failures


@pytest.mark.asyncio
async def test_duplicate_email_raises_and_rolls_back(
    db_session, redis_client, email_service
):
    # First registration succeeds.
    await register_identity(
        db_session, redis_client, email_service,
        email="dup@ex.com", password="Secret1!abc",
        full_name="First", organization_name="First Co",
    )

    # Second with same email bombs with the typed exception.
    with pytest.raises(EmailAlreadyRegistered):
        await register_identity(
            db_session, redis_client, email_service,
            email="dup@ex.com", password="Different1!xyz",
            full_name="Second", organization_name="Second Co",
        )

    # No "Second Co" row was created (full rollback).
    orgs = (
        await db_session.execute(
            select(Organization).where(Organization.name == "Second Co")
        )
    ).scalars().all()
    assert orgs == []


@pytest.mark.asyncio
async def test_password_over_72_bytes_rejected(
    db_session, redis_client, email_service
):
    with pytest.raises(ValueError, match="72-byte"):
        await register_identity(
            db_session, redis_client, email_service,
            email="big@ex.com",
            password="x" * (MAX_PASSWORD_BYTES + 1),
            full_name="Big", organization_name="Big Co",
        )
    # No side effects.
    assert (await db_session.execute(select(User))).scalars().all() == []
    assert email_service.outbox == []
    keys = [k async for k in redis_client.scan_iter(match="email_verify:*")]
    assert keys == []


# ---------------------------------------------------------------- slug retry


@pytest.mark.asyncio
async def test_slug_collision_retries_with_suffix(
    db_session, redis_client, email_service
):
    """Two orgs with the same slugified name — second gets `-2`."""
    await register_identity(
        db_session, redis_client, email_service,
        email="x1@ex.com", password="Secret1!abc",
        full_name="X1", organization_name="Acme",
    )
    await register_identity(
        db_session, redis_client, email_service,
        email="x2@ex.com", password="Secret1!abc",
        full_name="X2", organization_name="Acme",
    )

    slugs = sorted(
        (await db_session.execute(select(Organization.slug))).scalars().all()
    )
    assert slugs == ["acme", "acme-2"]


@pytest.mark.asyncio
async def test_slug_collision_exhausts_after_max_attempts(
    db_session, redis_client, email_service
):
    """Pre-populate the first MAX_SLUG_ATTEMPTS candidates; next
    register with the same base slug must raise SlugGenerationFailed.
    """
    # Register MAX_SLUG_ATTEMPTS orgs sharing the "zap" base slug —
    # each run creates one slot: zap, zap-2, ..., zap-5.
    for i in range(MAX_SLUG_ATTEMPTS):
        await register_identity(
            db_session, redis_client, email_service,
            email=f"z{i}@ex.com", password="Secret1!abc",
            full_name=f"Z{i}", organization_name="Zap",
        )
    slugs = sorted(
        (await db_session.execute(select(Organization.slug))).scalars().all()
    )
    assert slugs == ["zap", "zap-2", "zap-3", "zap-4", "zap-5"]

    # The next attempt with the same base must exhaust retries.
    with pytest.raises(SlugGenerationFailed):
        await register_identity(
            db_session, redis_client, email_service,
            email="z_last@ex.com", password="Secret1!abc",
            full_name="Z last", organization_name="Zap",
        )
