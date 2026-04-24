"""Tests for app.services.token_revocation — 2.3.4 Commit 1."""

from __future__ import annotations

import time
from uuid import uuid4

import pytest
import pytest_asyncio
from fakeredis import aioredis as fakeredis_aio

from app.services.token_revocation import (
    REVOKED_JTI_PREFIX,
    is_revoked,
    revoke,
)


@pytest_asyncio.fixture
async def redis_client():
    client = fakeredis_aio.FakeRedis(decode_responses=True)
    try:
        yield client
    finally:
        await client.flushall()
        await client.aclose()


# ---------------------------------------------------------------- is_revoked


@pytest.mark.asyncio
async def test_is_revoked_false_for_missing_jti(redis_client):
    """Fresh jti — never seen before — must report not revoked."""
    assert await is_revoked(redis_client, str(uuid4())) is False


@pytest.mark.asyncio
async def test_is_revoked_true_after_revoke(redis_client):
    jti = str(uuid4())
    exp = int(time.time()) + 3600
    await revoke(redis_client, jti, exp_unix=exp)
    assert await is_revoked(redis_client, jti) is True


# ---------------------------------------------------------------- revoke


@pytest.mark.asyncio
async def test_revoke_computes_ttl_from_exp_not_constant(redis_client):
    """TTL must track the token's own exp, not a fixed constant —
    otherwise we either leak keys past the token's natural expiry
    (memory) or expire early (token reusable after TTL).
    """
    jti = str(uuid4())
    now = int(time.time())
    # Token that still has ~1h left.
    await revoke(redis_client, jti, exp_unix=now + 3600)
    ttl = await redis_client.ttl(f"{REVOKED_JTI_PREFIX}:{jti}")
    assert 3500 < ttl <= 3600  # allow a couple seconds of test runtime


@pytest.mark.asyncio
async def test_revoke_skips_already_expired_token(redis_client):
    """Revoking a token whose exp is already in the past is a no-op —
    the token couldn't be used anyway, and SET EX 0 is ill-defined.
    """
    jti = str(uuid4())
    past = int(time.time()) - 60
    await revoke(redis_client, jti, exp_unix=past)
    # No key written — so is_revoked returns False.
    assert await is_revoked(redis_client, jti) is False


@pytest.mark.asyncio
async def test_revoke_is_idempotent(redis_client):
    """Calling revoke twice for the same jti must not error. Use
    case: the /logout handler and a subsequent /refresh reuse-detect
    might both attempt to revoke the same refresh jti.
    """
    jti = str(uuid4())
    exp = int(time.time()) + 3600
    await revoke(redis_client, jti, exp_unix=exp)
    # Second call — no exception.
    await revoke(redis_client, jti, exp_unix=exp)
    assert await is_revoked(redis_client, jti) is True


@pytest.mark.asyncio
async def test_revoke_stores_under_expected_key_prefix(redis_client):
    """Ops monitoring relies on `SCAN MATCH revoked_jti:*` to see the
    current revocation list. Pin the prefix shape as a regression
    guard against silent refactors."""
    jti = str(uuid4())
    await revoke(redis_client, jti, exp_unix=int(time.time()) + 60)
    keys = [k async for k in redis_client.scan_iter(match=f"{REVOKED_JTI_PREFIX}:*")]
    assert len(keys) == 1
    assert keys[0] == f"{REVOKED_JTI_PREFIX}:{jti}"
