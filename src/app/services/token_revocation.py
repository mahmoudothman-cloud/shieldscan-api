"""Refresh-token + access-token revocation list (Sub-task 2.3.4, Commit 1).

Targeted per-jti revocation via Redis. The key's TTL is computed from
the token's own ``exp`` claim — revoked keys auto-expire with the
token they represent, so the list self-cleans without a reaper.

Key shape::

    revoked_jti:{jti}   value: "1"   TTL: token.exp - now (seconds)

User-level revocation (all tokens for a user invalidated on password
change) is a separate, later mechanism using ``user_revoked_before:
{user_id}`` compared against the token's ``iat`` claim. That hook is
already in place (commit `4d32fcc`) but its consumer lands with the
password-change endpoint — see ADR-011.

Fail-closed posture: every ``is_revoked`` check must return True or
raise if Redis is unavailable. Silently returning False would let
revoked tokens back in during an outage. See OPERATIONS-RUNBOOK §11.6.
"""

from __future__ import annotations

import time

import redis.asyncio as redis_asyncio


REVOKED_JTI_PREFIX = "revoked_jti"


def _key(jti: str) -> str:
    return f"{REVOKED_JTI_PREFIX}:{jti}"


async def revoke(
    redis: redis_asyncio.Redis,
    jti: str,
    exp_unix: int,
) -> None:
    """Mark ``jti`` revoked until its natural expiry.

    ``exp_unix`` is the token's ``exp`` claim (unix seconds). TTL is
    computed as ``exp_unix - now``; if the token is already expired
    the entry is skipped (no point storing a key Redis would immediately
    evict, and ``SET EX 0`` is an error on some Redis builds).

    Idempotent: calling twice for the same jti is safe — the second
    call simply overwrites with the same value and a slightly smaller
    TTL. No error raised.
    """
    ttl = exp_unix - int(time.time())
    if ttl <= 0:
        return
    await redis.set(_key(jti), "1", ex=ttl)


async def is_revoked(
    redis: redis_asyncio.Redis,
    jti: str,
) -> bool:
    """Return True iff the jti is in the revocation list.

    ``EXISTS`` returns 0 for missing, 1 for present — coerced to
    bool here so callers can write ``if await is_revoked(...)``.
    """
    return bool(await redis.exists(_key(jti)))
