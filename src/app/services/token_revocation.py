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

import logging
import time
from uuid import UUID

import redis.asyncio as redis_asyncio


logger = logging.getLogger(__name__)

REVOKED_JTI_PREFIX = "revoked_jti"
USER_REVOKED_BEFORE_PREFIX = "user_revoked_before"


def _key(jti: str) -> str:
    return f"{REVOKED_JTI_PREFIX}:{jti}"


async def revoke(
    redis: redis_asyncio.Redis,
    jti: str,
    exp_unix: int,
) -> None:
    """Mark ``jti`` revoked until its natural expiry.

    ``exp_unix`` is the token's ``exp`` claim (unix seconds). TTL is
    computed as ``exp_unix - now``; behavior at the floor:

      - ``ttl <= 0``  (token already expired):   skipped — no Redis write.
                      ``SET EX 0`` is an error on some Redis builds.
      - ``0 < ttl < 1``: cannot arise with integer ``exp_unix``
                      (int subtraction of ints yields an int). If a
                      future caller passes a float, round **up** to 1
                      second before calling ``SET EX`` — never 0.
      - ``ttl >= 1``:   used as-is.

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


# ---------------------------------------------------------------- user-level revocation (Task 2.X)

# See ADR-011 "Deferred" section (shipped in Task 2.X). Used by the
# password-change endpoint to invalidate every token issued before
# the change timestamp, by comparing the token's `iat` claim against
# this Redis-stored unix timestamp.


def _user_key(user_id: UUID | str) -> str:
    return f"{USER_REVOKED_BEFORE_PREFIX}:{user_id}"


async def set_user_revoked_before(
    redis: redis_asyncio.Redis,
    user_id: UUID | str,
    unix_ts: int,
    ttl_seconds: int,
) -> None:
    """Mark every token for ``user_id`` with ``iat < unix_ts`` invalid.

    ``unix_ts`` is a unix-seconds int (matches the ``iat`` claim
    format from ``auth.create_access_token`` / ``create_refresh_token``).

    ``ttl_seconds`` SHOULD be ``JWT_REFRESH_TOKEN_EXPIRE_DAYS * 86400``
    — older tokens couldn't still be cryptographically valid beyond
    that anyway, so the revocation key doesn't need to outlive them.

    Called by:
      - ``POST /auth/password/change`` (Task 2.X)
      - Future admin-force-logout + account-recovery flows.
    """
    await redis.set(_user_key(user_id), unix_ts, ex=ttl_seconds)


async def get_user_revoked_before(
    redis: redis_asyncio.Redis,
    user_id: UUID | str,
) -> int | None:
    """Return the unix timestamp after which all of this user's
    pre-existing tokens are revoked, or ``None`` if the user has
    never had a user-level revocation set.

    Callers compare: if ``token.iat < returned_value``, the token
    is invalid. ``None`` short-circuits the check — no revocation
    has ever been applied to this user (ADR-011 Option C).

    Raises ``ValueError`` on malformed stored value (shouldn't
    happen in normal operation; caller should treat as Redis
    error and fail closed).
    """
    raw = await redis.get(_user_key(user_id))
    if raw is None:
        return None
    return int(raw)
