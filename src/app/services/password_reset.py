"""Password reset token mints + storage.

Mirrors ``email_verification.py`` in structure but has distinct
security properties:

- **Shorter TTL** (1 hour vs 24 hours) — reset is the higher-value
  target (full account takeover on consumption); shorter window
  reduces the attack surface from email-prefetch / mail-relay
  exposure.
- **Separate Redis namespace** (``password_reset:`` vs
  ``email_verify:``) — prevents accidental cross-purpose use; an
  email-verification token can never be consumed as a password
  reset and vice versa.
- **Must pair with ``set_user_revoked_before`` on consumption**
  (see ADR-011 + Task 2.X). Reset is functionally a forced
  password change; the security posture must be at least as strong.

See Task 2.Y DRIFT-LOG entries for full reasoning on TTL choice
+ reset-vs-change asymmetries.
"""

from __future__ import annotations

import hashlib
import secrets
from uuid import UUID

import redis.asyncio as redis_asyncio


PASSWORD_RESET_PREFIX = "password_reset"
TOKEN_TTL_SECONDS = 3_600  # 1 hour — matches GitHub / Stripe / Auth0 norms


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _key(token: str) -> str:
    return f"{PASSWORD_RESET_PREFIX}:{_hash(token)}"


async def issue_password_reset_token(
    redis: redis_asyncio.Redis,
    user_id: UUID,
) -> str:
    """Mint a fresh reset token, store ``SHA-256(token) -> user_id``
    in Redis with a 1-hour TTL, return the plaintext.

    The caller embeds the plaintext in the password-reset link sent
    via email; only the SHA-256 hash is persisted. Single-use is
    enforced by ``GETDEL`` at consumption time.
    """
    plaintext = secrets.token_urlsafe(32)
    await redis.set(_key(plaintext), str(user_id), ex=TOKEN_TTL_SECONDS)
    return plaintext
