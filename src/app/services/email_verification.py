"""Email-verification token issuance + consumption (Sub-task 2.3.3).

Tokens are Redis-backed per IMPLEMENTATION-PLAN §2.5 — no DB schema
change. The plaintext token is emailed to the user; only the SHA-256
hash is stored in Redis. Single-use is enforced by ``DEL`` on
successful verification; 24h expiry is enforced by Redis TTL.

Key shape::

    email_verify:{sha256_hex}   value: str(user_id)   TTL: 86400s

Namespace chosen to sit alongside ``ratelimit:*`` so ops ``SCAN MATCH
email_verify:*`` shows all outstanding tokens.

Consumption (``POST /auth/verify-email``) lands in Task 2.5. This
module ships only ``issue_email_verification_token`` for now.
"""

from __future__ import annotations

import hashlib
import secrets
from uuid import UUID

import redis.asyncio as redis_asyncio


EMAIL_VERIFY_PREFIX = "email_verify"
TOKEN_TTL_SECONDS = 86_400  # 24h per plan §2.5


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _key(token: str) -> str:
    return f"{EMAIL_VERIFY_PREFIX}:{_hash(token)}"


async def issue_email_verification_token(
    redis: redis_asyncio.Redis,
    user_id: UUID,
) -> str:
    """Mint a fresh token, store ``SHA-256(token) -> user_id`` in Redis
    with a 24h TTL, and return the plaintext token. The caller is
    responsible for embedding the plaintext in the verification link
    sent to the user — it must never be persisted in a long-lived
    store (audit logs, DB columns, etc.).

    ``secrets.token_urlsafe(32)`` yields 43 base64url chars — ~256
    bits of entropy, URL-safe without escaping.
    """
    plaintext = secrets.token_urlsafe(32)
    await redis.set(_key(plaintext), str(user_id), ex=TOKEN_TTL_SECONDS)
    return plaintext
