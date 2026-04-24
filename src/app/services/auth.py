"""Password hashing and JWT token utilities.

Task 2.1 scope (per IMPLEMENTATION-PLAN.md §2.1 + M2 envelope + ADR-010):
  - bcrypt hashing with cost factor 12 pinned explicitly
  - HS256 JWTs signed with settings.JWT_SECRET_KEY (ADR-010)
  - access + refresh tokens each carry a unique `jti` claim,
    which later tasks (2.3 / 2.4) will use as the revocation hook
  - decode_token distinguishes expired vs malformed tokens via
    the TokenExpiredError / TokenInvalidError hierarchy so
    callers can signal 401-refresh vs 401-reauth appropriately

# bcrypt has a 72-byte password limit (longer passwords are silently
# truncated by bcrypt itself). The register endpoint (Task 2.2) must
# reject passwords > 72 bytes explicitly with HTTP 400. This function
# does not enforce — it's the caller's responsibility.

Note: we use the `bcrypt` library directly rather than passlib
because passlib 1.7.4 is the last release (Oct 2020) and is
incompatible with bcrypt >= 4.1. See ADR-010.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import bcrypt
from jose import ExpiredSignatureError, JWTError, jwt

from app.config import settings


# ---------------------------------------------------------------- exceptions


class TokenError(Exception):
    """Base class for JWT decode failures. Consumers SHOULD catch this."""


class TokenExpiredError(TokenError):
    """Token signature verified but `exp` is in the past."""


class TokenInvalidError(TokenError):
    """Token is malformed, signed with the wrong key, or otherwise invalid."""


# ---------------------------------------------------------------- password
#
# Cost=12 pinned explicitly. ~250ms on modern server hardware —
# slow enough to frustrate offline cracking, fast enough not to
# DoS the login endpoint. Bumping to 13+ doubles the cost each
# step; coordinate with load tests before changing.
BCRYPT_ROUNDS = 12


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=BCRYPT_ROUNDS),
    ).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    # Defensive guards for future SSO/OAuth users whose `hashed_password`
    # column is NULL, and for malformed hashes that might sneak in from
    # a botched migration.
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------- jwt


def _encode(payload: dict) -> str:
    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_access_token(sub: str, extra: dict | None = None) -> str:
    """Mint a short-lived access token.

    The `jti` claim is a fresh UUID on every call — that's what
    makes per-token revocation (Task 2.3+) possible without
    rewriting this function.
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: dict = {
        "sub": sub,
        "iat": int(now.timestamp()),  # revocation hook (user-level)
        "exp": expire,
        "type": "access",
        "jti": str(uuid4()),
    }
    if extra:
        payload.update(extra)
    return _encode(payload)


def create_refresh_token(sub: str) -> str:
    """Mint a long-lived refresh token.

    Distinct `jti` from any paired access token — revoking a
    refresh must not cascade to the paired access token by
    accident.
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": sub,
        "iat": int(now.timestamp()),  # revocation hook (user-level)
        "exp": expire,
        "type": "refresh",
        "jti": str(uuid4()),
    }
    return _encode(payload)


def decode_token(token: str) -> dict:
    """Decode + verify a JWT.

    Raises:
        TokenExpiredError: signature is valid but `exp` has passed.
        TokenInvalidError: malformed, wrong signature, or any other
            JWT failure. Callers should treat as a hard 401.
    """
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except ExpiredSignatureError as e:
        raise TokenExpiredError(str(e)) from e
    except JWTError as e:
        raise TokenInvalidError(str(e)) from e
