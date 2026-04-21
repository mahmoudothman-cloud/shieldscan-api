"""Tests for app.services.auth — Task 2.1.

Covers the five public functions (hash_password, verify_password,
create_access_token, create_refresh_token, decode_token) plus the
distinct token-error hierarchy (TokenError / TokenExpiredError /
TokenInvalidError) and the jti-claim hook that later tasks will use
for refresh-token revocation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from jose import jwt

from app.config import settings


# ---------------------------------------------------------------- hashing


def test_hash_and_verify_password():
    from app.services.auth import hash_password, verify_password

    pwd = "SecureP@ssw0rd123"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("wrong", hashed) is False


def test_bcrypt_cost_factor_is_12():
    """bcrypt hashes encode the cost factor as `$2b$<cost>$…`.

    We pin cost=12 explicitly (rather than relying on passlib's
    default) so the pin survives passlib upgrades.
    """
    from app.services.auth import hash_password

    hashed = hash_password("any-password")
    # Format: $2b$12$<22-char-salt><31-char-hash>
    assert hashed.startswith("$2b$12$"), f"expected cost=12 bcrypt, got {hashed[:10]}"


# ---------------------------------------------------------------- jwt basics


def test_create_and_decode_jwt():
    from app.services.auth import create_access_token, decode_token

    user_id = uuid4()
    token = create_access_token(sub=str(user_id))
    payload = decode_token(token)
    assert payload["sub"] == str(user_id)


# ---------------------------------------------------------------- jti claim


def test_access_token_has_jti_claim():
    from app.services.auth import create_access_token, decode_token

    t1 = create_access_token(sub=str(uuid4()))
    t2 = create_access_token(sub=str(uuid4()))
    p1 = decode_token(t1)
    p2 = decode_token(t2)
    # jti must be a parseable UUID
    UUID(p1["jti"])
    UUID(p2["jti"])
    # and distinct across calls
    assert p1["jti"] != p2["jti"]
    assert p1["type"] == "access"


def test_refresh_token_has_jti_claim_and_type():
    from app.services.auth import create_refresh_token, decode_token

    token = create_refresh_token(sub=str(uuid4()))
    payload = decode_token(token)
    UUID(payload["jti"])
    assert payload["type"] == "refresh"


def test_access_and_refresh_tokens_have_different_jti():
    """Regression guard: if the two token factories ever share a UUID
    instance (e.g. module-level `_JTI = uuid4()`), revoking a refresh
    would inadvertently revoke its paired access token.
    """
    from app.services.auth import (
        create_access_token,
        create_refresh_token,
        decode_token,
    )

    sub = str(uuid4())
    access_payload = decode_token(create_access_token(sub=sub))
    refresh_payload = decode_token(create_refresh_token(sub=sub))
    assert access_payload["jti"] != refresh_payload["jti"]


# ---------------------------------------------------------------- errors


def test_decode_raises_token_expired_error_for_expired_token():
    from app.services.auth import TokenError, TokenExpiredError, decode_token

    # Mint a token with exp in the past using the same secret/alg.
    past = datetime.now(timezone.utc) - timedelta(seconds=60)
    payload = {"sub": "x", "exp": past, "type": "access", "jti": str(uuid4())}
    expired = jwt.encode(
        payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )
    with pytest.raises(TokenExpiredError) as excinfo:
        decode_token(expired)
    # Must be catchable as the common base class too.
    assert isinstance(excinfo.value, TokenError)


def test_decode_raises_token_invalid_error_for_malformed_token():
    from app.services.auth import TokenError, TokenInvalidError, decode_token

    with pytest.raises(TokenInvalidError) as excinfo:
        decode_token("not.a.jwt")
    assert isinstance(excinfo.value, TokenError)


def test_token_expired_and_invalid_are_both_token_error():
    """Consumers should be able to `except TokenError` and catch either
    subtype — the hierarchy is part of the public contract.
    """
    from app.services.auth import TokenError, TokenExpiredError, TokenInvalidError

    assert issubclass(TokenExpiredError, TokenError)
    assert issubclass(TokenInvalidError, TokenError)
    assert TokenExpiredError is not TokenInvalidError
