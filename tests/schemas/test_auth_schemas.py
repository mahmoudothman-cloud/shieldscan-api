"""Tests for app.schemas.auth — Sub-task 2.3.4, Commit 3."""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.models.identity import User
from app.schemas.auth import (
    PASSWORD_MAX_BYTES,
    PASSWORD_MIN_BYTES,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.schemas.errors import ErrorResponse


# ---------------------------------------------------------------- RegisterRequest


def test_register_request_accepts_valid_input():
    r = RegisterRequest(
        email="new@test.com",
        password="Secure12345",
        full_name="New User",
        organization_name="New Co",
    )
    assert r.email == "new@test.com"
    assert r.password == "Secure12345"


def test_register_request_rejects_short_password():
    with pytest.raises(ValidationError, match="at least"):
        RegisterRequest(
            email="a@b.c", password="Ab1", full_name="X",
            organization_name="Y",
        )


def test_register_request_rejects_password_exceeding_72_bytes_ascii():
    # 73 ASCII chars = 73 bytes.
    with pytest.raises(ValidationError, match="at most"):
        RegisterRequest(
            email="a@b.c",
            password="A" + "a" * 71 + "1",  # 73 bytes, has letter+digit
            full_name="X",
            organization_name="Y",
        )


def test_register_request_rejects_unicode_password_exceeding_72_bytes():
    """30-char password of 4-byte emoji = 120 bytes, well over the
    bcrypt limit — must be rejected even though len(str)=30 < 72.
    Regression guard against validating chars-not-bytes.
    """
    emoji_password = "a1" + ("😀" * 18)  # 2 + 72 = 74 bytes
    assert len(emoji_password) < PASSWORD_MAX_BYTES  # chars-wise "fits"
    assert len(emoji_password.encode("utf-8")) > PASSWORD_MAX_BYTES
    with pytest.raises(ValidationError, match="at most"):
        RegisterRequest(
            email="a@b.c", password=emoji_password,
            full_name="X", organization_name="Y",
        )


def test_register_request_rejects_password_without_letter():
    with pytest.raises(ValidationError, match="letter"):
        RegisterRequest(
            email="a@b.c", password="12345678",
            full_name="X", organization_name="Y",
        )


def test_register_request_rejects_password_without_digit():
    with pytest.raises(ValidationError, match="digit"):
        RegisterRequest(
            email="a@b.c", password="abcdefghXYZ",
            full_name="X", organization_name="Y",
        )


def test_register_request_rejects_invalid_email():
    with pytest.raises(ValidationError):
        RegisterRequest(
            email="not-an-email", password="Secure12345",
            full_name="X", organization_name="Y",
        )


def test_register_request_rejects_empty_full_name():
    with pytest.raises(ValidationError):
        RegisterRequest(
            email="a@b.c", password="Secure12345",
            full_name="", organization_name="Y",
        )


def test_register_request_rejects_empty_organization_name():
    with pytest.raises(ValidationError):
        RegisterRequest(
            email="a@b.c", password="Secure12345",
            full_name="X", organization_name="",
        )


def test_register_request_rejects_overlong_name_fields():
    with pytest.raises(ValidationError):
        RegisterRequest(
            email="a@b.c", password="Secure12345",
            full_name="A" * 256, organization_name="Y",
        )
    with pytest.raises(ValidationError):
        RegisterRequest(
            email="a@b.c", password="Secure12345",
            full_name="X", organization_name="B" * 256,
        )


def test_password_bounds_are_bytes_not_chars():
    """Sanity pin on the constants — bcrypt's boundary is bytewise."""
    assert PASSWORD_MIN_BYTES == 8
    assert PASSWORD_MAX_BYTES == 72


# ---------------------------------------------------------------- LoginRequest


def test_login_request_accepts_valid_input():
    r = LoginRequest(email="a@b.c", password="anything")
    assert r.email == "a@b.c"


def test_login_request_has_no_password_shape_validation():
    """Login accepts any non-empty password string — the shape check
    belongs on register. If we validated here, an attacker could
    enumerate which accounts have "strong" passwords from 422 vs 401
    responses.
    """
    # Short password is accepted at the schema layer.
    r = LoginRequest(email="a@b.c", password="x")
    assert r.password == "x"


def test_login_request_rejects_invalid_email():
    with pytest.raises(ValidationError):
        LoginRequest(email="nope", password="anything")


# ---------------------------------------------------------------- refresh / logout


def test_refresh_request_requires_non_empty_token():
    RefreshRequest(refresh_token="abc")  # ok
    with pytest.raises(ValidationError):
        RefreshRequest(refresh_token="")


def test_logout_request_requires_non_empty_token():
    LogoutRequest(refresh_token="abc")
    with pytest.raises(ValidationError):
        LogoutRequest(refresh_token="")


# ---------------------------------------------------------------- UserResponse


def test_user_response_builds_from_orm_via_from_attributes():
    """Pydantic v2: `model_validate(obj, from_attributes=True)` — NOT
    v1's `.from_orm()`. If someone accidentally reverts to v1 API
    this test breaks the build."""
    user = User(
        id=uuid4(),
        email="u@t.co",
        hashed_password="hashed-should-not-leak",
        full_name="U",
        email_verified=True,
    )
    resp = UserResponse.model_validate(user)
    assert resp.email == "u@t.co"
    assert resp.full_name == "U"
    assert resp.email_verified is True
    assert resp.id == user.id


def test_user_response_does_not_expose_password_fields():
    """Regression guard: the response schema must never serialize
    ``hashed_password`` (or any variant). If someone adds the field
    to the schema for convenience, this test flags it immediately.
    """
    user = User(
        id=uuid4(),
        email="u@t.co",
        hashed_password="SECRET-MUST-NOT-LEAK-hashed",
        full_name="U",
        email_verified=False,
    )
    resp = UserResponse.model_validate(user)
    dumped = resp.model_dump()
    json_str = resp.model_dump_json()

    forbidden = ("hashed_password", "password", "SECRET-MUST-NOT-LEAK-hashed")
    for fb in forbidden:
        assert fb not in dumped, f"{fb!r} leaked in model_dump()"
        assert fb not in json_str, f"{fb!r} leaked in model_dump_json()"


def test_user_response_schema_has_no_password_field_in_openapi():
    """Catches accidental addition of password fields at schema level
    (belt-and-suspenders over the value-level check above)."""
    schema = UserResponse.model_json_schema()
    props = set(schema.get("properties", {}).keys())
    assert props == {"id", "email", "full_name", "email_verified"}, (
        f"UserResponse must expose exactly these fields, got {props}"
    )


# ---------------------------------------------------------------- TokenResponse


def test_token_response_has_oauth_fields():
    user = User(
        id=uuid4(), email="u@t.co", hashed_password="x",
        full_name="U", email_verified=True,
    )
    resp = TokenResponse(
        access_token="a.a.a",
        refresh_token="r.r.r",
        user=UserResponse.model_validate(user),
    )
    dumped = resp.model_dump()
    assert dumped["access_token"] == "a.a.a"
    assert dumped["refresh_token"] == "r.r.r"
    assert dumped["token_type"] == "bearer"
    # expires_in default = JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60 = 15 * 60
    assert dumped["expires_in"] == 900
    assert dumped["user"]["email"] == "u@t.co"


def test_token_response_does_not_leak_password():
    """Double-check the nested UserResponse inside TokenResponse
    doesn't leak credentials when serialized end-to-end."""
    user = User(
        id=uuid4(), email="u@t.co",
        hashed_password="must-not-leak-hashed-via-token",
        full_name="U", email_verified=True,
    )
    resp = TokenResponse(
        access_token="a", refresh_token="r",
        user=UserResponse.model_validate(user),
    )
    assert "must-not-leak-hashed-via-token" not in resp.model_dump_json()
    assert "hashed_password" not in resp.model_dump_json()


# ---------------------------------------------------------------- ErrorResponse


def test_error_response_has_detail_field():
    r = ErrorResponse(detail="unauthorized")
    assert r.model_dump() == {"detail": "unauthorized"}
