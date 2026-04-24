"""Auth request/response schemas (Sub-task 2.3.4, Commit 3).

All Pydantic v2 — ``ConfigDict(from_attributes=True)`` on response
models, ``@field_validator`` (never v1 ``@validator``), no
``.from_orm()``.

Password policy rationale (``RegisterRequest.validate_password``):
  - **8–72 bytes** (not chars): bcrypt's 72-byte limit is bytewise;
    a Unicode-heavy password can exceed 72 bytes at <30 chars.
  - **At least one letter + one digit.** No special-char / mixed-case
    requirement — modern NIST SP 800-63B guidance discourages
    character-class mandates (they push users toward predictable
    substitutions). Length is the strongest lever, which is why we
    sit right against the bcrypt ceiling.
"""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.config import settings


# ---------------------------------------------------------------- constants

PASSWORD_MIN_BYTES = 8
PASSWORD_MAX_BYTES = 72  # bcrypt ceiling per ADR-010


# ---------------------------------------------------------------- requests


class RegisterRequest(BaseModel):
    """``POST /auth/register`` body."""

    email: EmailStr
    password: str
    full_name: str = Field(min_length=1, max_length=255)
    organization_name: str = Field(min_length=1, max_length=255)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        # Length check in BYTES, not chars — bcrypt limit is bytewise.
        encoded = v.encode("utf-8")
        if len(encoded) < PASSWORD_MIN_BYTES:
            raise ValueError(
                f"password must be at least {PASSWORD_MIN_BYTES} bytes"
            )
        if len(encoded) > PASSWORD_MAX_BYTES:
            raise ValueError(
                f"password must be at most {PASSWORD_MAX_BYTES} bytes "
                "(bcrypt limit; note that some Unicode characters are "
                "multi-byte)"
            )
        # Structural requirements: >=1 letter and >=1 digit.
        if not any(c.isalpha() for c in v):
            raise ValueError("password must contain at least one letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("password must contain at least one digit")
        return v


class LoginRequest(BaseModel):
    """``POST /auth/login`` body. No password-shape validation here —
    wrong passwords get a generic 401 from the handler, not a 422.
    """

    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class LogoutRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


# ---------------------------------------------------------------- responses


class UserResponse(BaseModel):
    """Outbound user shape — intentionally narrow.

    Fields enumerated EXPLICITLY (not auto-derived) so that adding
    ``hashed_password`` or any future credential column to the
    ``User`` ORM model does NOT auto-leak into API responses.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    full_name: str
    email_verified: bool


class TokenResponse(BaseModel):
    """Matches OAuth 2.0 Access Token Response (RFC 6749 §5.1)
    conventions. ``expires_in`` is the access-token lifetime in
    seconds — clients schedule refresh before it hits zero.
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(
        default=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        description="Access-token lifetime in seconds (OAuth 2.0).",
    )
    user: UserResponse
