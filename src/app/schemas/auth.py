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


def normalize_email(email: str) -> str:
    """Canonical form for email comparison across register / login /
    resend-verification. Strip surrounding whitespace, lowercase the
    whole address (Pydantic EmailStr only lowercases the domain).

    Applied at three layers (defense-in-depth):
      - Pydantic ``@field_validator`` on every ``EmailStr`` request
        field (schemas/auth.py + schemas/api_keys.py if applicable).
      - ``register_identity`` redundantly normalizes for non-HTTP
        callers (CLI tools, background jobs).
      - DB ``CHECK (email = lower(email))`` as the last line.

    See DRIFT-LOG 2026-04-21 email-normalization entry for the bug
    this closes (case-varied duplicate registration / login lock-out).
    """
    return email.strip().lower()


def validate_password_shape(v: str) -> str:
    """Shared password-shape validator — used by RegisterRequest
    (initial password) and PasswordChangeRequest (new password).

    Centralizing here ensures the two validators don't drift; if
    we tighten the policy later (e.g. raise minimum length, ban
    common dictionary words), there's one place to do it.
    """
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
    if not any(c.isalpha() for c in v):
        raise ValueError("password must contain at least one letter")
    if not any(c.isdigit() for c in v):
        raise ValueError("password must contain at least one digit")
    return v


# ---------------------------------------------------------------- requests


class RegisterRequest(BaseModel):
    """``POST /auth/register`` body."""

    email: EmailStr
    password: str
    full_name: str = Field(min_length=1, max_length=255)
    organization_name: str = Field(min_length=1, max_length=255)

    @field_validator("email", mode="after")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return normalize_email(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_shape(v)


class LoginRequest(BaseModel):
    """``POST /auth/login`` body. No password-shape validation here —
    wrong passwords get a generic 401 from the handler, not a 422.
    """

    email: EmailStr
    password: str

    @field_validator("email", mode="after")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return normalize_email(v)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class LogoutRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class VerifyEmailRequest(BaseModel):
    """``POST /auth/verify-email`` body. Token is the plaintext value
    from the verification link; its SHA-256 is GETDEL'd from Redis."""

    token: str = Field(min_length=1)


class PasswordChangeRequest(BaseModel):
    """``POST /auth/password/change`` body.

    ``current_password`` has no shape validation — verification
    against the stored hash is what proves possession. Validating
    its shape here would be theatre.

    ``new_password`` reuses the registration validator (8-72 bytes,
    >=1 letter, >=1 digit). Future tightening (e.g. dictionary
    blocklist) lives in ``validate_password_shape`` so register
    and change stay in lockstep.
    """

    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _validate_new_password(cls, v: str) -> str:
        return validate_password_shape(v)


class ForgotPasswordRequest(BaseModel):
    """``POST /auth/forgot-password`` body. Email normalization here
    feeds the per-email rate-limit bucket — without it, case-varied
    inputs would evade the limiter (same enumeration concern as
    ``ResendVerificationRequest``)."""

    email: EmailStr

    @field_validator("email", mode="after")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return normalize_email(v)


class ResetPasswordRequest(BaseModel):
    """``POST /auth/reset-password`` body. ``token`` is the plaintext
    from the reset link; its SHA-256 is GETDEL'd from Redis.

    ``new_password`` reuses the shared password-shape validator. We
    do NOT reject "new equals current" here (unlike
    ``PasswordChangeRequest``): the user reaching this endpoint by
    definition does not remember their current password, so checking
    against it would be theatre. See Task 2.Y DRIFT-LOG entry on
    the asymmetry.
    """

    token: str = Field(min_length=1)
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _validate_new_password(cls, v: str) -> str:
        return validate_password_shape(v)


class ResendVerificationRequest(BaseModel):
    """``POST /auth/resend-verification`` body. Email normalization
    here feeds the rate-limit bucket — without it, case-varied inputs
    would evade the per-email limit (`Alice@x.com` and `alice@x.com`
    would share zero counter state)."""

    email: EmailStr

    @field_validator("email", mode="after")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return normalize_email(v)


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
