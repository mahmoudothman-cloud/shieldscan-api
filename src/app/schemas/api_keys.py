"""API-key request/response schemas + dual-kind identity response
(Task 2.4, Commit 2).

Three DISTINCT schemas implement the plaintext-only-once discipline:

  APIKeyCreateRequest     — input, no secrets
  APIKeyCreatedResponse   — 201 response from POST; INCLUDES plaintext_key.
                            NEVER reused for list / get / any other path.
  APIKeySummary           — all other responses (list item, nested inside
                            AuthIdentityResponse). EXCLUDES plaintext_key,
                            EXCLUDES key_hash. Built from the ORM row.

Keeping these as three types (not one with optional fields) is the
forcing function that prevents a future refactor from accidentally
merging them and leaking plaintext_key into a list response.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.auth import UserResponse


# ---------------------------------------------------------------- API key


class APIKeyCreateRequest(BaseModel):
    """``POST /auth/api-keys`` body. No scopes field — scopes are
    deferred until schema support lands (see ADR-012 follow-ups).
    """

    name: str = Field(min_length=1, max_length=255)


class APIKeyCreatedResponse(BaseModel):
    """201 response from ``POST /auth/api-keys``. This is the ONLY
    response shape that carries ``plaintext_key`` — it is visible to
    the client exactly once, at creation, and never persisted in any
    long-lived store (not DB, not audit log, not email).
    """

    id: UUID
    name: str
    key_prefix: str
    plaintext_key: str
    created_at: datetime


class APIKeySummary(BaseModel):
    """Response shape for list / nested-in-identity. EXCLUDES
    plaintext_key by construction — the field doesn't exist on the
    schema, so no accidental inclusion is possible even if the caller
    serializes the full ORM row."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    key_prefix: str
    last_used_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


# ---------------------------------------------------------------- identity


class OrganizationSummary(BaseModel):
    """Minimal org shape embedded in AuthIdentityResponse."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str


class AuthIdentityResponse(BaseModel):
    """Discriminated-union shape returned by ``GET /auth/me``.

    Clients MUST branch on ``kind``:
      - ``kind == "jwt"``:     ``user`` populated, ``api_key`` is null
      - ``kind == "api_key"``: ``api_key`` populated, ``user`` is null

    Pre-launch: this replaces the flat ``UserResponse`` that ``/auth/me``
    returned in Task 2.3. Documented as a deliberate breaking change
    in DRIFT-LOG (pre-launch window; no external clients).
    """

    kind: Literal["jwt", "api_key"]
    organization: OrganizationSummary
    user: UserResponse | None = None
    api_key: APIKeySummary | None = None
