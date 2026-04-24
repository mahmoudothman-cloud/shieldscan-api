"""Project request/response schemas (Task 3.1).

Pydantic v2 throughout. ``ConfigDict(from_attributes=True)`` on
response models. Validators use ``@field_validator``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from urllib.parse import urlparse
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _validate_https_url(v: str) -> str:
    """Reject non-HTTPS URLs (HTTP would be tested in plaintext).

    Empty / non-URL strings caught here too — caller's caller (the
    schema validator) renders these as 422.
    """
    if not v:
        raise ValueError("target_url is required")
    parsed = urlparse(v)
    if parsed.scheme != "https":
        raise ValueError("target_url must use https://")
    if not parsed.hostname:
        raise ValueError("target_url must include a hostname")
    return v


# ---------------------------------------------------------------- requests


class ProjectCreateRequest(BaseModel):
    """``POST /v1/orgs/{org_id}/projects`` body.

    ``root_domain`` is derived server-side from ``target_url`` —
    never accepted from the client (it's the security boundary that
    Task 3.2's verify endpoint binds to).
    """

    name: str = Field(min_length=1, max_length=255)
    target_url: str = Field(min_length=1, max_length=500)
    source_repo_url: str | None = Field(default=None, max_length=500)
    container_image: str | None = Field(default=None, max_length=255)

    @field_validator("target_url")
    @classmethod
    def _validate_target_url(cls, v: str) -> str:
        return _validate_https_url(v)


class ProjectUpdateRequest(BaseModel):
    """``PATCH /v1/orgs/{org_id}/projects/{id}`` body.

    All fields optional — caller sends only what's changing.
    Immutable fields (``id``, ``organization_id``, ``root_domain``,
    ``domain_verified``, ``verification_token``, ``archived_at``)
    don't appear here at all; sending them is a 422 (extra fields
    rejected) per Pydantic default.

    NOTE: ``target_url`` change that alters root_domain auto-resets
    ``domain_verified`` and re-mints ``verification_token`` — handled
    in the route handler, not this schema. See DRIFT-LOG 2026-04-23.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    target_url: str | None = Field(default=None, min_length=1, max_length=500)
    source_repo_url: str | None = Field(default=None, max_length=500)
    container_image: str | None = Field(default=None, max_length=255)

    @field_validator("target_url")
    @classmethod
    def _validate_target_url(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _validate_https_url(v)


# ---------------------------------------------------------------- responses


class ProjectResponse(BaseModel):
    """Project as returned to the client. Fields explicitly enumerated
    so that adding ORM columns later doesn't auto-leak them."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    name: str
    target_url: str
    root_domain: str
    source_repo_url: str | None
    container_image: str | None
    domain_verified: bool
    verification_token: str  # included on read — see Task 3.1 §H decision #2
    archived_at: datetime | None
    created_at: datetime
    updated_at: datetime


class PaginationMeta(BaseModel):
    """Pagination block for list responses (Task 3.1 §H decision #7)."""

    page: int
    per_page: int
    total: int
    total_pages: int
    has_next: bool
    has_prev: bool


class PaginatedProjectsResponse(BaseModel):
    """Standard list-response envelope. The ``pagination`` block
    extends cleanly when cursor-based pagination is added later."""

    items: list[ProjectResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------- list query


# Allowed sort keys — anything else → 422.
_SORT_KEYS = {"created_at", "updated_at", "name"}


def _validate_sort_key(v: str) -> str:
    key = v.lstrip("-")
    if key not in _SORT_KEYS:
        raise ValueError(
            f"sort key must be one of {sorted(_SORT_KEYS)} "
            f"(prefix with '-' for descending)"
        )
    return v


PageNumber = Annotated[int, Field(ge=1)]
PerPage = Annotated[int, Field(ge=1, le=100)]


# ---------------------------------------------------------------- /verify (Task 3.2)


class VerifyDomainRequest(BaseModel):
    """``POST /v1/orgs/{org_id}/projects/{id}/verify`` body."""

    method: str = Field(min_length=1)

    @field_validator("method")
    @classmethod
    def _validate_method(cls, v: str) -> str:
        if v not in {"dns_txt", "meta_tag"}:
            raise ValueError("method must be one of: dns_txt, meta_tag")
        return v


class VerifyDomainSuccess(BaseModel):
    """200 body on successful verification."""

    verified: bool = True
    method: str
    project: ProjectResponse


class VerifyDomainFailure(BaseModel):
    """400 body on verification failure. ``expected_record`` shows
    the customer exactly what to add to make verification succeed
    on retry — substantial UX win (Task 3.2 §C extra)."""

    detail: str = "verification_failed"
    method: str
    failure_reason: str
    expected_record: str
