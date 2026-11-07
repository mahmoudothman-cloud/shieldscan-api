"""Public quick-scan schemas (M11 pre-work; ADDENDUM-CRITICAL-5 §2).

Request: target URL + work email + explicit consent. Response: a slug
the client polls; the result view shows a score, the top findings in
full and only the *count* of the rest (the "create an account" hook,
flow F1 of the approved dashboard design).
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.schemas.auth import normalize_email


class PublicScanCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=1, max_length=500)
    email: EmailStr
    consent: bool = Field(
        description=(
            "Requester confirms they own the target or have written permission "
            "to scan it (Egypt Law 175/2018 and the target's jurisdiction)."
        )
    )

    @field_validator("target_url")
    @classmethod
    def _https_hostname(cls, v: str) -> str:
        v = v.strip()
        if "://" not in v:
            v = "https://" + v
        parsed = urlparse(v)
        if parsed.scheme != "https":
            raise ValueError("target_url must use https://")
        host = parsed.hostname
        if not host:
            raise ValueError("target_url must include a hostname")
        if parsed.username or parsed.password:
            raise ValueError("target_url must not carry credentials")
        # Rebuild without query/fragment: a quick scan targets an origin
        # (plus path), not a specific request.
        port = f":{parsed.port}" if parsed.port and parsed.port != 443 else ""
        path = parsed.path.rstrip("/") or ""
        return f"https://{host.lower()}{port}{path}"

    @field_validator("email", mode="after")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return normalize_email(v)

    @field_validator("consent")
    @classmethod
    def _must_consent(cls, v: bool) -> bool:
        if not v:
            raise ValueError("consent is required")
        return v


class PublicScanCreateResponse(BaseModel):
    slug: str
    status: str
    target_url: str
    result_url: str
    estimated_seconds: int
    expires_at: datetime


class PublicFinding(BaseModel):
    title: str
    severity: str
    engine: str
    summary: str | None
    target_url: str | None


class PublicSeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class PublicScanResultResponse(BaseModel):
    slug: str
    status: str  # queued | running | completed | partial | failed | canceled | expired
    target_url: str
    domain: str
    created_at: datetime
    completed_at: datetime | None
    expires_at: datetime
    engines_total: int
    engines_finished: int
    score: int | None
    grade: str | None
    findings_by_severity: PublicSeverityCounts
    findings: list[PublicFinding]
    hidden_count: int
    register_url: str
