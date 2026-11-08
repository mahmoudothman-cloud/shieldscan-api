"""Organization-level read schemas (M11 pre-work).

``OrgSummaryResponse`` is the dashboard's header in one round-trip:
project counts, scan activity, open vulnerabilities by severity, and the
last finished scan with its raw→unique figure. Everything here is
derived from tables that already exist; nothing is denormalised.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.identity import MembershipRole
from app.schemas.auth import normalize_email


class ProjectCounts(BaseModel):
    total: int
    verified: int
    unverified: int


class ScanCounts(BaseModel):
    total: int
    active: int
    completed_30d: int


class OpenVulnerabilityCounts(BaseModel):
    """Vulnerabilities with status ``open`` on live projects, counted once
    per issue: a newer scan's copy supersedes the older one (cross-scan
    identity, services/vulnerability_identity.py)."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
    corroborated: int = 0


class LastCompletedScan(BaseModel):
    id: UUID
    project_id: UUID
    project_name: str
    status: str
    completed_at: datetime | None
    raw_finding_count: int
    vulnerability_count: int


class OrgSummaryResponse(BaseModel):
    organization_id: UUID
    projects: ProjectCounts
    scans: ScanCounts
    open_vulnerabilities: OpenVulnerabilityCounts
    last_completed_scan: LastCompletedScan | None


# ---------------------------------------------------------------- settings + members (M11 pre-work)


class OrgResponse(BaseModel):
    """``GET /orgs/{org_id}``: the org as the caller sees it, plus the
    caller's own role so the client can gate admin controls without a
    second call. ``my_role`` is ``None`` for API-key callers."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    industry: str | None
    country: str | None
    company_size: str | None
    created_at: datetime
    member_count: int
    my_role: str | None


class OrgPatchRequest(BaseModel):
    """Admin-editable org settings. Slug is identity and stays fixed;
    Stripe/certificate fields are system-owned."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    industry: str | None = Field(default=None, max_length=50)
    country: str | None = Field(default=None, min_length=2, max_length=2)
    company_size: str | None = Field(default=None, max_length=20)

    @field_validator("name", "industry", "company_size")
    @classmethod
    def _strip(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        return v or None

    @field_validator("country")
    @classmethod
    def _upper(cls, v: str | None) -> str | None:
        return v.upper() if v else v


class MemberItem(BaseModel):
    user_id: UUID
    email: str
    full_name: str
    role: str
    email_verified: bool
    joined_at: datetime


class MemberInviteRequest(BaseModel):
    """``POST /orgs/{org_id}/members``. An existing account is added
    directly; a new address gets an account created and an invite email
    carrying set-password + verify-email tokens."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    role: MembershipRole = MembershipRole.MEMBER
    full_name: str | None = Field(default=None, min_length=1, max_length=255)

    @field_validator("email", mode="after")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return normalize_email(v)


class MemberInviteResponse(MemberItem):
    invited_new_user: bool


class MemberRolePatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: MembershipRole
