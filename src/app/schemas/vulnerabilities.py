"""Vulnerability endpoint schemas (M10.A; Task 10.1; SPEC §6).

Response shapes per the M10.A Q7 lock: list items are mid-weight, detail is
full — but ``ai_fix_text`` is EXCLUSIVE to the /fix endpoint (clean
tier-gateable surface per SPEC §9). Evidence items project RawFinding fields
(``tool_name`` legitimately appears only here per Q2). Envelope mirrors the
projects.py convention (items + PaginationMeta).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.raw_findings import EngineCategory, MobileOS, Severity
from app.models.vulnerabilities import VulnerabilityStatus
from app.schemas.projects import PaginationMeta


class VulnerabilityListItem(BaseModel):
    """Mid-weight list projection (Q7)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    title: str
    severity: Severity
    severity_score: float | None
    status: VulnerabilityStatus
    cwe_id: str | None
    engine_category: EngineCategory
    corroborated_count: int
    scan_id: UUID
    created_at: datetime
    # Cross-scan identity (M11)
    first_seen_at: datetime | None = None
    previous_id: UUID | None = None
    superseded_by_id: UUID | None = None
    regression: bool = False


class VulnerabilityDetail(VulnerabilityListItem):
    """Full detail projection (Q7). ai_fix_text intentionally absent — /fix."""

    description: str | None
    target_url: str | None
    code_file: str | None
    code_line: int | None
    parameter: str | None
    mobile_os: MobileOS | None
    mobile_permission: str | None
    mobile_component_name: str | None
    correlation_cluster_id: UUID | None
    updated_at: datetime


class VulnerabilityPatchRequest(BaseModel):
    """PATCH body (Q6): status required, notes optional."""

    status: VulnerabilityStatus
    notes: str | None = Field(default=None, max_length=2000)


class VulnerabilityHistoryItem(BaseModel):
    """Status-transition history row (Q5/Q7)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    from_status: VulnerabilityStatus
    to_status: VulnerabilityStatus
    changed_by: UUID | None
    notes: str | None
    created_at: datetime


class EvidenceItem(BaseModel):
    """RawFinding projection for /evidence (Q7; tool_name lives here per Q2)."""

    raw_finding_id: UUID
    tool_name: str
    engine_category: EngineCategory
    description: str | None
    code_snippet: str | None
    code_file: str | None
    code_line: int | None
    target_url: str | None
    parameter: str | None


class FixResponse(BaseModel):
    """/fix response (Q7/Q9): the ai_fix_text surface. ``is_fallback`` tells
    the client the text is the deterministic template, not model output,
    so the UI can label it instead of presenting it as a tailored fix."""

    vulnerability_id: UUID
    ai_fix_text: str | None
    is_fallback: bool = False


class PaginatedVulnerabilitiesResponse(BaseModel):
    """List envelope mirroring PaginatedProjectsResponse (Q3)."""

    items: list[VulnerabilityListItem]
    pagination: PaginationMeta
