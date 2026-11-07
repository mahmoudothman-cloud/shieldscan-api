"""Scan request/response schemas (Task 4.3).

Request: ``ScanCreateRequest`` with mutual-exclusion validator on
``mobile_upload_id`` + ``scan_type``, public-scan rejection, and
shape-bounds DoS guards on the free-form ``config`` dict.

Response: ``ScanResponse`` embedding the dispatched ``ScanJobSummary``
list per the plan literal `data["jobs"]` shape.

Per-scan-type semantic validation of ``config`` is deferred until
worker-side schemas firm up (see DRIFT-LOG 2026-04-30 Task 4.3 entry).
Shape bounds (size, depth, key count) ship now to prevent obvious DoS
vectors without committing to a per-type schema.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

from app.models.scans import ScanType
from app.schemas.projects import PaginationMeta
from app.services.orchestrator import ScanPriority


# ---------------------------------------------------------------- shape-bounds helpers


_CONFIG_MAX_BYTES: int = 64 * 1024  # 64 KB serialized
_CONFIG_MAX_DEPTH: int = 5
_CONFIG_MAX_KEYS: int = 50  # at the root level


def _max_depth(value: Any, _current: int = 1) -> int:
    """Return the maximum nesting depth of ``value``. A flat dict has
    depth 1; ``{"a": {"b": 1}}`` has depth 2."""
    if isinstance(value, dict):
        if not value:
            return _current
        return max(_max_depth(v, _current + 1) for v in value.values())
    if isinstance(value, list):
        if not value:
            return _current
        return max(_max_depth(v, _current + 1) for v in value)
    return _current


def _validate_config_bounds(cfg: dict) -> dict:
    """DoS-guard validation. Defer per-scan-type semantic schema."""
    serialized = json.dumps(cfg)
    if len(serialized) > _CONFIG_MAX_BYTES:
        raise ValueError("config_too_large")
    if _max_depth(cfg) > _CONFIG_MAX_DEPTH:
        raise ValueError("config_too_deep")
    if isinstance(cfg, dict) and len(cfg) > _CONFIG_MAX_KEYS:
        raise ValueError("config_too_many_keys")
    return cfg


# ---------------------------------------------------------------- request


class ScanCreateRequest(BaseModel):
    """``POST /v1/orgs/{org}/projects/{pid}/scans`` body.

    Mutual exclusion: ``mobile_upload_id`` must be present iff
    ``scan_type == MOBILE``. ``PUBLIC`` is rejected here — public scans
    use a separate endpoint per ADDENDUM-CRITICAL-5 §2.4.

    ``config`` accepts an arbitrary dict but is shape-bounds validated
    (size/depth/keys) to prevent DoS. Per-type semantic schemas are
    deferred to a follow-up task.
    """

    model_config = ConfigDict(extra="forbid")

    scan_type: ScanType
    priority: ScanPriority = ScanPriority.NORMAL
    config: Annotated[
        dict[str, Any],
        Field(default_factory=dict),
        AfterValidator(_validate_config_bounds),
    ]
    recon_enabled: bool = True
    subdomain_limit: int = Field(default=100, ge=1, le=500)
    mobile_upload_id: UUID | None = None

    @model_validator(mode="after")
    def _validate_scan_type_constraints(self):
        if self.scan_type == ScanType.PUBLIC:
            raise ValueError(
                "public scans use a different endpoint "
                "(ADDENDUM-CRITICAL-5 §2.4)"
            )
        if self.scan_type == ScanType.MOBILE and self.mobile_upload_id is None:
            raise ValueError("mobile_upload_id required for MOBILE scan_type")
        if self.scan_type != ScanType.MOBILE and self.mobile_upload_id is not None:
            raise ValueError("mobile_upload_id only allowed for MOBILE scan_type")
        return self


# ---------------------------------------------------------------- response


class ScanJobSummary(BaseModel):
    """One row of the dispatched ScanJob list, returned in 201 response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engine: str
    status: str
    idempotency_key: str


class ScanResponse(BaseModel):
    """201 body. Embeds the dispatched jobs list so the client knows
    what was queued without a follow-up GET (per plan §4.3 example
    `len(data["jobs"]) == 8`)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    organization_id: UUID
    scan_type: str
    status: str
    priority: str
    recon_enabled: bool
    subdomain_limit: int
    mobile_upload_id: UUID | None
    created_at: datetime
    jobs: list[ScanJobSummary]


# ---------------------------------------------------------------- read models (M11 pre-work)


class ScanListItem(BaseModel):
    """One row of ``GET /orgs/{org}/scans`` and the project-scoped list.

    Mid-weight on purpose (mirrors the M10.A list/detail split): enough
    for a scans table — who, what, when, how far, how bad — without the
    per-job breakdown. ``jobs_total``/``jobs_terminal`` give the
    "6 of 7" progress the dashboard shows; ``vulnerability_count`` is
    post-AI-pipeline (0 while the scan is active).
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    project_name: str
    scan_type: str
    status: str
    priority: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    jobs_total: int
    jobs_terminal: int
    vulnerability_count: int
    ai_pipeline_degraded: bool


class PaginatedScansResponse(BaseModel):
    """List envelope mirroring PaginatedProjectsResponse."""

    items: list[ScanListItem]
    pagination: PaginationMeta


class ScanJobDetail(BaseModel):
    """Per-engine row on the scan detail page (progress bars + errors)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engine: str
    target_url: str
    status: str
    finding_count: int
    duration_ms: int | None
    error_message: str | None
    created_at: datetime
    updated_at: datetime


class SeverityCounts(BaseModel):
    """Vulnerabilities by severity for one scan (all statuses)."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanDetailResponse(BaseModel):
    """``GET /orgs/{org}/scans/{scan_id}`` body.

    The header of the scan page: identity, timing, outcome, the job
    breakdown, and severity totals. Findings themselves come from the
    per-scan vulnerabilities list; the narrative from ``/report/executive``.
    ``executive_summary_available`` lets the client decide whether to
    render that tab without a second round-trip.
    """

    id: UUID
    project_id: UUID
    project_name: str
    target_url: str
    organization_id: UUID
    scan_type: str
    status: str
    priority: str
    recon_enabled: bool
    subdomain_limit: int
    mobile_upload_id: UUID | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    ai_pipeline_degraded: bool
    executive_summary_available: bool
    jobs: list[ScanJobDetail]
    raw_finding_count: int
    vulnerability_count: int
    severity_counts: SeverityCounts
