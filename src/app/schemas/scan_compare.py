"""Scan comparison request/response schemas (Task 4.6; reworked on
identity links 2026-11-13 — see services/scan_compare.py).

``baseline_scan_id`` is optional: omitted, the API picks the project's
previous finished scan of the same type (the identity pass's own
baseline). The response names which baseline it used.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ScanComparisonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_scan_id: UUID
    baseline_scan_id: UUID | None = None


class ComparedFindingSummary(BaseModel):
    """Lightweight projection of Vulnerability for the diff response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_id: UUID
    title: str
    severity: str
    status: str
    finding_type: str
    cwe_id: str | None
    target_url: str | None
    first_seen_at: datetime | None
    resolved_at: datetime | None
    regression: bool


class ComparedScan(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_type: str
    status: str
    created_at: datetime
    completed_at: datetime | None


class ComparisonSummary(BaseModel):
    new: int
    regressions: int
    persisting: int
    fixed: int
    not_covered: int
    triaged: int
    truncated: bool
    # False when the current scan's scope (depth, template tags) is
    # narrower than the baseline's: a large not_covered bucket is then
    # expected, and nothing in it was auto-resolved.
    scope_covered: bool


class ScanComparisonResponse(BaseModel):
    baseline: ComparedScan
    current: ComparedScan
    summary: ComparisonSummary
    new: list[ComparedFindingSummary]
    regressions: list[ComparedFindingSummary]
    persisting: list[ComparedFindingSummary]
    fixed: list[ComparedFindingSummary]
    not_covered: list[ComparedFindingSummary]
