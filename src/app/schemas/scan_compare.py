"""Scan comparison request/response schemas (Task 4.6).

Request: two scan UUIDs, no other fields. ``extra="forbid"`` for the
usual loud-rejection discipline.

Response: lightweight projection of ``Vulnerability`` rows (heavy
fields like description, ai_fix_text, full evidence require a separate
GET via the M10 read-side cluster), plus a summary block carrying
counts and the truncation flag.
"""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ScanComparisonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline_scan_id: UUID
    current_scan_id: UUID


class ComparedFindingSummary(BaseModel):
    """Lightweight projection of Vulnerability for the diff response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    fingerprint: str
    title: str
    severity: str
    finding_type: str
    cwe_id: str | None
    target_url: str | None


class ComparisonSummary(BaseModel):
    """Counts + truncation flag at the top of the response.

    ``truncated=True`` means at least one category hit the
    ``MAX_FINDINGS_PER_CATEGORY`` cap. The route handler also emits
    a logger.warning when this flag fires — operational signal for
    capacity planning (if it fires regularly, raise cap or ship
    pagination earlier than M10).
    """

    new_count: int
    resolved_count: int
    persisting_count: int
    truncated: bool


class ScanComparisonResponse(BaseModel):
    """200 body. The three list fields ALSO appear at top level (per
    plan-literal `data["new_vulnerabilities"]` assertion shape) — the
    ``summary`` envelope is additive."""

    baseline_scan_id: UUID
    current_scan_id: UUID
    summary: ComparisonSummary
    new_vulnerabilities: list[ComparedFindingSummary]
    resolved_vulnerabilities: list[ComparedFindingSummary]
    persisting_vulnerabilities: list[ComparedFindingSummary]
