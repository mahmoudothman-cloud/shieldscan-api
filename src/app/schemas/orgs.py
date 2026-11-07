"""Organization-level read schemas (M11 pre-work).

``OrgSummaryResponse`` is the dashboard's header in one round-trip:
project counts, scan activity, open vulnerabilities by severity, and the
last finished scan with its raw→unique figure. Everything here is
derived from tables that already exist; nothing is denormalised.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class ProjectCounts(BaseModel):
    total: int
    verified: int
    unverified: int


class ScanCounts(BaseModel):
    total: int
    active: int
    completed_30d: int


class OpenVulnerabilityCounts(BaseModel):
    """Vulnerabilities with status ``open`` only — the work still to do."""

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
