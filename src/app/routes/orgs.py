"""Organization-level read endpoints (M11 pre-work).

    GET /v1/orgs/{org_id}/summary   200 OrgSummaryResponse

The dashboard header in one call. Pure aggregation over projects,
scans, raw_findings and vulnerabilities; no state mutation and no
audit rows (reads are not audited in this codebase).

Auth: ``require_org_membership()`` — JWT or API key, any member. A
non-member asking for another tenant's summary gets 404 from the
dependency (existence-hiding), never an empty summary.

Org settings (GET/PATCH) and membership management are the next
additions to this router; they carry writes and will audit.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import AuthIdentity, get_db, require_org_membership
from app.models.projects import Project
from app.models.raw_findings import RawFinding, Severity
from app.models.scans import Scan, ScanStatus
from app.models.vulnerabilities import Vulnerability, VulnerabilityStatus
from app.schemas.orgs import (
    LastCompletedScan,
    OpenVulnerabilityCounts,
    OrgSummaryResponse,
    ProjectCounts,
    ScanCounts,
)

router = APIRouter(prefix="/orgs/{org_id}", tags=["orgs"])

_ACTIVE: tuple[ScanStatus, ...] = (
    ScanStatus.QUEUED,
    ScanStatus.RECONNING,
    ScanStatus.RUNNING,
    ScanStatus.ANALYZING,
)
_FINISHED: tuple[ScanStatus, ...] = (ScanStatus.COMPLETED, ScanStatus.PARTIAL)


@router.get("/summary", response_model=OrgSummaryResponse)
async def get_org_summary(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
) -> OrgSummaryResponse:
    # Projects: live (non-archived) only; verified split drives the
    # "needs you" card.
    proj_row = (
        await db.execute(
            select(
                func.count(Project.id),
                func.count(Project.id).filter(Project.domain_verified.is_(True)),
            ).where(
                Project.organization_id == org_id,
                Project.archived_at.is_(None),
            )
        )
    ).one()
    projects_total, projects_verified = int(proj_row[0]), int(proj_row[1])

    # Scans: lifetime total, currently active, finished in the last 30 days.
    since = datetime.now(timezone.utc) - timedelta(days=30)
    scan_row = (
        await db.execute(
            select(
                func.count(Scan.id),
                func.count(Scan.id).filter(Scan.status.in_(_ACTIVE)),
                func.count(Scan.id).filter(
                    Scan.status.in_(_FINISHED), Scan.completed_at >= since
                ),
            ).where(Scan.organization_id == org_id)
        )
    ).one()

    # Open vulnerabilities by severity + corroborated (seen by ≥2 engines).
    sev_rows = (
        await db.execute(
            select(
                Vulnerability.severity,
                func.count(Vulnerability.id),
                func.count(Vulnerability.id).filter(
                    Vulnerability.corroborated_count >= 2
                ),
            )
            .where(
                Vulnerability.organization_id == org_id,
                Vulnerability.status == VulnerabilityStatus.OPEN,
            )
            .group_by(Vulnerability.severity)
        )
    ).all()
    by_sev = {sev.value: int(n) for sev, n, _ in sev_rows}
    open_counts = OpenVulnerabilityCounts(
        **{s.value: by_sev.get(s.value, 0) for s in Severity},
        total=sum(by_sev.values()),
        corroborated=sum(int(c) for _, _, c in sev_rows),
    )

    # Last finished scan with its raw→unique figure (the "noise removed" tile).
    last_row = (
        await db.execute(
            select(Scan, Project.name)
            .join(Project, Project.id == Scan.project_id)
            .where(Scan.organization_id == org_id, Scan.status.in_(_FINISHED))
            .order_by(Scan.completed_at.desc().nulls_last(), Scan.created_at.desc())
            .limit(1)
        )
    ).one_or_none()
    last: LastCompletedScan | None = None
    if last_row is not None:
        last_scan, project_name = last_row
        raw_n = (
            await db.execute(
                select(func.count(RawFinding.id)).where(
                    RawFinding.scan_id == last_scan.id
                )
            )
        ).scalar_one()
        vuln_n = (
            await db.execute(
                select(func.count(Vulnerability.id)).where(
                    Vulnerability.scan_id == last_scan.id
                )
            )
        ).scalar_one()
        last = LastCompletedScan(
            id=last_scan.id,
            project_id=last_scan.project_id,
            project_name=project_name,
            status=last_scan.status.value,
            completed_at=last_scan.completed_at,
            raw_finding_count=int(raw_n),
            vulnerability_count=int(vuln_n),
        )

    return OrgSummaryResponse(
        organization_id=org_id,
        projects=ProjectCounts(
            total=projects_total,
            verified=projects_verified,
            unverified=projects_total - projects_verified,
        ),
        scans=ScanCounts(
            total=int(scan_row[0]),
            active=int(scan_row[1]),
            completed_30d=int(scan_row[2]),
        ),
        open_vulnerabilities=open_counts,
        last_completed_scan=last,
    )
