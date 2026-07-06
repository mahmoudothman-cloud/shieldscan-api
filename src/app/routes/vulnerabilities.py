"""Vulnerability endpoints (M10.A; Task 10.1; SPEC §6 — all 7 canon routes).

Two routers per the routes/scans.py precedent:
- ``router``            /orgs/{org_id}/vulnerabilities/...       (6 routes)
- ``scan_vulns_router`` /orgs/{org_id}/scans/{scan_id}/vulnerabilities (1 route)

Tenancy via ``require_org_membership()`` (ADR-012 pattern: cross-tenant
collapses to 404). Pagination/sort mirror routes/projects.py (Q3). The PATCH
handler is the FIRST write-site for the scaffolded VulnerabilityHistory table
(Q5) and emits one VULNERABILITY_STATUS_CHANGED audit row per actual
transition (Q8; same-status PATCH is a 200 no-op with no history row, Q4).
``ai_fix_text`` is served only by /fix (Q7; tier-gating forward-pinned to the
billing milestone per Q9). /evidence loads RawFindings by the
``raw_finding_ids`` array (no ORM relationship; M9 ``6c9e270`` pattern).
"""

from __future__ import annotations

from math import ceil
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import AuthIdentity, get_db, require_org_membership
from app.models.raw_findings import EngineCategory, RawFinding, Severity
from app.models.scans import Scan
from app.models.vulnerabilities import (
    Vulnerability,
    VulnerabilityHistory,
    VulnerabilityStatus,
)
from app.schemas.projects import PageNumber, PaginationMeta, PerPage
from app.schemas.vulnerabilities import (
    EvidenceItem,
    FixResponse,
    PaginatedVulnerabilitiesResponse,
    VulnerabilityDetail,
    VulnerabilityHistoryItem,
    VulnerabilityListItem,
    VulnerabilityPatchRequest,
)
from app.services.audit import VulnerabilityAction, audit

router = APIRouter(prefix="/orgs/{org_id}/vulnerabilities", tags=["vulnerabilities"])
scan_vulns_router = APIRouter(
    prefix="/orgs/{org_id}/scans/{scan_id}/vulnerabilities",
    tags=["vulnerabilities"],
)

_SORT_COLUMNS = {
    "severity_score": Vulnerability.severity_score,
    "created_at": Vulnerability.created_at,
    "status": Vulnerability.status,
    "cwe_id": Vulnerability.cwe_id,
}

_EVIDENCE_DESCRIPTION_LIMIT = 500
_EVIDENCE_SNIPPET_LIMIT = 1000

_NOT_FOUND = HTTPException(status_code=404, detail="not_found")


def _parse_csv_enum(raw: str | None, enum_cls, param: str) -> list | None:
    """Parse a CSV multi-value query param into enum members (Q2); 422 on bad."""
    if raw is None:
        return None
    members = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            members.append(enum_cls(token))
        except ValueError:
            raise HTTPException(
                status_code=422, detail=f"invalid {param} value: {token}"
            ) from None
    return members or None


async def _paginated_list(
    db: AsyncSession,
    *,
    org_id: UUID,
    page: int,
    per_page: int,
    sort: str,
    severity: str | None,
    status: str | None,
    engine_category: str | None,
    scan_id: UUID | None = None,
    project_id: UUID | None = None,
) -> PaginatedVulnerabilitiesResponse:
    """Shared query-builder for the per-scan + org-wide lists (Q1/Q2/Q3)."""
    descending = sort.startswith("-")
    sort_key = sort.lstrip("-")
    if sort_key not in _SORT_COLUMNS:
        raise HTTPException(status_code=422, detail=f"invalid sort key: {sort_key}")

    base_where = [Vulnerability.organization_id == org_id]
    severities = _parse_csv_enum(severity, Severity, "severity")
    if severities:
        base_where.append(Vulnerability.severity.in_(severities))
    statuses = _parse_csv_enum(status, VulnerabilityStatus, "status")
    if statuses:
        base_where.append(Vulnerability.status.in_(statuses))
    engines = _parse_csv_enum(engine_category, EngineCategory, "engine_category")
    if engines:
        base_where.append(Vulnerability.engine_category.in_(engines))
    if scan_id is not None:
        base_where.append(Vulnerability.scan_id == scan_id)
    if project_id is not None:
        base_where.append(Vulnerability.project_id == project_id)

    count_stmt = select(func.count(Vulnerability.id))
    for clause in base_where:
        count_stmt = count_stmt.where(clause)
    total = (await db.execute(count_stmt)).scalar_one()

    col = _SORT_COLUMNS[sort_key]
    stmt = select(Vulnerability)
    for clause in base_where:
        stmt = stmt.where(clause)
    stmt = stmt.order_by(col.desc() if descending else col.asc())
    stmt = stmt.offset((page - 1) * per_page).limit(per_page)
    rows = (await db.execute(stmt)).scalars().all()

    total_pages = max(1, ceil(total / per_page)) if total else 0
    return PaginatedVulnerabilitiesResponse(
        items=[VulnerabilityListItem.model_validate(r) for r in rows],
        pagination=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
            has_next=page * per_page < total,
            has_prev=page > 1,
        ),
    )


async def _load_vuln(db: AsyncSession, org_id: UUID, vid: UUID) -> Vulnerability:
    """Org-scoped load; cross-tenant/missing collapses to 404 (ADR-012)."""
    vuln = (
        await db.execute(
            select(Vulnerability).where(
                Vulnerability.id == vid,
                Vulnerability.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if vuln is None:
        raise _NOT_FOUND
    return vuln


# ---------------------------------------------------------------- lists


@scan_vulns_router.get("", response_model=PaginatedVulnerabilitiesResponse)
async def list_scan_vulnerabilities(
    org_id: UUID,
    scan_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    page: PageNumber = 1,
    per_page: PerPage = 20,
    sort: str = Query("-severity_score"),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    engine_category: str | None = Query(None),
):
    # Scan must belong to the org (404 semantics).
    scan = (
        await db.execute(
            select(Scan.id).where(Scan.id == scan_id, Scan.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if scan is None:
        raise _NOT_FOUND
    return await _paginated_list(
        db, org_id=org_id, page=page, per_page=per_page, sort=sort,
        severity=severity, status=status, engine_category=engine_category,
        scan_id=scan_id,
    )


@router.get("", response_model=PaginatedVulnerabilitiesResponse)
async def list_vulnerabilities(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    page: PageNumber = 1,
    per_page: PerPage = 20,
    sort: str = Query("-severity_score"),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    engine_category: str | None = Query(None),
    scan_id: UUID | None = Query(None),
    project_id: UUID | None = Query(None),
):
    return await _paginated_list(
        db, org_id=org_id, page=page, per_page=per_page, sort=sort,
        severity=severity, status=status, engine_category=engine_category,
        scan_id=scan_id, project_id=project_id,
    )


# ---------------------------------------------------------------- detail


@router.get("/{vid}", response_model=VulnerabilityDetail)
async def get_vulnerability(
    org_id: UUID,
    vid: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
):
    vuln = await _load_vuln(db, org_id, vid)
    return VulnerabilityDetail.model_validate(vuln)


# ---------------------------------------------------------------- patch


@router.patch("/{vid}", response_model=VulnerabilityDetail)
async def patch_vulnerability(
    org_id: UUID,
    vid: UUID,
    body: VulnerabilityPatchRequest,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
):
    vuln = await _load_vuln(db, org_id, vid)

    if body.status == vuln.status:
        # Q4: same-status PATCH is a 200 no-op — no history row, no audit.
        return VulnerabilityDetail.model_validate(vuln)

    old_status = vuln.status
    # Q5: FIRST write-site for the scaffolded VulnerabilityHistory table.
    db.add(
        VulnerabilityHistory(
            organization_id=org_id,
            vulnerability_id=vuln.id,
            from_status=old_status,
            to_status=body.status,
            changed_by=identity.user.id if identity.user else None,
            notes=body.notes,
        )
    )
    vuln.status = body.status
    # Q8: one audit row per actual transition.
    await audit(
        db,
        organization_id=org_id,
        actor_id=identity.user.id if identity.user else None,
        action=VulnerabilityAction.VULNERABILITY_STATUS_CHANGED,
        resource_type="vulnerability",
        resource_id=vuln.id,
        details={  # type: ignore[arg-type]
            "from_status": old_status.value,
            "to_status": body.status.value,
        },
    )
    await db.commit()
    return VulnerabilityDetail.model_validate(vuln)


# ---------------------------------------------------------------- evidence


@router.get("/{vid}/evidence", response_model=list[EvidenceItem])
async def get_vulnerability_evidence(
    org_id: UUID,
    vid: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
):
    vuln = await _load_vuln(db, org_id, vid)
    if not vuln.raw_finding_ids:
        return []
    rows = (
        await db.execute(
            select(RawFinding).where(RawFinding.id.in_(vuln.raw_finding_ids))
        )
    ).scalars().all()

    def _trunc(text: str | None, limit: int) -> str | None:
        if text is not None and len(text) > limit:
            return text[:limit] + "…"
        return text

    return [
        EvidenceItem(
            raw_finding_id=r.id,
            tool_name=r.tool_name,
            engine_category=r.engine_category,
            description=_trunc(r.description, _EVIDENCE_DESCRIPTION_LIMIT),
            code_snippet=_trunc(r.code_snippet, _EVIDENCE_SNIPPET_LIMIT),
            code_file=r.code_file,
            code_line=r.code_line,
            target_url=r.target_url,
            parameter=r.parameter,
        )
        for r in rows
    ]


# ---------------------------------------------------------------- fix


@router.get("/{vid}/fix", response_model=FixResponse)
async def get_vulnerability_fix(
    org_id: UUID,
    vid: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
):
    # Q9: ungated at M10.A; tier-enforcement (SPEC §9 — AI fix generation
    # unavailable at Free) forward-pinned to the billing milestone.
    vuln = await _load_vuln(db, org_id, vid)
    return FixResponse(vulnerability_id=vuln.id, ai_fix_text=vuln.ai_fix_text)


# ---------------------------------------------------------------- history


@router.get("/{vid}/history", response_model=list[VulnerabilityHistoryItem])
async def get_vulnerability_history(
    org_id: UUID,
    vid: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
):
    vuln = await _load_vuln(db, org_id, vid)
    rows = (
        await db.execute(
            select(VulnerabilityHistory)
            .where(VulnerabilityHistory.vulnerability_id == vuln.id)
            .order_by(VulnerabilityHistory.created_at.desc())
        )
    ).scalars().all()
    return [VulnerabilityHistoryItem.model_validate(r) for r in rows]
