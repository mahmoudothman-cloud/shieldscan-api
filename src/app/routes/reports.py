"""Report endpoints (M10.B; Task 10.4; SPEC §6 — 5 scan-scoped report routes).

All 5 are GETs on ``/orgs/{org_id}/scans/{scan_id}/report``:
- ``""``          manifest — available formats + PDF-generation status (G4-L12)
- ``/pdf``        presigned-GET URL in JSON (G2-L5/L8; lazy generate-or-reuse)
- ``/sarif``      inline SARIF 2.1.0 (on-demand; never stored per DQ3)
- ``/json``       inline versioned full-fidelity envelope (on-demand)
- ``/executive``  the Scan.executive_summary (G1-L3; read, not regenerated)

Tenancy mirrors routes/vulnerabilities.py — ``require_org_membership()`` +
org-scoped scan load (cross-tenant collapses to 404, ADR-012). Reports are
available only for terminal-with-results scans (COMPLETED/PARTIAL); other
states → 409 (G4-L14). All endpoints ungated; tier-enforcement is forward-
pinned to the billing milestone (M10.A /fix precedent). No audit rows — these
are reads (V-JJH: this codebase audits state changes, not reads).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import AuthIdentity, get_db, require_org_membership
from app.models.reports import Report, ReportFormat
from app.models.scans import Scan, ScanStatus
from app.schemas.reports import (
    ExecutiveReportResponse,
    PdfArtifactInfo,
    PdfReportResponse,
    ReportManifest,
)
from app.services.r2 import generate_presigned_get_url
from app.services.reports.context import build_report_context
from app.services.reports.json_report import generate_json_report
from app.services.reports.pdf import generate_or_get_pdf_report
from app.services.reports.sarif import generate_sarif_report

router = APIRouter(
    prefix="/orgs/{org_id}/scans/{scan_id}/report", tags=["reports"]
)

_PDF_URL_EXPIRY_SECONDS = 3600  # G2-L8: customer download window (vs 600s MobSF)
_AVAILABLE_FORMATS = ["pdf", "sarif", "json", "executive"]
_TERMINAL_WITH_RESULTS = {ScanStatus.COMPLETED, ScanStatus.PARTIAL}


async def _load_terminal_scan(
    db: AsyncSession, org_id: UUID, scan_id: UUID
) -> Scan:
    """Org-scoped scan load; 404 (cross-tenant/missing) then 409 (non-terminal)."""
    scan = (
        await db.execute(
            select(Scan).where(
                Scan.id == scan_id, Scan.organization_id == org_id
            )
        )
    ).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="not_found")
    if scan.status not in _TERMINAL_WITH_RESULTS:
        raise HTTPException(
            status_code=409,
            detail=(
                "scan not yet complete; reports are available after the scan "
                "reaches a terminal state"
            ),
        )
    return scan


@router.get("", response_model=ReportManifest)
async def get_report_manifest(
    org_id: UUID,
    scan_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_terminal_scan(db, org_id, scan_id)
    pdf_row = (
        await db.execute(
            select(Report).where(
                Report.scan_id == scan_id, Report.format == ReportFormat.PDF
            )
        )
    ).scalar_one_or_none()
    pdf_info = (
        PdfArtifactInfo(
            generated=True,
            generated_at=pdf_row.generated_at,
            size_bytes=pdf_row.size_bytes,
        )
        if pdf_row is not None
        else None
    )
    return ReportManifest(
        scan_id=scan.id,
        status=scan.status,
        available_formats=_AVAILABLE_FORMATS,
        pdf=pdf_info,
    )


@router.get("/pdf", response_model=PdfReportResponse)
async def get_report_pdf(
    org_id: UUID,
    scan_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
):
    # Ungated at M10.B; tier-enforcement forward-pinned to billing (M10.A /fix).
    await _load_terminal_scan(db, org_id, scan_id)
    report = await generate_or_get_pdf_report(db=db, scan_id=scan_id)
    url = await generate_presigned_get_url(
        report.r2_key, expiry=_PDF_URL_EXPIRY_SECONDS
    )
    now = datetime.now(timezone.utc)
    return PdfReportResponse(
        format="pdf",
        download_url=url,
        expires_at=now + timedelta(seconds=_PDF_URL_EXPIRY_SECONDS),
        expires_in=_PDF_URL_EXPIRY_SECONDS,
        generated_at=report.generated_at,
        size_bytes=report.size_bytes,
    )


@router.get("/sarif")
async def get_report_sarif(
    org_id: UUID,
    scan_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _load_terminal_scan(db, org_id, scan_id)
    ctx = await build_report_context(db=db, scan_id=scan_id)
    return generate_sarif_report(ctx)


@router.get("/json")
async def get_report_json(
    org_id: UUID,
    scan_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _load_terminal_scan(db, org_id, scan_id)
    ctx = await build_report_context(db=db, scan_id=scan_id)
    return generate_json_report(ctx)


@router.get("/executive", response_model=ExecutiveReportResponse)
async def get_report_executive(
    org_id: UUID,
    scan_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_terminal_scan(db, org_id, scan_id)
    # G1-L3: the summary is eagerly pipeline-produced and lives on Scan.
    return ExecutiveReportResponse(
        scan_id=scan.id,
        executive_summary=scan.executive_summary,
        generated_at=datetime.now(timezone.utc),
    )
