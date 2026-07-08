"""ReportContext assembler — the G1 format-neutral data seam (M10.B; ADR-034).

``build_report_context`` gathers the Scan + severity-ordered Vulnerabilities +
per-vuln evidence ONCE into a plain dataclass structure. All three format
generators (JSON/SARIF/PDF) consume this single gather-point, so a field only
has to be loaded/ordered correctly in one place — preventing per-format drift.

Evidence loads via the ``raw_finding_ids`` array → ``RawFinding`` IN-query
(no ORM relationship; the M9 ``6c9e270`` representative-query precedent, same
as the M10.A /evidence route). Pure read; no storage (DQ3 — JSON/SARIF are
on-demand; only the PDF is persisted, at C3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.projects import Project
from app.models.raw_findings import EngineCategory, RawFinding, Severity
from app.models.scans import Scan, ScanStatus, ScanType
from app.models.vulnerabilities import Vulnerability, VulnerabilityStatus


class ScanNotFoundError(LookupError):
    """Raised when no scan matches the id in the current tenant context."""


@dataclass(frozen=True)
class ReportEvidence:
    """A single RawFinding projection backing a vulnerability."""

    raw_finding_id: UUID
    tool_name: str
    engine_category: EngineCategory
    description: str | None
    code_snippet: str | None
    code_file: str | None
    code_line: int | None
    target_url: str | None
    parameter: str | None


@dataclass(frozen=True)
class ReportVulnerability:
    """A scored/enriched vulnerability with its evidence, for rendering."""

    id: UUID
    title: str
    description: str | None
    severity: Severity
    severity_score: float | None
    cvss_score: float | None
    cwe_id: str | None
    finding_type: str
    engine_category: EngineCategory
    status: VulnerabilityStatus
    corroborated_count: int
    correlation_cluster_id: UUID | None
    target_url: str | None
    parameter: str | None
    code_file: str | None
    code_line: int | None
    mobile_os: str | None
    mobile_permission: str | None
    mobile_component_name: str | None
    ai_fix_text: str | None
    evidence: list[ReportEvidence] = field(default_factory=list)


@dataclass(frozen=True)
class ReportScan:
    """Scan-level header fields for the report."""

    id: UUID
    scan_type: ScanType
    status: ScanStatus
    target_url: str | None
    completed_at: datetime | None
    executive_summary: str | None


@dataclass(frozen=True)
class ReportContext:
    """The format-neutral data seam all generators consume (G1)."""

    scan: ReportScan
    vulnerabilities: list[ReportVulnerability]


async def build_report_context(*, db: AsyncSession, scan_id: UUID) -> ReportContext:
    """Assemble the format-neutral report context for a scan.

    Tenant scoping is enforced by RLS (the session GUC) + the caller's
    org check; this loads by scan_id within that context. Raises
    ``ScanNotFoundError`` if the scan is not visible.
    """
    scan = (
        await db.execute(select(Scan).where(Scan.id == scan_id))
    ).scalar_one_or_none()
    if scan is None:
        raise ScanNotFoundError(str(scan_id))

    # target_url lives on Project (Scan carries only project_id).
    target_url = (
        await db.execute(
            select(Project.target_url).where(Project.id == scan.project_id)
        )
    ).scalar_one_or_none()

    vulns = (
        await db.execute(
            select(Vulnerability)
            .where(Vulnerability.scan_id == scan_id)
            .order_by(Vulnerability.severity_score.desc().nullslast())
        )
    ).scalars().all()

    report_vulns: list[ReportVulnerability] = []
    for v in vulns:
        evidence: list[ReportEvidence] = []
        if v.raw_finding_ids:
            rows = (
                await db.execute(
                    select(RawFinding).where(RawFinding.id.in_(v.raw_finding_ids))
                )
            ).scalars().all()
            evidence = [
                ReportEvidence(
                    raw_finding_id=r.id,
                    tool_name=r.tool_name,
                    engine_category=r.engine_category,
                    description=r.description,
                    code_snippet=r.code_snippet,
                    code_file=r.code_file,
                    code_line=r.code_line,
                    target_url=r.target_url,
                    parameter=r.parameter,
                )
                for r in rows
            ]
        report_vulns.append(
            ReportVulnerability(
                id=v.id,
                title=v.title,
                description=v.description,
                severity=v.severity,
                severity_score=v.severity_score,
                cvss_score=v.cvss_score,
                cwe_id=v.cwe_id,
                finding_type=v.finding_type,
                engine_category=v.engine_category,
                status=v.status,
                corroborated_count=v.corroborated_count,
                correlation_cluster_id=v.correlation_cluster_id,
                target_url=v.target_url,
                parameter=v.parameter,
                code_file=v.code_file,
                code_line=v.code_line,
                mobile_os=v.mobile_os.value if v.mobile_os else None,
                mobile_permission=v.mobile_permission,
                mobile_component_name=v.mobile_component_name,
                ai_fix_text=v.ai_fix_text,
                evidence=evidence,
            )
        )

    return ReportContext(
        scan=ReportScan(
            id=scan.id,
            scan_type=scan.scan_type,
            status=scan.status,
            target_url=target_url,
            completed_at=scan.completed_at,
            executive_summary=scan.executive_summary,
        ),
        vulnerabilities=report_vulns,
    )
