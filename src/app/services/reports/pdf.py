"""PDF report service (M10.B; ADR-034 G2/G5; Task 10.2).

Lazy generate-or-reuse in a service method (routes stay thin — C4):
  1. If a Report row already exists for (scan_id, PDF), reuse it — no regen.
     (Benign concurrent-render race accepted at pre-launch; a (scan_id, format)
     unique-constraint is forward-pinned.)
  2. Assemble the ReportContext (the C2 G1 seam).
  3. Render report.html via Jinja2, style with report.css.
  4. WeasyPrint HTML(string=...).write_pdf() → bytes.
  5. Store in R2 via put_object (reports/{scan_id}/{report_id}.pdf).
  6. Write the Report row — Python api is the sole writer per ADR-013.

The PDF is the ONLY persisted format (DQ3); JSON/SARIF are on-demand (C2).
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from weasyprint import CSS, HTML

from app.models.reports import Report, ReportFormat
from app.models.scans import Scan
from app.services.r2 import put_object
from app.services.reports.context import ReportContext, build_report_context

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_CSS_PATH = _TEMPLATES_DIR / "report.css"

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)

_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _severity_counts(ctx: ReportContext) -> dict[str, int]:
    counts = Counter(v.severity.value for v in ctx.vulnerabilities)
    result = {sev: counts.get(sev, 0) for sev in _SEVERITIES}
    result["total"] = len(ctx.vulnerabilities)
    return result


def render_report_html(ctx: ReportContext, *, generated_at: datetime) -> str:
    """Render the report template to an HTML string (testable pre-WeasyPrint)."""
    template = _env.get_template("report.html")
    return template.render(
        ctx=ctx,
        severity_counts=_severity_counts(ctx),
        generated_at=generated_at,
        mobile_present=any(v.mobile_os for v in ctx.vulnerabilities),
    )


async def generate_or_get_pdf_report(*, db: AsyncSession, scan_id: UUID) -> Report:
    """Return the PDF Report row for a scan — reusing an existing one, or
    generating + storing + recording a new one (G2 lazy generate-or-reuse)."""
    existing = (
        await db.execute(
            select(Report).where(
                Report.scan_id == scan_id,
                Report.format == ReportFormat.PDF,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    ctx = await build_report_context(db=db, scan_id=scan_id)
    org_id = (
        await db.execute(
            select(Scan.organization_id).where(Scan.id == scan_id)
        )
    ).scalar_one()

    generated_at = datetime.now(timezone.utc)
    html = render_report_html(ctx, generated_at=generated_at)
    pdf_bytes = HTML(string=html).write_pdf(
        stylesheets=[CSS(filename=str(_CSS_PATH))]
    )

    report_id = uuid4()
    key = f"reports/{scan_id}/{report_id}.pdf"
    await put_object(key, pdf_bytes, "application/pdf")

    report = Report(
        id=report_id,
        organization_id=org_id,
        scan_id=scan_id,
        format=ReportFormat.PDF,
        r2_key=key,
        size_bytes=len(pdf_bytes),
        generated_at=generated_at,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report
