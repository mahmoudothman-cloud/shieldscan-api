"""PDF report service tests (M10.B C3; G2 generate-or-reuse + G5 content)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select

from app.models.raw_findings import Severity
from app.models.reports import Report, ReportFormat
from app.services.reports import pdf as pdf_module
from app.services.reports.context import build_report_context
from app.services.reports.pdf import generate_or_get_pdf_report, render_report_html
from tests.services.ai.conftest import add_vulnerability


@pytest.fixture
def stub_r2(monkeypatch):
    """Record put_object calls (key, content, content_type); no network."""
    calls: list[tuple[str, bytes, str]] = []

    async def _fake_put_object(key, content, content_type):
        calls.append((key, content, content_type))

    monkeypatch.setattr(pdf_module, "put_object", _fake_put_object)
    return calls


async def _reports_count(db, scan_id):
    return (
        await db.execute(
            select(func.count(Report.id)).where(Report.scan_id == scan_id)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_generate_produces_pdf_and_writes_row(db_session, report_scan, stub_r2):
    scan, org, project = report_scan
    await add_vulnerability(
        db_session, scan, org, project,
        title="Critical SQLi", severity=Severity.CRITICAL, severity_score=9.4,
        ai_fix_text="Use parameterized queries.",
    )
    await db_session.commit()

    report = await generate_or_get_pdf_report(db=db_session, scan_id=scan.id)

    assert report.format == ReportFormat.PDF
    assert report.r2_key == f"reports/{scan.id}/{report.id}.pdf"
    assert report.size_bytes > 0
    # One R2 write with real PDF bytes.
    assert len(stub_r2) == 1
    key, content, content_type = stub_r2[0]
    assert content_type == "application/pdf"
    assert content[:5] == b"%PDF-"
    # Row persisted.
    assert await _reports_count(db_session, scan.id) == 1


@pytest.mark.asyncio
async def test_idempotency_reuses_row(db_session, report_scan, stub_r2):
    scan, org, project = report_scan
    await add_vulnerability(
        db_session, scan, org, project, title="V", severity_score=5.0
    )
    await db_session.commit()

    first = await generate_or_get_pdf_report(db=db_session, scan_id=scan.id)
    second = await generate_or_get_pdf_report(db=db_session, scan_id=scan.id)

    # Reused — same row, no second render/upload, single reports row.
    assert second.id == first.id
    assert second.r2_key == first.r2_key
    assert len(stub_r2) == 1
    assert await _reports_count(db_session, scan.id) == 1


@pytest.mark.asyncio
async def test_empty_vulns_still_valid_pdf(db_session, report_scan, stub_r2):
    scan, _org, _project = report_scan
    report = await generate_or_get_pdf_report(db=db_session, scan_id=scan.id)
    assert report.size_bytes > 0
    assert stub_r2[0][1][:5] == b"%PDF-"
    assert await _reports_count(db_session, scan.id) == 1


@pytest.mark.asyncio
async def test_render_html_content_sanity(db_session, report_scan):
    scan, org, project = report_scan
    await add_vulnerability(
        db_session, scan, org, project,
        title="Reflected XSS in search", severity=Severity.HIGH, severity_score=7.2,
        ai_fix_text="Encode output; apply a strict CSP.",
    )
    await db_session.commit()

    ctx = await build_report_context(db=db_session, scan_id=scan.id)
    html = render_report_html(ctx, generated_at=datetime.now(timezone.utc))

    # Pre-WeasyPrint string assertions (avoid brittle PDF-bytes parsing).
    assert "Two findings" in html  # executive_summary verbatim
    assert "Reflected XSS in search" in html  # vuln title
    assert "Encode output; apply a strict CSP." in html  # ai_fix_text present
    assert "Executive Summary" in html and "Findings Overview" in html
