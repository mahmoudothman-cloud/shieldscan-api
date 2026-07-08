"""JSON report generator tests (M10.B C2; G3 envelope)."""

from __future__ import annotations

import pytest

from app.models.raw_findings import Severity
from app.services.reports.context import build_report_context
from app.services.reports.json_report import (
    JSON_REPORT_SCHEMA_VERSION,
    generate_json_report,
)
from tests.services.ai.conftest import add_vulnerability


@pytest.mark.asyncio
async def test_json_envelope_shape_and_fidelity(db_session, report_scan):
    scan, org, project = report_scan
    await add_vulnerability(
        db_session, scan, org, project,
        title="Critical SQLi", severity=Severity.CRITICAL, severity_score=9.4,
        ai_fix_text="Use parameterized queries.",
    )
    await add_vulnerability(
        db_session, scan, org, project,
        title="Low reflected", severity=Severity.LOW, severity_score=3.1,
    )
    await db_session.commit()

    ctx = await build_report_context(db=db_session, scan_id=scan.id)
    report = generate_json_report(ctx)

    assert report["schema_version"] == JSON_REPORT_SCHEMA_VERSION
    assert report["scan"]["id"] == str(scan.id)
    assert report["scan"]["target_url"] == "https://report.example.com"
    # Full document — no pagination; count matches, all vulns present.
    assert report["vulnerability_count"] == 2
    assert len(report["vulnerabilities"]) == 2
    assert "pagination" not in report
    # ai_fix_text inline.
    first = report["vulnerabilities"][0]
    assert first["title"] == "Critical SQLi"
    assert first["ai_fix_text"] == "Use parameterized queries."
    # Scalars normalised (enum → value).
    assert first["severity"] == "critical"


@pytest.mark.asyncio
async def test_json_empty_vulns(db_session, report_scan):
    scan, _org, _project = report_scan
    ctx = await build_report_context(db=db_session, scan_id=scan.id)
    report = generate_json_report(ctx)
    assert report["vulnerability_count"] == 0
    assert report["vulnerabilities"] == []
    assert report["scan"]["executive_summary"].startswith("Two findings")
