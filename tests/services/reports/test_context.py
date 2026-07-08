"""ReportContext assembler tests (M10.B C2; G1 data seam)."""

from __future__ import annotations

import pytest

from app.models.raw_findings import Severity
from app.services.reports.context import ScanNotFoundError, build_report_context
from tests.services.ai.conftest import add_raw_finding, add_vulnerability


@pytest.mark.asyncio
async def test_context_gathers_scan_and_severity_ordered_vulns(db_session, report_scan):
    scan, org, project = report_scan
    # Two vulns with distinct severity_score — assembler must order DESC.
    await add_vulnerability(
        db_session, scan, org, project,
        title="Low reflected", severity=Severity.LOW, severity_score=3.1,
    )
    await add_vulnerability(
        db_session, scan, org, project,
        title="Critical SQLi", severity=Severity.CRITICAL, severity_score=9.4,
    )
    await db_session.commit()

    ctx = await build_report_context(db=db_session, scan_id=scan.id)

    assert ctx.scan.id == scan.id
    assert ctx.scan.target_url == "https://report.example.com"  # from Project
    assert ctx.scan.executive_summary.startswith("Two findings")
    assert [v.title for v in ctx.vulnerabilities] == ["Critical SQLi", "Low reflected"]
    assert ctx.vulnerabilities[0].severity_score == 9.4


@pytest.mark.asyncio
async def test_context_loads_evidence_via_raw_finding_ids(db_session, report_scan):
    scan, org, project = report_scan
    rf = await add_raw_finding(db_session, scan, org, tool_name="semgrep")
    await add_vulnerability(
        db_session, scan, org, project,
        title="Has evidence", severity_score=7.0, raw_finding_ids=[rf.id],
    )
    await db_session.commit()

    ctx = await build_report_context(db=db_session, scan_id=scan.id)

    ev = ctx.vulnerabilities[0].evidence
    assert len(ev) == 1
    assert ev[0].raw_finding_id == rf.id
    assert ev[0].tool_name == "semgrep"


@pytest.mark.asyncio
async def test_context_empty_vulns_is_valid(db_session, report_scan):
    scan, _org, _project = report_scan
    ctx = await build_report_context(db=db_session, scan_id=scan.id)
    assert ctx.scan.id == scan.id
    assert ctx.vulnerabilities == []


@pytest.mark.asyncio
async def test_context_missing_scan_raises(db_session, report_scan):
    from uuid import uuid4

    with pytest.raises(ScanNotFoundError):
        await build_report_context(db=db_session, scan_id=uuid4())
