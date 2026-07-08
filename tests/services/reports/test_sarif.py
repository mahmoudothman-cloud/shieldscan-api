"""SARIF 2.1.0 generator tests (M10.B C2; G3 provable conformance)."""

from __future__ import annotations

import jsonschema
import pytest

from app.models.raw_findings import Severity
from app.services.reports.context import build_report_context
from app.services.reports.sarif import (
    SARIF_VERSION,
    _sarif_schema,
    generate_sarif_report,
)
from tests.services.ai.conftest import add_vulnerability


@pytest.mark.asyncio
async def test_sarif_validates_against_bundled_schema(db_session, report_scan):
    scan, org, project = report_scan
    await add_vulnerability(
        db_session, scan, org, project,
        title="SQLi in login", severity=Severity.CRITICAL, severity_score=9.4,
        cwe_id="CWE-89", target_url="https://report.example.com/login",
    )
    await add_vulnerability(
        db_session, scan, org, project,
        title="Verbose error", severity=Severity.LOW, severity_score=2.0,
        cwe_id="CWE-209", code_file="app/views.py", code_line=42, target_url=None,
    )
    await db_session.commit()

    ctx = await build_report_context(db=db_session, scan_id=scan.id)
    doc = generate_sarif_report(ctx)

    # Self-validation already ran inside the generator; assert here too.
    jsonschema.validate(instance=doc, schema=_sarif_schema())
    assert doc["version"] == SARIF_VERSION
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "ShieldScan"
    assert len(run["results"]) == 2


@pytest.mark.asyncio
async def test_sarif_severity_to_level_mapping(db_session, report_scan):
    scan, org, project = report_scan
    await add_vulnerability(
        db_session, scan, org, project,
        title="crit", severity=Severity.CRITICAL, severity_score=9.0, cwe_id="CWE-1",
    )
    await add_vulnerability(
        db_session, scan, org, project,
        title="med", severity=Severity.MEDIUM, severity_score=5.0, cwe_id="CWE-2",
    )
    await add_vulnerability(
        db_session, scan, org, project,
        title="info", severity=Severity.INFO, severity_score=1.0, cwe_id="CWE-3",
    )
    await db_session.commit()

    ctx = await build_report_context(db=db_session, scan_id=scan.id)
    results = generate_sarif_report(ctx)["runs"][0]["results"]
    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels["CWE-1"] == "error"
    assert levels["CWE-2"] == "warning"
    assert levels["CWE-3"] == "note"


@pytest.mark.asyncio
async def test_sarif_locations_and_ruleid_fallback(db_session, report_scan):
    scan, org, project = report_scan
    # No cwe_id → ruleId falls back to finding_type; code_file+line → location.
    await add_vulnerability(
        db_session, scan, org, project,
        title="hardcoded secret", severity=Severity.HIGH, severity_score=7.5,
        cwe_id=None, finding_type="secret", target_url=None,
        code_file="config.py", code_line=10,
    )
    await db_session.commit()

    ctx = await build_report_context(db=db_session, scan_id=scan.id)
    result = generate_sarif_report(ctx)["runs"][0]["results"][0]
    assert result["ruleId"] == "secret"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "config.py"
    assert loc["region"]["startLine"] == 10


@pytest.mark.asyncio
async def test_sarif_empty_vulns_is_valid(db_session, report_scan):
    scan, _org, _project = report_scan
    ctx = await build_report_context(db=db_session, scan_id=scan.id)
    doc = generate_sarif_report(ctx)
    jsonschema.validate(instance=doc, schema=_sarif_schema())
    assert doc["runs"][0]["results"] == []
