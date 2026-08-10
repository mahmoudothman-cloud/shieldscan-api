"""Unit tests for M9.C executive summary (ADR-032; summary.py).

Covers Q9-Q13: severity-tiered input construction, the deterministic fallback,
and the scan-level entry point (idempotency, budget + Claude failure fallback,
zero-vuln trivial summary).
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

from sqlalchemy import func, select

from app.models.ai import AIAPICall
from app.models.raw_findings import Severity
from app.services.ai import fix_generation as fixgen_mod
from app.services.ai.cost_tracking import log_ai_call
from app.services.ai.summary import (
    _build_corroboration_summary,
    _build_top_findings,
    _build_vuln_breakdown,
    _deterministic_fallback_summary,
    _generate_executive_summary,
)
from tests.services.ai.conftest import (
    add_vulnerability,
    install_anthropic,
    make_anthropic_response,
    seed_org_project_scan,
)

_SUMMARY_TEXT = (
    "## Executive Summary\nx\n## Key Findings\ny\n## Risk Posture\nz\n"
    "## Recommended Actions\n1. w"
)


async def _no_sleep(_delay):
    return None


def _vuln_ns(severity, *, cwe_id="CWE-89", title="v", score=5.0, corroborated=1):
    return SimpleNamespace(
        severity=severity,
        cwe_id=cwe_id,
        title=title,
        target_url="https://ex.com/x",
        code_file=None,
        corroborated_count=corroborated,
        severity_score=score,
    )


# ------------------------------------------------------------ input construction


def test_build_top_findings_severity_tier_selection():
    vulns = (
        [_vuln_ns(Severity.CRITICAL, title="crit")]
        + [_vuln_ns(Severity.HIGH, title="high")]
        + [_vuln_ns(Severity.MEDIUM, title=f"med{i}", score=float(i)) for i in range(7)]
        + [_vuln_ns(Severity.LOW, title="low")]
    )
    out = _build_top_findings(vulns)
    assert "crit" in out
    assert "high" in out
    assert "] low " not in out  # Q10 A.c: LOW skipped
    # top-5 MEDIUM only (scores 6..2 included; scores 0,1 excluded)
    assert "med6" in out and "med2" in out
    assert "med0" not in out and "med1" not in out


def test_build_top_findings_mid_detail_per_finding():
    out = _build_top_findings([_vuln_ns(Severity.HIGH, cwe_id="CWE-79", corroborated=2)])
    assert "high" in out.lower()
    assert "CWE-79" in out
    assert "2 layers" in out


def test_build_vuln_breakdown_severity_and_top_cwe():
    vulns = [
        _vuln_ns(Severity.CRITICAL, cwe_id="CWE-89"),
        _vuln_ns(Severity.CRITICAL, cwe_id="CWE-89"),
        _vuln_ns(Severity.HIGH, cwe_id="CWE-79"),
    ]
    out = _build_vuln_breakdown(vulns)
    assert "Total: 3" in out
    assert "CWE-89 (2)" in out


def test_build_corroboration_summary_aggregate():
    vulns = [
        _vuln_ns(Severity.HIGH, corroborated=2),
        _vuln_ns(Severity.HIGH, corroborated=1),
    ]
    out = _build_corroboration_summary(vulns)
    assert "1 of 2" in out


def test_deterministic_fallback_summary_four_sections():
    out = _deterministic_fallback_summary([_vuln_ns(Severity.CRITICAL)])
    assert "## Executive Summary" in out
    assert "## Key Findings" in out
    assert "## Risk Posture" in out
    assert "## Recommended Actions" in out


# ------------------------------------------------------------ entry point


async def test_generate_executive_summary_success(db_session, monkeypatch):
    org, project, scan = await seed_org_project_scan(db_session)
    install_anthropic(monkeypatch, [make_anthropic_response(_SUMMARY_TEXT)])
    await add_vulnerability(db_session, scan, org, project)

    await _generate_executive_summary(db=db_session, scan_id=scan.id)
    assert scan.executive_summary == _SUMMARY_TEXT
    logged = (
        await db_session.execute(
            select(func.count(AIAPICall.id)).where(
                AIAPICall.scan_id == scan.id,
                AIAPICall.operation_type == "executive_summary",
            )
        )
    ).scalar_one()
    assert logged == 1


async def test_generate_executive_summary_preserve_existing(db_session, monkeypatch):
    org, project, scan = await seed_org_project_scan(db_session)
    scan.executive_summary = "already written"
    await db_session.flush()
    install_anthropic(monkeypatch, [make_anthropic_response(_SUMMARY_TEXT)])
    await add_vulnerability(db_session, scan, org, project)

    await _generate_executive_summary(db=db_session, scan_id=scan.id)
    assert scan.executive_summary == "already written"  # Q12 A


async def test_generate_executive_summary_zero_vuln_trivial(db_session, monkeypatch):
    _org, _project, scan = await seed_org_project_scan(db_session)
    install_anthropic(monkeypatch, [make_anthropic_response(_SUMMARY_TEXT)])
    await _generate_executive_summary(db=db_session, scan_id=scan.id)
    assert scan.executive_summary is not None
    assert "vulnerabilities" in scan.executive_summary.lower()


async def test_generate_executive_summary_budget_exceeded_fallback(
    db_session, monkeypatch
):
    org, project, scan = await seed_org_project_scan(db_session)
    await log_ai_call(
        db=db_session,
        organization_id=org.id,
        scan_id=scan.id,
        provider="openai",
        model="text-embedding-3-small",
        operation_type="embedding",
        tokens_in=1,
        tokens_out=None,
        cost_usd=Decimal("0.80"),  # exhausts FULL_WEB $0.75 (summary gates on full cap)
    )
    install_anthropic(monkeypatch, [make_anthropic_response(_SUMMARY_TEXT)])
    await add_vulnerability(db_session, scan, org, project)

    await _generate_executive_summary(db=db_session, scan_id=scan.id)
    assert scan.executive_summary is not None
    assert "## Executive Summary" in scan.executive_summary
    assert scan.ai_pipeline_degraded is True


async def test_generate_executive_summary_claude_error_fallback(db_session, monkeypatch):
    org, project, scan = await seed_org_project_scan(db_session)
    monkeypatch.setattr(fixgen_mod.asyncio, "sleep", _no_sleep)
    install_anthropic(monkeypatch, [RuntimeError("x")] * 3)
    await add_vulnerability(db_session, scan, org, project)

    await _generate_executive_summary(db=db_session, scan_id=scan.id)
    assert "## Executive Summary" in scan.executive_summary
    assert scan.ai_pipeline_degraded is True
