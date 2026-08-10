"""End-to-end smoke tests for the M9.C pipeline stage (ADR-032; Q13).

Exercises fix generation + executive summary through ``pipeline.run()`` (and the
scan-level entry points) with the Anthropic client stubbed. Helpers are imported
as plain functions from the AI conftest; fixtures do not cross sibling conftest
directories (this file is in tests/integration/), so any fixture lives locally
(PY7; M9.B C3 f82c38a fixture-scoping lesson).
"""

from __future__ import annotations

from decimal import Decimal

from sqlalchemy import select

from app.models.raw_findings import EngineCategory
from app.models.vulnerabilities import Vulnerability
from app.services.ai import fix_generation as fixgen_mod
from app.services.ai.cost_tracking import log_ai_call
from app.services.ai.fix_generation import _generate_fixes
from app.services.ai.pipeline import run
from app.services.ai.summary import _generate_executive_summary
from tests.services.ai.conftest import (
    FakeEmbeddings,
    add_raw_finding,
    add_vulnerability,
    install_anthropic,
    install_openai,
    install_qdrant,
    make_anthropic_response,
    seed_org_project_scan,
)

_FIX = "## Explanation\na\n## Fix Code\nb\n## Remediation Steps\n1. c"
_SUMMARY = (
    "## Executive Summary\na\n## Key Findings\nb\n## Risk Posture\nc\n"
    "## Recommended Actions\n1. d"
)


async def _no_sleep(_delay):
    return None


def _distinct_vec(text):
    vec = [0.0] * 1536
    vec[hash(text) % 1536] = 1.0
    return vec


async def _seed_two_findings(db_session, scan, org):
    await add_raw_finding(
        db_session, scan, org,
        title="SQLi via DAST", engine_category=EngineCategory.DAST,
        tool_name="sqlmap", cwe_id="CWE-89", finding_type="sqli",
        parameter="userid", target_url="https://ai.example.com/users",
    )
    await add_raw_finding(
        db_session, scan, org,
        title="XSS via DAST", engine_category=EngineCategory.DAST,
        tool_name="nuclei", cwe_id="CWE-79", finding_type="xss",
        parameter="q", target_url="https://ai.example.com/search",
    )


async def _vulns(db_session, scan_id):
    return list(
        (
            await db_session.execute(
                select(Vulnerability).where(Vulnerability.scan_id == scan_id)
            )
        )
        .scalars()
        .all()
    )


async def test_m9c_smoke_full_pipeline_e2e(db_session, monkeypatch):
    org, _project, scan = await seed_org_project_scan(db_session)
    install_openai(monkeypatch, FakeEmbeddings(vector_for=_distinct_vec))
    install_qdrant(monkeypatch)
    install_anthropic(
        monkeypatch,
        [make_anthropic_response(_FIX), make_anthropic_response(_FIX),
         make_anthropic_response(_SUMMARY)],
    )
    await _seed_two_findings(db_session, scan, org)

    await run(db=db_session, scan_id=scan.id)

    vulns = await _vulns(db_session, scan.id)
    assert len(vulns) == 2
    assert all(v.ai_fix_text == _FIX for v in vulns)
    assert scan.executive_summary == _SUMMARY
    assert scan.ai_pipeline_degraded is False


async def test_m9c_smoke_zero_vuln_defensive(db_session, monkeypatch):
    _org, _project, scan = await seed_org_project_scan(db_session)
    install_anthropic(monkeypatch, [make_anthropic_response(_SUMMARY)])
    # No vulnerabilities → Q13 C.b trivial deterministic summary, no Claude call.
    await _generate_executive_summary(db=db_session, scan_id=scan.id)
    assert scan.executive_summary is not None
    assert "vulnerabilities" in scan.executive_summary.lower()


async def test_m9c_smoke_budget_exhaustion_graceful_degradation(
    db_session, monkeypatch
):
    org, _project, scan = await seed_org_project_scan(db_session)
    install_openai(monkeypatch, FakeEmbeddings(vector_for=_distinct_vec))
    install_qdrant(monkeypatch)
    install_anthropic(monkeypatch, [make_anthropic_response(_FIX)] * 5)
    # Exhaust the FULL_WEB budget ($0.75) up front — above both the fix
    # ceiling (budget - summary reserve = 0.70) and the summary's full-cap
    # gate, so fixes AND the summary degrade to their fallbacks.
    await log_ai_call(
        db=db_session, organization_id=org.id, scan_id=scan.id,
        provider="openai", model="text-embedding-3-small",
        operation_type="embedding", tokens_in=1, tokens_out=None,
        cost_usd=Decimal("0.80"),
    )
    await _seed_two_findings(db_session, scan, org)

    await run(db=db_session, scan_id=scan.id)

    vulns = await _vulns(db_session, scan.id)
    assert all("## Explanation" in v.ai_fix_text for v in vulns)  # fallback template
    assert scan.ai_pipeline_degraded is True


async def test_m9c_smoke_claude_failures_threshold_degraded(db_session, monkeypatch):
    org, _project, scan = await seed_org_project_scan(db_session)
    monkeypatch.setattr(fixgen_mod.asyncio, "sleep", _no_sleep)
    install_openai(monkeypatch, FakeEmbeddings(vector_for=_distinct_vec))
    install_qdrant(monkeypatch)
    install_anthropic(monkeypatch, [RuntimeError("claude down")] * 99)
    await _seed_two_findings(db_session, scan, org)

    await run(db=db_session, scan_id=scan.id)

    assert scan.ai_pipeline_degraded is True


async def test_m9c_smoke_severity_ordered_processing(db_session, monkeypatch):
    org, project, scan = await seed_org_project_scan(db_session)
    client = install_anthropic(
        monkeypatch, [make_anthropic_response(_FIX) for _ in range(3)]
    )
    await add_vulnerability(
        db_session, scan, org, project, title="minor", severity_score=2.0
    )
    await add_vulnerability(
        db_session, scan, org, project, title="severe", severity_score=9.5
    )
    await _generate_fixes(db=db_session, scan_id=scan.id)
    # Q6 C: highest severity_score first.
    first = client.messages.calls[0]["messages"][0]["content"]
    assert "severe" in first


async def test_m9c_smoke_idempotency_re_run(db_session, monkeypatch):
    org, _project, scan = await seed_org_project_scan(db_session)
    install_openai(monkeypatch, FakeEmbeddings(vector_for=_distinct_vec))
    install_qdrant(monkeypatch)
    client = install_anthropic(
        monkeypatch,
        [make_anthropic_response(_FIX), make_anthropic_response(_FIX),
         make_anthropic_response(_SUMMARY)],
    )
    await _seed_two_findings(db_session, scan, org)

    await run(db=db_session, scan_id=scan.id)
    calls_after_first = len(client.messages.calls)

    # Re-invoke the M9.C stages: every vuln already has ai_fix_text + the summary
    # exists → no new Claude calls (Q7 A + Q12 A idempotency).
    await _generate_fixes(db=db_session, scan_id=scan.id)
    await _generate_executive_summary(db=db_session, scan_id=scan.id)
    assert len(client.messages.calls) == calls_after_first
