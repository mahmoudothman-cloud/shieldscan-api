"""Unit tests for M9.C fix generation (ADR-032; fix_generation.py).

Covers Q1-Q8 + Gate-1 Path A: engine-dispatch context builders, evidence
formatting, the deterministic fallback, the retry helper, and the per-vuln +
scan-level orchestrators (cost-tracking, idempotency, defensive skip, threshold).
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from app.models.ai import AIAPICall
from app.models.raw_findings import EngineCategory, MobileOS, Severity
from app.services.ai.cost_tracking import log_ai_call
from app.services.ai.fix_generation import (
    DEGRADED_THRESHOLD_COUNT,
    _build_target_context,
    _compute_cost_from_usage,
    _call_claude_with_retry,
    _fallback_fix_template,
    _format_evidence,
    _generate_fixes,
    generate_fix,
)
from app.services.ai import fix_generation as fixgen_mod
from tests.services.ai.conftest import (
    add_vulnerability,
    install_anthropic,
    make_anthropic_response,
    seed_org_project_scan,
)

_FIX_TEXT = "## Explanation\nx\n## Fix Code\ny\n## Remediation Steps\n1. z"


async def _no_sleep(_delay):
    return None


# ------------------------------------------------------------ context dispatch


def _vuln_ns(**overrides):
    base = dict(
        engine_category=EngineCategory.DAST,
        corroborated_count=1,
        target_url="https://ex.com/a",
        parameter="q",
        code_file="app.py",
        code_line=10,
        mobile_os=None,
        mobile_component_name=None,
        mobile_permission=None,
        severity=Severity.HIGH,
        cwe_id="CWE-79",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_build_target_context_dispatches_mobile():
    vuln = _vuln_ns(
        engine_category=EngineCategory.MOBILE,
        mobile_os=MobileOS.ANDROID,
        mobile_component_name="LoginActivity",
        mobile_permission="INTERNET",
    )
    ctx = _build_target_context(vuln, None)
    assert "android" in ctx.lower()
    assert "LoginActivity" in ctx
    assert "INTERNET" in ctx


def test_build_target_context_dispatches_sast():
    vuln = _vuln_ns(engine_category=EngineCategory.SAST)
    rf = SimpleNamespace(code_snippet="exec(user_input)")
    ctx = _build_target_context(vuln, rf)
    assert "app.py" in ctx
    assert "exec(user_input)" in ctx


def test_build_target_context_dispatches_dast():
    vuln = _vuln_ns(engine_category=EngineCategory.DAST)
    ctx = _build_target_context(vuln, None)
    assert "https://ex.com/a" in ctx
    assert "q" in ctx


def test_build_target_context_dispatches_generic():
    vuln = _vuln_ns(engine_category=EngineCategory.SCA)
    ctx = _build_target_context(vuln, None)
    assert "sca" in ctx.lower()


def test_build_target_context_mobile_null_fields_n_a():
    vuln = _vuln_ns(
        engine_category=EngineCategory.MOBILE,
        mobile_os=None,
        mobile_component_name=None,
        mobile_permission=None,
        code_file=None,
        code_line=None,
    )
    ctx = _build_target_context(vuln, None)
    assert "N/A" in ctx


def test_build_target_context_appends_corroboration():
    vuln = _vuln_ns(engine_category=EngineCategory.DAST, corroborated_count=3)
    ctx = _build_target_context(vuln, None)
    assert "3" in ctx and "corroborat" in ctx.lower()


# ------------------------------------------------------------ evidence + fallback


def test_format_evidence_truncates_description_and_snippet():
    rf = SimpleNamespace(
        tool_name="semgrep",
        engine_category=EngineCategory.SAST,
        description="d" * 900,
        code_snippet="s" * 1500,
    )
    out = _format_evidence(_vuln_ns(), rf)
    assert "semgrep" in out
    assert "…" in out
    # description capped at 500, snippet at 1000 → the full inputs are absent.
    assert "d" * 900 not in out
    assert "s" * 1500 not in out
    assert "d" * 500 in out
    assert "s" * 1000 in out


def test_format_evidence_null_raw_finding():
    out = _format_evidence(_vuln_ns(), None)
    assert "N/A" in out


def test_fallback_fix_template_has_three_sections():
    out = _fallback_fix_template(_vuln_ns(severity=Severity.CRITICAL, cwe_id="CWE-89"))
    assert "## Explanation" in out
    assert "## Fix Code" in out
    assert "## Remediation Steps" in out
    assert "critical" in out.lower()


def test_compute_cost_from_usage_sonnet_pricing():
    # 1M input + 1M output = $3 + $15 = $18
    assert _compute_cost_from_usage(1_000_000, 1_000_000) == Decimal("18")


# ------------------------------------------------------------ retry helper


async def test_call_claude_with_retry_success_first_attempt(monkeypatch):
    install_anthropic(monkeypatch, [make_anthropic_response(_FIX_TEXT)])
    msg = await _call_claude_with_retry(
        system="s", user_prompt="u", max_tokens=100
    )
    assert msg.content[0].text == _FIX_TEXT


async def test_call_claude_with_retry_success_third_attempt(monkeypatch):
    monkeypatch.setattr(fixgen_mod.asyncio, "sleep", _no_sleep)
    client = install_anthropic(
        monkeypatch,
        [RuntimeError("boom"), RuntimeError("boom"), make_anthropic_response(_FIX_TEXT)],
    )
    msg = await _call_claude_with_retry(system="s", user_prompt="u", max_tokens=100)
    assert msg.content[0].text == _FIX_TEXT
    assert len(client.messages.calls) == 3


async def test_call_claude_with_retry_exhausted_raises_last(monkeypatch):
    monkeypatch.setattr(fixgen_mod.asyncio, "sleep", _no_sleep)
    install_anthropic(
        monkeypatch, [RuntimeError("e1"), RuntimeError("e2"), RuntimeError("e3")]
    )
    with pytest.raises(RuntimeError, match="e3"):
        await _call_claude_with_retry(system="s", user_prompt="u", max_tokens=100)



# ------------------------------------------------------------ generate_fix


async def test_generate_fix_success_logs_ai_call(db_session, monkeypatch):
    org, project, scan = await seed_org_project_scan(db_session)
    install_anthropic(monkeypatch, [make_anthropic_response(_FIX_TEXT)])
    vuln = await add_vulnerability(db_session, scan, org, project)

    text = await generate_fix(
        db=db_session, vulnerability=vuln, raw_finding=None, scan=scan
    )
    assert text == _FIX_TEXT
    assert vuln.ai_fix_text == _FIX_TEXT
    logged = (
        await db_session.execute(
            select(func.count(AIAPICall.id)).where(
                AIAPICall.scan_id == scan.id,
                AIAPICall.operation_type == "fix_generation",
            )
        )
    ).scalar_one()
    assert logged == 1


async def test_generate_fix_budget_exceeded_falls_back(db_session, monkeypatch):
    org, project, scan = await seed_org_project_scan(db_session)
    # Pre-consume past the FULL_WEB fix ceiling (budget 0.75 - summary reserve
    # 0.05 = 0.70) so the next fix call is refused.
    await log_ai_call(
        db=db_session,
        organization_id=org.id,
        scan_id=scan.id,
        provider="openai",
        model="text-embedding-3-small",
        operation_type="embedding",
        tokens_in=1,
        tokens_out=None,
        cost_usd=Decimal("0.80"),
    )
    install_anthropic(monkeypatch, [make_anthropic_response(_FIX_TEXT)])
    vuln = await add_vulnerability(db_session, scan, org, project)

    text = await generate_fix(
        db=db_session, vulnerability=vuln, raw_finding=None, scan=scan
    )
    assert "## Explanation" in text  # fallback template
    assert vuln.ai_fix_text == text
    assert scan.ai_pipeline_degraded is True


async def test_generate_fix_retry_exhausted_falls_back(db_session, monkeypatch):
    org, project, scan = await seed_org_project_scan(db_session)
    monkeypatch.setattr(fixgen_mod.asyncio, "sleep", _no_sleep)
    install_anthropic(monkeypatch, [RuntimeError("x")] * 3)
    vuln = await add_vulnerability(db_session, scan, org, project)

    text = await generate_fix(
        db=db_session, vulnerability=vuln, raw_finding=None, scan=scan
    )
    assert "## Explanation" in text
    assert scan.ai_pipeline_degraded is True
    # failure marker logged (cost_usd=0)
    row = (
        await db_session.execute(
            select(AIAPICall).where(
                AIAPICall.scan_id == scan.id,
                AIAPICall.operation_type == "fix_generation",
            )
        )
    ).scalar_one()
    assert row.cost_usd == Decimal("0")


# ------------------------------------------------------------ _generate_fixes


async def test_generate_fixes_empty_defensive_skip(db_session, monkeypatch):
    _org, _project, scan = await seed_org_project_scan(db_session)
    install_anthropic(monkeypatch, [make_anthropic_response(_FIX_TEXT)])
    await _generate_fixes(db=db_session, scan_id=scan.id)  # no raise, no vulns
    assert scan.ai_pipeline_degraded is False


async def test_generate_fixes_preserve_existing_idempotent(db_session, monkeypatch):
    org, project, scan = await seed_org_project_scan(db_session)
    install_anthropic(monkeypatch, [make_anthropic_response(_FIX_TEXT)])
    vuln = await add_vulnerability(
        db_session, scan, org, project, ai_fix_text="already done"
    )
    await _generate_fixes(db=db_session, scan_id=scan.id)
    assert vuln.ai_fix_text == "already done"  # Q7 A skip


async def test_generate_fixes_severity_ordered(db_session, monkeypatch):
    org, project, scan = await seed_org_project_scan(db_session)
    client = install_anthropic(
        monkeypatch, [make_anthropic_response(_FIX_TEXT) for _ in range(3)]
    )
    await add_vulnerability(
        db_session, scan, org, project, title="low", severity_score=2.0
    )
    await add_vulnerability(
        db_session, scan, org, project, title="high", severity_score=9.0
    )
    await add_vulnerability(
        db_session, scan, org, project, title="mid", severity_score=5.0
    )
    await _generate_fixes(db=db_session, scan_id=scan.id)
    # Q6 C: highest severity_score processed first.
    first_prompt = client.messages.calls[0]["messages"][0]["content"]
    assert "high" in first_prompt


async def test_generate_fixes_threshold_degraded_count(db_session, monkeypatch):
    org, project, scan = await seed_org_project_scan(db_session)
    monkeypatch.setattr(fixgen_mod.asyncio, "sleep", _no_sleep)
    # Every Claude call fails → each vuln falls back (Q4 + Q8 B.b).
    install_anthropic(monkeypatch, [RuntimeError("x")] * 99)
    for i in range(DEGRADED_THRESHOLD_COUNT):
        await add_vulnerability(
            db_session, scan, org, project, title=f"v{i}", severity_score=float(i)
        )
    await _generate_fixes(db=db_session, scan_id=scan.id)
    assert scan.ai_pipeline_degraded is True


# ------------------------------------------------- INFO exclusion (observations)


async def test_generate_fixes_skips_info_severity(db_session, monkeypatch):
    """INFO vulnerabilities get no Claude call and no fix text.

    On a live scan ~24 of 39 findings are informational (tech banners,
    robots.txt, SPA advisories). Spending a Sonnet call each starves the genuine
    HIGH/CRITICAL findings under the per-scan budget cap.
    """
    org, project, scan = await seed_org_project_scan(db_session)
    client = install_anthropic(monkeypatch, [make_anthropic_response(_FIX_TEXT)])
    info = await add_vulnerability(
        db_session, scan, org, project, severity=Severity.INFO, severity_score=1.0
    )
    high = await add_vulnerability(
        db_session, scan, org, project, severity=Severity.HIGH, severity_score=7.0
    )
    await _generate_fixes(db=db_session, scan_id=scan.id)

    assert len(client.messages.calls) == 1  # only the HIGH one
    assert high.ai_fix_text == _FIX_TEXT
    assert info.ai_fix_text is None


async def test_generate_fixes_info_fix_text_stays_null_not_fallback_template(
    db_session, monkeypatch
):
    """INFO must NOT get _fallback_fix_template.

    That template claims "AI-generated remediation is temporarily unavailable",
    which would be false: nothing failed and nothing was skipped for budget.
    """
    org, project, scan = await seed_org_project_scan(db_session)
    install_anthropic(monkeypatch, [])
    info = await add_vulnerability(
        db_session, scan, org, project, severity=Severity.INFO, severity_score=1.0
    )
    await _generate_fixes(db=db_session, scan_id=scan.id)

    assert info.ai_fix_text is None
    assert scan.ai_pipeline_degraded is False  # an exclusion is not a degradation
