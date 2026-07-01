"""AI executive summary generation (ADR-032; M9.C Stage 3 C1).

The M9.C companion to fix generation: a single Claude Sonnet call per scan that
produces a C-level executive summary of the scan's findings (SPEC §8.5; Sonnet
locked). Per ADR-013 the api is the sole writer of ``Scan.executive_summary``.

Q9 4-section structure; Q10 severity-tiered input; Q11 deterministic fallback on
budget exhaustion or Claude failure; Q12 idempotency (skip when a summary already
exists); Q13 C.b trivial summary for zero-vuln scans. The retry + cost helpers are
shared with fix generation (PY2 cross-module discipline).
"""

from __future__ import annotations

import logging
from collections import Counter
from decimal import Decimal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scans import Scan
from app.models.vulnerabilities import Severity, Vulnerability
from app.services.ai.cost_tracking import check_budget, log_ai_call
from app.services.ai.fix_generation import (
    _call_claude_with_retry,
    _compute_cost_from_usage,
)

logger = logging.getLogger(__name__)

# SPEC §8.5: executive summary → Claude Sonnet.
SUMMARY_PROVIDER = "anthropic"
SUMMARY_MODEL = "claude-sonnet-4-6"
SUMMARY_OPERATION = "executive_summary"
SUMMARY_MAX_TOKENS = 1500

# Q11 A.a: conservative per-scan summary cost estimate for the budget gate.
ESTIMATED_SUMMARY_COST_USD = Decimal("0.05")

_ZERO_VULN_SUMMARY = (
    "## Executive Summary\n\n"
    "The scan completed successfully and did not identify any vulnerabilities.\n"
)

# Q10 A.c: how many MEDIUM findings to surface in detail (CRITICAL/HIGH: all).
_MEDIUM_TOP_N = 5
_TOP_CWE_N = 5

SUMMARY_SYSTEM_PROMPT = (
    "You are a senior security advisor writing an executive summary of an "
    "application security scan for a CISO and CTO audience. Use clear business "
    "language; quantify risk; avoid tool jargon and raw finding dumps.\n\n"
    "Respond in plain Markdown with exactly these four sections:\n"
    "## Executive Summary\n"
    "## Key Findings\n"
    "## Risk Posture\n"
    "## Recommended Actions\n\n"
    "Constraints: stay under 600 words; no external links; base every statement "
    "on the provided data."
)

SUMMARY_USER_PROMPT_TEMPLATE = (
    "Scan context:\n{scan_context}\n\n"
    "Vulnerability breakdown:\n{vuln_breakdown}\n\n"
    "Top findings:\n{top_findings}\n\n"
    "Corroboration:\n{corroboration_summary}\n"
)

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _build_scan_context(scan: Scan) -> str:
    """Scan-level framing (type + timing)."""
    return (
        f"Scan type: {scan.scan_type.value}\n"
        f"Started: {scan.started_at or 'N/A'}\n"
        f"Completed: {scan.completed_at or 'N/A'}"
    )


def _build_vuln_breakdown(vulnerabilities: list[Vulnerability]) -> str:
    """Q10 C.c: counts by severity + top-5 CWE families."""
    by_severity = Counter(v.severity for v in vulnerabilities)
    severity_lines = "\n".join(
        f"- {sev.value}: {by_severity.get(sev, 0)}"
        for sev in _SEVERITY_ORDER
        if by_severity.get(sev, 0)
    )
    cwe_counts = Counter(v.cwe_id for v in vulnerabilities if v.cwe_id)
    top_cwes = ", ".join(
        f"{cwe} ({count})" for cwe, count in cwe_counts.most_common(_TOP_CWE_N)
    )
    return (
        f"Total: {len(vulnerabilities)}\n"
        f"{severity_lines}\n"
        f"Top CWE families: {top_cwes or 'N/A'}"
    )


def _build_top_findings(vulnerabilities: list[Vulnerability]) -> str:
    """Q10 A.c severity-tier selection + Q10 B.b mid-detail per finding.

    All CRITICAL + all HIGH + top-5 MEDIUM (by severity_score); LOW/INFO skipped.
    """
    criticals = [v for v in vulnerabilities if v.severity == Severity.CRITICAL]
    highs = [v for v in vulnerabilities if v.severity == Severity.HIGH]
    mediums = sorted(
        (v for v in vulnerabilities if v.severity == Severity.MEDIUM),
        key=lambda v: v.severity_score or 0.0,
        reverse=True,
    )[:_MEDIUM_TOP_N]

    selected = criticals + highs + mediums
    if not selected:
        return "N/A"

    lines = []
    for v in selected:
        location = v.target_url or v.code_file or "N/A"
        lines.append(
            f"- [{v.severity.value}] {v.title} "
            f"(CWE: {v.cwe_id or 'N/A'}; location: {location}; "
            f"corroborated across {v.corroborated_count} layers)"
        )
    return "\n".join(lines)


def _build_corroboration_summary(vulnerabilities: list[Vulnerability]) -> str:
    """Q10 D.a: aggregate cross-layer corroboration signal."""
    total = len(vulnerabilities)
    corroborated = sum(1 for v in vulnerabilities if v.corroborated_count > 1)
    return (
        f"{corroborated} of {total} findings were corroborated across multiple "
        "testing layers."
    )


def _build_summary_user_prompt(
    scan: Scan, vulnerabilities: list[Vulnerability]
) -> str:
    """Combine the four builders into the user prompt (Q10)."""
    return SUMMARY_USER_PROMPT_TEMPLATE.format(
        scan_context=_build_scan_context(scan),
        vuln_breakdown=_build_vuln_breakdown(vulnerabilities),
        top_findings=_build_top_findings(vulnerabilities),
        corroboration_summary=_build_corroboration_summary(vulnerabilities),
    )


def _deterministic_fallback_summary(vulnerabilities: list[Vulnerability]) -> str:
    """Q11 C.c: deterministic 4-section summary when Claude is unavailable."""
    by_severity = Counter(v.severity for v in vulnerabilities)
    counts = ", ".join(
        f"{by_severity.get(sev, 0)} {sev.value}"
        for sev in _SEVERITY_ORDER
        if by_severity.get(sev, 0)
    )
    return (
        "## Executive Summary\n"
        f"The scan identified {len(vulnerabilities)} vulnerabilities "
        f"({counts or 'none by severity'}). AI-generated narrative is temporarily "
        "unavailable; this is a deterministic summary.\n\n"
        "## Key Findings\n"
        f"Findings by severity: {counts or 'N/A'}.\n\n"
        "## Risk Posture\n"
        "Prioritise remediation by severity, addressing critical and high findings "
        "first.\n\n"
        "## Recommended Actions\n"
        "1. Triage critical and high findings immediately.\n"
        "2. Schedule remediation for medium findings.\n"
        "3. Re-scan after fixes to confirm resolution."
    )


async def _generate_executive_summary(*, db: AsyncSession, scan_id: UUID) -> None:
    """Generate + store the scan's executive summary (Q9-Q13).

    Idempotent (Q12 A): returns early when a summary already exists. Zero-vuln
    scans get a trivial deterministic summary (Q13 C.b). Budget exhaustion or a
    retry-exhausted Claude failure degrades to ``_deterministic_fallback_summary``
    and sets ``scan.ai_pipeline_degraded`` (Q11 C.c). Sole writer per ADR-013.
    """
    scan = await db.get(Scan, scan_id)
    if scan is None:
        return
    if scan.executive_summary is not None:
        return  # Q12 A idempotency

    vulnerabilities = list(
        (
            await db.execute(
                select(Vulnerability).where(Vulnerability.scan_id == scan_id)
            )
        )
        .scalars()
        .all()
    )
    if not vulnerabilities:
        scan.executive_summary = _ZERO_VULN_SUMMARY  # Q13 C.b
        return

    permitted = await check_budget(
        db=db,
        scan_id=scan.id,
        scan_type=scan.scan_type,
        estimated_cost_usd=ESTIMATED_SUMMARY_COST_USD,
    )
    if not permitted:
        logger.info("summary: scan %s over budget; deterministic fallback", scan_id)
        await log_ai_call(
            db=db,
            organization_id=scan.organization_id,
            scan_id=scan.id,
            provider=SUMMARY_PROVIDER,
            model=SUMMARY_MODEL,
            operation_type=SUMMARY_OPERATION,
            tokens_in=0,
            tokens_out=0,
            cost_usd=Decimal("0"),
        )
        scan.executive_summary = _deterministic_fallback_summary(vulnerabilities)
        scan.ai_pipeline_degraded = True
        return

    user_prompt = _build_summary_user_prompt(scan, vulnerabilities)
    try:
        message = await _call_claude_with_retry(
            system=SUMMARY_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            max_tokens=SUMMARY_MAX_TOKENS,
        )
    except Exception:  # noqa: BLE001 — retry-exhausted: degrade, don't propagate
        logger.warning("summary: Claude call failed for scan %s; fallback", scan_id)
        await log_ai_call(
            db=db,
            organization_id=scan.organization_id,
            scan_id=scan.id,
            provider=SUMMARY_PROVIDER,
            model=SUMMARY_MODEL,
            operation_type=SUMMARY_OPERATION,
            tokens_in=0,
            tokens_out=0,
            cost_usd=Decimal("0"),
        )
        scan.executive_summary = _deterministic_fallback_summary(vulnerabilities)
        scan.ai_pipeline_degraded = True
        return

    tokens_in = message.usage.input_tokens
    tokens_out = message.usage.output_tokens
    await log_ai_call(
        db=db,
        organization_id=scan.organization_id,
        scan_id=scan.id,
        provider=SUMMARY_PROVIDER,
        model=SUMMARY_MODEL,
        operation_type=SUMMARY_OPERATION,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cost_usd=_compute_cost_from_usage(tokens_in, tokens_out),
    )
    scan.executive_summary = message.content[0].text
