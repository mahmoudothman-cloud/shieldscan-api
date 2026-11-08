"""AI fix generation (ADR-032; M9.C Stage 3 C1).

The third real-AI pipeline stage (after M9.A embed/dedup + M9.B correlate/score):
per-Vulnerability remediation guidance from Claude Sonnet per SPEC §8.4 (mobile
context) + §8.5 (multi-provider strategy; Sonnet locked).

Gate-1 Y-FIX-GEN-PER-VULN-VS-BATCH = Path A: one Claude call per Vulnerability;
per-vuln ``check_budget`` pre-call; isolated failure semantics + graceful
``_fallback_fix_template``; per-vuln ai_api_calls granularity; per-vuln
idempotency (skip where ``ai_fix_text IS NOT NULL``, Q7). Threshold-based
``Scan.ai_pipeline_degraded`` when >=3 fallbacks OR >=30% of vulns fall back
(Q8 B.b). Circuit-breaker forward-pinned to production-readiness (Gate-2 B).

Per ADR-013 the api is the sole writer of ``Vulnerability.ai_fix_text``.

V-BB pre-C1 grounding: ``check_budget`` returns a bool (True = permitted), it does
not raise; the budget-exhaustion class is ``BudgetExceededError``. Vulnerability
carries ``raw_finding_ids`` (array column, no ORM relationship), so the
representative raw_finding is loaded by id (M9.B ``6c9e270`` evidence pattern).
"""

from __future__ import annotations

import asyncio
import logging
from decimal import Decimal
from uuid import UUID

import anthropic
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.raw_findings import EngineCategory, RawFinding, Severity
from app.models.scans import Scan
from app.models.vulnerabilities import Vulnerability, VulnerabilityStatus
from app.services.ai.clients import get_anthropic_client
from app.services.ai.cost_tracking import (
    RESERVED_SUMMARY_BUDGET_USD,
    check_budget,
    log_ai_call,
)

logger = logging.getLogger(__name__)

# SPEC §8.5: fix generation → Claude Sonnet (Opus/Haiku Phase-2 forward-pinned).
FIX_GEN_PROVIDER = "anthropic"
FIX_GEN_MODEL = "claude-sonnet-4-6"
FIX_GEN_OPERATION = "fix_generation"
FIX_GEN_MAX_TOKENS = 2000

# Q5 A.c: conservative per-vuln cost estimate for the pre-call budget gate.
# Sonnet pricing (Q5): $3 / 1M input tokens + $15 / 1M output tokens.
ESTIMATED_FIX_COST_USD = Decimal("0.025")
_SONNET_INPUT_COST_PER_TOKEN = Decimal("3") / Decimal("1000000")
_SONNET_OUTPUT_COST_PER_TOKEN = Decimal("15") / Decimal("1000000")

# Q8 A.b: retry the Claude call up to 3 times with exponential backoff.
RETRY_MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = [1, 2, 4]

# Q8 B.b: mark the scan degraded when fallbacks cross either threshold.
DEGRADED_THRESHOLD_COUNT = 3
DEGRADED_THRESHOLD_PCT = 0.30

_EVIDENCE_DESCRIPTION_LIMIT = 500
_EVIDENCE_SNIPPET_LIMIT = 1000

# Q1 C.b: role + output format + hard constraints. The user prompt carries the
# per-finding detail; the system prompt is stable (prompt-caching forward-pin).
FIX_GEN_SYSTEM_PROMPT = (
    "You are a senior application security engineer writing remediation guidance "
    "for a specific, confirmed vulnerability. Write for the developer who owns the "
    "affected code. Be concrete and actionable; prefer secure defaults and platform "
    "best practices.\n\n"
    "Respond in plain Markdown with exactly these three sections:\n"
    "## Explanation\n"
    "## Fix Code\n"
    "## Remediation Steps\n\n"
    "Constraints: stay under 500 words; no external links; do not invent details "
    "not supported by the evidence; if the language or framework is unknown, give "
    "language-agnostic guidance."
)

FIX_GEN_USER_PROMPT_TEMPLATE = (
    "Vulnerability: {title}\n"
    "Severity: {severity}\n"
    "CWE: {cwe_id}\n\n"
    "Description:\n{description}\n\n"
    "Target context:\n{target_context}\n\n"
    "Evidence:\n{evidence}\n"
)


def _build_mobile_context(vuln: Vulnerability) -> str:
    """SPEC §8.4 mobile fix context (Q2 B.a; N/A for unset fields)."""
    platform = vuln.mobile_os.value if vuln.mobile_os is not None else "N/A"
    return (
        f"Platform: {platform}\n"
        f"Component: {vuln.mobile_component_name or 'N/A'}\n"
        f"Permission: {vuln.mobile_permission or 'N/A'}\n"
        f"Code location: {vuln.code_file or 'N/A'}"
        f"{f':{vuln.code_line}' if vuln.code_line is not None else ''}"
    )


def _build_sast_context(vuln: Vulnerability, raw_finding: RawFinding | None) -> str:
    """Source-analysis fix context (code location + snippet)."""
    line = f":{vuln.code_line}" if vuln.code_line is not None else ""
    snippet = raw_finding.code_snippet if raw_finding is not None else None
    if snippet and len(snippet) > _EVIDENCE_SNIPPET_LIMIT:
        snippet = snippet[:_EVIDENCE_SNIPPET_LIMIT] + "…"
    return (
        f"Code location: {vuln.code_file or 'N/A'}{line}\n"
        f"Snippet:\n{snippet or 'N/A'}"
    )


def _build_dast_context(vuln: Vulnerability) -> str:
    """Dynamic-analysis fix context (endpoint + parameter)."""
    return (
        f"Target URL: {vuln.target_url or 'N/A'}\n"
        f"Parameter: {vuln.parameter or 'N/A'}"
    )


def _build_generic_context(vuln: Vulnerability) -> str:
    """Fallback context for engine categories without a specialised builder."""
    return (
        f"Engine category: {vuln.engine_category.value}\n"
        f"Target URL: {vuln.target_url or 'N/A'}\n"
        f"Code location: {vuln.code_file or 'N/A'}"
    )


def _build_target_context(vuln: Vulnerability, raw_finding: RawFinding | None) -> str:
    """Dispatch to the engine-specific context builder (Q1 A.c + Q3 A).

    Mobile is detected by ``engine_category == MOBILE`` (Q3 A). A one-line
    corroboration summary is appended when the Vulnerability was corroborated
    across engines (Q2 C.b).
    """
    if vuln.engine_category == EngineCategory.MOBILE:
        context = _build_mobile_context(vuln)
    elif vuln.engine_category == EngineCategory.SAST:
        context = _build_sast_context(vuln, raw_finding)
    elif vuln.engine_category == EngineCategory.DAST:
        context = _build_dast_context(vuln)
    else:
        context = _build_generic_context(vuln)

    if vuln.corroborated_count and vuln.corroborated_count > 1:
        context += (
            f"\nCorroboration: confirmed across {vuln.corroborated_count} "
            "testing layers."
        )
    return context


def _format_evidence(vuln: Vulnerability, raw_finding: RawFinding | None) -> str:
    """Q4 hybrid structured evidence (tool + engine + description + snippet)."""
    if raw_finding is None:
        return "N/A (no contributing raw finding available)"

    description = raw_finding.description or "N/A"
    if len(description) > _EVIDENCE_DESCRIPTION_LIMIT:
        description = description[:_EVIDENCE_DESCRIPTION_LIMIT] + "…"

    snippet = raw_finding.code_snippet
    if snippet and len(snippet) > _EVIDENCE_SNIPPET_LIMIT:
        snippet = snippet[:_EVIDENCE_SNIPPET_LIMIT] + "…"

    return (
        f"Tool: {raw_finding.tool_name}\n"
        f"Engine: {raw_finding.engine_category.value}\n"
        f"Description: {description}\n"
        f"Snippet: {snippet or 'N/A'}"
    )


def _fallback_fix_template(vuln: Vulnerability) -> str:
    """Q4 deterministic fallback used when Claude is unavailable or over budget.

    The caller sets ``Scan.ai_pipeline_degraded`` when it uses this path (Q8 B.b).
    """
    return (
        "## Explanation\n"
        "AI-generated remediation is temporarily unavailable for this finding. "
        f"This is a {vuln.severity.value} severity {vuln.engine_category.value} "
        f"issue (CWE: {vuln.cwe_id or 'N/A'}).\n\n"
        "## Fix Code\n"
        "Not available — apply the standard remediation for this vulnerability "
        "class.\n\n"
        "## Remediation Steps\n"
        "1. Review the finding evidence and confirm the affected code path.\n"
        "2. Apply the standard mitigation for this CWE class.\n"
        "3. Re-scan to verify the finding is resolved."
    )


def _use_fallback(vuln: Vulnerability) -> str:
    """Assign the fallback template AND mark the vulnerability as fallen back.

    One helper so the two can never drift: a fix_text without the flag is
    exactly the state that forced audits to match on
    ``ai_fix_text LIKE '%temporarily unavailable%'``.
    """
    fix_text = _fallback_fix_template(vuln)
    vuln.ai_fix_text = fix_text
    vuln.ai_fix_is_fallback = True
    return fix_text


def _compute_cost_from_usage(tokens_in: int, tokens_out: int) -> Decimal:
    """Sonnet cost from token usage (Q5): $3/1M in + $15/1M out."""
    return (
        Decimal(tokens_in) * _SONNET_INPUT_COST_PER_TOKEN
        + Decimal(tokens_out) * _SONNET_OUTPUT_COST_PER_TOKEN
    )


def is_retryable(exc: Exception) -> bool:
    """True when retrying ``exc`` could plausibly succeed.

    Retry 429 (rate limit) and 5xx (provider-side); fail fast on every other
    4xx. A 400 ``invalid_request_error`` — a bad request, an unknown model, or
    an exhausted credit balance — will return exactly the same error on every
    attempt.

    This is not a micro-optimisation. During a 34-hour credit outage the
    uniform-retry policy sent 3 attempts × 10 calls = 30 doomed requests per
    scan, turning a single unambiguous billing error into 30 identical
    failures and three times the latency before the fallback appeared.

    Connection/timeout errors carry no status and ARE retried — those are the
    transient case retries exist for.
    """
    status = getattr(exc, "status_code", None)
    if status is None:
        return True  # network/timeout/unknown — the genuinely transient case
    if status == 429 or status >= 500:
        return True
    return False


def describe_error(exc: Exception) -> str:
    """Short, stable label for an AI call failure (stored in ai_api_calls).

    Prefers the provider's own error type (e.g. ``invalid_request_error``) so
    a billing exhaustion is distinguishable from a bad model id; falls back to
    the exception class name.
    """
    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict) and err.get("type"):
            return str(err["type"])[:100]
    return type(exc).__name__[:100]


async def _call_claude_with_retry(
    *, system: str, user_prompt: str, max_tokens: int
) -> anthropic.types.Message:
    """Q8 A.b: call Claude with up to 3 attempts, backing off 1s/2s/4s.

    Only retryable failures are retried (see ``is_retryable``); a
    non-retryable one propagates immediately. The last exception propagates
    once attempts are exhausted.
    """
    client = get_anthropic_client()
    last_exc: Exception | None = None
    for attempt in range(RETRY_MAX_ATTEMPTS):
        try:
            return await client.messages.create(
                model=FIX_GEN_MODEL,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user_prompt}],
            )
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised
            last_exc = exc
            if not is_retryable(exc):
                logger.error(
                    "ai call failed with a non-retryable error; not retrying: "
                    "%s status=%s type=%s",
                    type(exc).__name__,
                    getattr(exc, "status_code", "n/a"),
                    describe_error(exc),
                )
                raise
            if attempt < RETRY_MAX_ATTEMPTS - 1:
                await asyncio.sleep(RETRY_BACKOFF_SECONDS[attempt])
    assert last_exc is not None
    raise last_exc


async def generate_fix(
    *,
    db: AsyncSession,
    vulnerability: Vulnerability,
    raw_finding: RawFinding | None,
    scan: Scan,
) -> str:
    """Generate (and store) remediation text for one Vulnerability (Path A).

    Pre-call ``check_budget`` (Q5 B.a). On budget exhaustion or retry-exhausted
    Claude failure, degrade to ``_fallback_fix_template`` (Q4/Q8) and set
    ``scan.ai_pipeline_degraded``. Returns the fix text (also assigned to
    ``vulnerability.ai_fix_text`` per ADR-013 sole-writer).
    """
    permitted = await check_budget(
        db=db,
        scan_id=scan.id,
        scan_type=scan.scan_type,
        estimated_cost_usd=ESTIMATED_FIX_COST_USD,
        # Reserve the executive summary's slice so a high-finding-count scan's
        # fix spend can't starve it (the summary runs last).
        reserve_usd=RESERVED_SUMMARY_BUDGET_USD,
    )
    if not permitted:
        logger.info(
            "fix-gen: scan %s over budget; falling back for vuln %s",
            scan.id,
            vulnerability.id,
        )
        scan.ai_pipeline_degraded = True
        return _use_fallback(vulnerability)

    target_context = _build_target_context(vulnerability, raw_finding)
    evidence = _format_evidence(vulnerability, raw_finding)
    user_prompt = FIX_GEN_USER_PROMPT_TEMPLATE.format(
        title=vulnerability.title,
        severity=vulnerability.severity.value,
        cwe_id=vulnerability.cwe_id or "N/A",
        description=vulnerability.description or "N/A",
        target_context=target_context,
        evidence=evidence,
    )

    try:
        message = await _call_claude_with_retry(
            system=FIX_GEN_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            max_tokens=FIX_GEN_MAX_TOKENS,
        )
    except Exception as exc:  # noqa: BLE001 — degrade, don't propagate
        # Log the CAUSE, at error. Falling back is correct behaviour; discarding
        # why is not — a one-line warning summary is what let a 34-hour credit
        # outage look like ordinary degradation. exc_info carries the traceback
        # for anything the type/status/detail triple doesn't explain.
        logger.error(
            "fix-gen: Claude call failed for vuln %s; serving fallback. "
            "%s status=%s detail=%s",
            vulnerability.id,
            type(exc).__name__,
            getattr(exc, "status_code", "n/a"),
            describe_error(exc),
            exc_info=exc,
        )
        await log_ai_call(
            db=db,
            organization_id=scan.organization_id,
            scan_id=scan.id,
            provider=FIX_GEN_PROVIDER,
            model=FIX_GEN_MODEL,
            operation_type=FIX_GEN_OPERATION,
            tokens_in=0,
            tokens_out=0,
            cost_usd=Decimal("0"),
            error_type=describe_error(exc),
        )
        scan.ai_pipeline_degraded = True
        return _use_fallback(vulnerability)

    tokens_in = message.usage.input_tokens
    tokens_out = message.usage.output_tokens
    await log_ai_call(
        db=db,
        organization_id=scan.organization_id,
        scan_id=scan.id,
        provider=FIX_GEN_PROVIDER,
        model=FIX_GEN_MODEL,
        operation_type=FIX_GEN_OPERATION,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cost_usd=_compute_cost_from_usage(tokens_in, tokens_out),
    )
    fix_text = message.content[0].text
    vulnerability.ai_fix_text = fix_text
    vulnerability.ai_fix_is_fallback = False
    return fix_text


async def _generate_fixes(*, db: AsyncSession, scan_id: UUID) -> None:
    """Scan-level fix-generation orchestrator (Q6 + Q7 + Q8 B.b; Path A).

    Loads the scan's Vulnerabilities, skips those already fixed (Q7 A idempotency),
    processes the rest in descending ``severity_score`` order (Q6 C), and marks
    the scan degraded when the fallback rate crosses either Q8 B.b threshold.
    Defensive skip when the scan has no Vulnerabilities (Q13 C.b).

    INFO-severity Vulnerabilities are excluded: they are observations (technology
    banners, robots.txt, SPA advisories), not remediable defects, and on a real
    scan they are the majority — spending a Sonnet call each both wastes budget
    and pushes genuine HIGH/CRITICAL findings past the per-scan cap. Their
    ``ai_fix_text`` stays NULL. It is deliberately NOT filled with
    ``_fallback_fix_template``: that text claims "AI-generated remediation is
    temporarily unavailable", which would be false here — nothing failed and
    nothing was skipped for lack of budget. The report renderer, the JSON report,
    and the /fix endpoint all handle a null fix.
    """
    scan = await db.get(Scan, scan_id)
    if scan is None:
        return

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
        return  # Q13 C.b defensive skip

    pending = [
        v
        for v in vulnerabilities
        if v.ai_fix_text is None  # Q7 A idempotency
        and v.severity != Severity.INFO  # observations, not remediable defects
        # M11: a status carried over from the previous scan (false positive /
        # accepted risk) needs no fix; the previous row's fix text is reused.
        and v.status == VulnerabilityStatus.OPEN
    ]
    # Reuse the previous scan's fix for continued issues (same issue, same
    # fix) instead of paying for it again.
    continued = [v for v in vulnerabilities if v.previous_id is not None and v.ai_fix_text is None]
    if continued:
        prev_rows = {
            r.id: r
            for r in (
                await db.execute(
                    select(Vulnerability).where(
                        Vulnerability.id.in_([v.previous_id for v in continued])
                    )
                )
            ).scalars()
        }
        for v in continued:
            prev = prev_rows.get(v.previous_id)
            if prev is not None and prev.ai_fix_text and not prev.ai_fix_is_fallback:
                v.ai_fix_text = prev.ai_fix_text
                v.ai_fix_is_fallback = False
        pending = [v for v in pending if v.ai_fix_text is None]
    if not pending:
        return
    pending.sort(key=lambda v: v.severity_score or 0.0, reverse=True)  # Q6 C

    # Load each pending vuln's representative raw_finding (first id) for evidence
    # (V-BB: no ORM relationship; M9.B 6c9e270 pattern).
    rep_ids = {v.raw_finding_ids[0] for v in pending if v.raw_finding_ids}
    findings_by_id: dict[UUID, RawFinding] = {}
    if rep_ids:
        rows = (
            (await db.execute(select(RawFinding).where(RawFinding.id.in_(rep_ids))))
            .scalars()
            .all()
        )
        findings_by_id = {r.id: r for r in rows}

    fallback_before = scan.ai_pipeline_degraded
    fallback_count = 0
    for vuln in pending:
        rep = (
            findings_by_id.get(vuln.raw_finding_ids[0])
            if vuln.raw_finding_ids
            else None
        )
        degraded_pre = scan.ai_pipeline_degraded
        await generate_fix(
            db=db, vulnerability=vuln, raw_finding=rep, scan=scan
        )
        # generate_fix flips ai_pipeline_degraded on a fallback; count those.
        if scan.ai_pipeline_degraded and not degraded_pre:
            fallback_count += 1

    # Q8 B.b: degrade when fallbacks cross either threshold. generate_fix already
    # sets the flag per-fallback; this keeps the semantics explicit + auditable.
    total = len(pending)
    if fallback_count and (
        fallback_count >= DEGRADED_THRESHOLD_COUNT
        or fallback_count / total >= DEGRADED_THRESHOLD_PCT
    ):
        scan.ai_pipeline_degraded = True
    logger.info(
        "fix-gen: scan %s generated %d fixes (%d fallbacks; degraded=%s)",
        scan_id,
        total,
        fallback_count,
        scan.ai_pipeline_degraded or fallback_before,
    )
