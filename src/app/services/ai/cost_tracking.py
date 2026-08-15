"""AI API cost tracking + budget enforcement per ADR-029 Q2 Phase-2 (M9.0 C1.5).

Y-COST-TRACKING-MODULE-SHAPE resolved (a): function-style, stateless API
(mirrors ``app.services.audit``). Closes Drift #64 (ai_api_calls absence per
CLAUDE.md Gotcha 5 mandate).

Architecture (ADR-029 Q2):
- Per-call ``ai_api_calls`` rows; aggregate cost via SUM query (A.c).
- Hybrid enforcement (B.c): pre-call check for high-cost ops (Claude fix-gen +
  executive summary); post-call log for low-cost ops (embeddings + correlation).
- Per-scan circuit breaker (C.a); global circuit breaker forward-pinned.
- Hardcoded ScanType budgets per SPEC §8.5; database-configurable per-org tiers
  forward-pinned (production-readiness audit).
"""

from __future__ import annotations

from decimal import Decimal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai import AIAPICall
from app.models.scans import ScanType

# Hardcoded ScanType AI-cost budgets (USD) per SPEC §8.5 + ADR-029 Q2.
# Production-readiness audit forward-pin: database-configurable per-org tiers.
# Covers every ScanType member (V-IIC grounded) so check_budget never hits the
# "no budget configured" path for a real scan. PUBLIC (demo) is treated as
# QUICK-equivalent.
# Raised at the live full_web bring-up (scan a70e1711, 26 findings): the
# original caps (FULL_WEB 0.25 etc.) did not scale with finding count, so a
# rich scan's per-vuln fix spend consumed the whole budget and the executive
# summary — which runs LAST — was starved into its deterministic fallback
# (ai_pipeline_degraded=true). Caps now cover a realistic high-finding-count
# scan: per-vuln fix (~$0.014 actual / $0.025 gate-estimate) × dozens +
# embeddings + the reserved summary slice (RESERVED_SUMMARY_BUDGET_USD). Small
# scan types were also raised so the summary reservation cannot starve their
# fixes. Reconciled in SPEC §8.5 (caps vs the lower typical-spend targets).
SCAN_TYPE_BUDGETS_USD: dict[ScanType, Decimal] = {
    ScanType.QUICK: Decimal("0.15"),
    ScanType.FULL_WEB: Decimal("0.75"),
    ScanType.FULL_WEB_SOURCE: Decimal("1.00"),
    ScanType.FULL_SPECTRUM: Decimal("1.50"),
    ScanType.API: Decimal("0.30"),
    ScanType.MOBILE: Decimal("0.20"),
    ScanType.CONTAINER: Decimal("0.15"),
    ScanType.PUBLIC: Decimal("0.15"),
}

# Slice of a scan's budget reserved for the executive summary so a
# high-finding-count scan's fix-generation spend cannot starve it (the
# summary runs last in the pipeline). Fix-generation gates against
# budget - this reserve; the summary gates against the full budget. Kept
# equal to the summary's own gate-estimate so the reservation exactly
# covers one summary call. See fix_generation + summary.
RESERVED_SUMMARY_BUDGET_USD = Decimal("0.05")


class BudgetExceededError(Exception):
    """Raised when a scan's AI cost budget is exhausted (Q2 C.a circuit breaker)."""


async def get_consumed_cost(*, db: AsyncSession, scan_id: UUID) -> Decimal:
    """Aggregate AI cost consumed by a scan so far (Q2 A.c computed aggregate)."""
    result = await db.scalar(
        select(func.coalesce(func.sum(AIAPICall.cost_usd), Decimal("0"))).where(
            AIAPICall.scan_id == scan_id
        )
    )
    return result if result is not None else Decimal("0")


async def check_budget(
    *,
    db: AsyncSession,
    scan_id: UUID,
    scan_type: ScanType,
    estimated_cost_usd: Decimal | None = None,
    reserve_usd: Decimal | None = None,
) -> bool:
    """Return True if a call is permitted; False if budget would be exceeded.

    Pre-call use (Q2 B.c high-cost ops): pass ``estimated_cost_usd``.
    Post-call use (low-cost ops): omit it to verify the running aggregate.

    ``reserve_usd`` holds back part of the budget from THIS caller so a
    later, must-run stage is guaranteed its slice. Fix-generation passes
    ``RESERVED_SUMMARY_BUDGET_USD`` so a high-finding-count scan cannot
    consume the executive summary's budget (the summary runs last and gates
    against the full budget, i.e. without a reserve).
    """
    consumed = await get_consumed_cost(db=db, scan_id=scan_id)
    budget = SCAN_TYPE_BUDGETS_USD.get(scan_type)
    if budget is None:
        raise RuntimeError(f"No AI budget configured for scan_type={scan_type!r}")
    available = budget - (reserve_usd or Decimal("0"))
    return (consumed + (estimated_cost_usd or Decimal("0"))) <= available


async def log_ai_call(
    *,
    db: AsyncSession,
    organization_id: UUID,
    scan_id: UUID,
    provider: str,
    model: str,
    operation_type: str,
    tokens_in: int,
    tokens_out: int | None,
    cost_usd: Decimal,
    error_type: str | None = None,
) -> AIAPICall:
    """Record one AI call (Q2 B.c post-call logging).

    ``error_type`` is None for a successful call and carries the failure reason
    otherwise. Without it a failed call (tokens 0, cost 0) is indistinguishable
    from a cheap one, so a fully-degraded pipeline reads as free in the cost
    metrics.

    Adds the row to the session and returns it; the caller owns the
    flush/commit (transaction boundary discipline, as with ``audit``).
    """
    call = AIAPICall(
        organization_id=organization_id,
        scan_id=scan_id,
        provider=provider,
        model=model,
        operation_type=operation_type,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cost_usd=cost_usd,
        error_type=error_type,
    )
    db.add(call)
    return call
