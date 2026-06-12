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
SCAN_TYPE_BUDGETS_USD: dict[ScanType, Decimal] = {
    ScanType.QUICK: Decimal("0.08"),
    ScanType.FULL_WEB: Decimal("0.25"),
    ScanType.FULL_WEB_SOURCE: Decimal("0.40"),
    ScanType.FULL_SPECTRUM: Decimal("0.55"),
    ScanType.API: Decimal("0.15"),
    ScanType.MOBILE: Decimal("0.10"),
    ScanType.CONTAINER: Decimal("0.05"),
    ScanType.PUBLIC: Decimal("0.08"),
}


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
) -> bool:
    """Return True if a call is permitted; False if budget would be exceeded.

    Pre-call use (Q2 B.c high-cost ops): pass ``estimated_cost_usd``.
    Post-call use (low-cost ops): omit it to verify the running aggregate.
    """
    consumed = await get_consumed_cost(db=db, scan_id=scan_id)
    budget = SCAN_TYPE_BUDGETS_USD.get(scan_type)
    if budget is None:
        raise RuntimeError(f"No AI budget configured for scan_type={scan_type!r}")
    return (consumed + (estimated_cost_usd or Decimal("0"))) <= budget


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
) -> AIAPICall:
    """Record one AI call (Q2 B.c post-call logging).

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
    )
    db.add(call)
    return call
