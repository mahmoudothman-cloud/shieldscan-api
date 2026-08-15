"""AI pipeline cost-tracking models per ADR-029 (M9.0 Stage 3 C1).

Closes Drift #64 (Drift #60 catch-class 4th-instance: ai_api_calls absence per
CLAUDE.md Gotcha 5 mandate). Per-call rows; aggregate cost computed via SUM query
on scan_id (ADR-029 Q2 A.c). Budget enforcement lives at
``app.services.ai.cost_tracking``.

Tenant-scoped: ``ai_api_calls`` is registered in ``app.db.policies.TENANT_TABLES``
and carries the standard ``tenant_isolation`` RLS policy (Gotcha 3).
"""

from __future__ import annotations

from decimal import Decimal
from uuid import UUID, uuid4

from sqlalchemy import ForeignKey, Integer, Numeric, String
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantMixin, TimestampMixin


class AIAPICall(Base, TimestampMixin, TenantMixin):
    """One row per AI provider API call, for cost tracking + budget enforcement.

    Per ADR-029 Q2 Phase-2: ``provider`` ∈ {"openai", "anthropic"};
    ``operation_type`` names the pipeline stage (e.g. "embedding",
    "fix_generation", "executive_summary"). ``tokens_out`` is nullable
    (embeddings have no completion tokens). ``cost_usd`` is Numeric(10,6).
    """

    __tablename__ = "ai_api_calls"

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    operation_type: Mapped[str] = mapped_column(String(50), nullable=False)
    tokens_in: Mapped[int] = mapped_column(Integer, nullable=False)
    tokens_out: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(10, 6), nullable=False)
    # NULL = the call succeeded. Non-NULL = it failed, and this is the reason
    # (provider error type where available, else the exception class name).
    #
    # Without this a failed call is indistinguishable from a cheap one: the
    # failure path logs tokens=0 and cost=0, so a 100%-degraded pipeline shows
    # up in cost metrics as free. That is how 34 hours of every-fix-is-a-
    # placeholder went unnoticed — the spend graph looked healthy because
    # nothing was being spent.
    error_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
