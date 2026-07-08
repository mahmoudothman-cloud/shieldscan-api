"""Report artifacts (M10.B; ADR-034; Tasks 10.2-10.4).

Tracks generated report artifacts per scan. Per DQ3 lazy per-format
persistence: only the PDF is stored in R2 and recorded here (at first
download); JSON/SARIF are rendered on-demand from the DB and never stored.
The ``format`` enum carries all three values for forward-compat even though
only PDF rows exist in practice.

Standard ``TenantMixin`` + RLS table per Gotcha 3 — the Python api is the
sole writer per ADR-013. (ADR-012 governs only the route-layer cross-tenant
-404 collapse, NOT this table's row-scoping — distinct mechanisms per ADR-034.)
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum as PyEnum
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantMixin, TimestampMixin


class ReportFormat(str, PyEnum):
    """Report output formats (G1.2; forward-compat — only PDF rows persist)."""

    PDF = "pdf"
    SARIF = "sarif"
    JSON = "json"


class Report(Base, TimestampMixin, TenantMixin):
    """A generated report artifact for a scan (M10.B; ADR-034 G1)."""

    __tablename__ = "reports"

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    format: Mapped[ReportFormat] = mapped_column(
        Enum(ReportFormat, name="report_format"), nullable=False
    )
    r2_key: Mapped[str] = mapped_column(String(500), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
