from __future__ import annotations

from datetime import datetime
from enum import Enum as PyEnum
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantMixin, TimestampMixin


class ScanType(str, PyEnum):
    QUICK = "quick"
    FULL_WEB = "full_web"
    FULL_WEB_SOURCE = "full_web_source"
    API = "api"
    MOBILE = "mobile"
    CONTAINER = "container"
    FULL_SPECTRUM = "full_spectrum"
    # ADDENDUM-CRITICAL-5 §2, §9.2 — unauthenticated 60s public scan.
    # Lives in the `scans` enum for the tool router; public-scan *records*
    # live in a separate `public_scans` table (ADDENDUM §2.4).
    PUBLIC = "public"


class ScanStatus(str, PyEnum):
    QUEUED = "queued"
    RECONNING = "reconning"
    RUNNING = "running"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELED = "canceled"


class Scan(Base, TimestampMixin, TenantMixin):
    __tablename__ = "scans"

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    project_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_type: Mapped[ScanType] = mapped_column(
        Enum(ScanType, name="scan_type"), nullable=False
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"),
        nullable=False,
        default=ScanStatus.QUEUED,
    )
    mobile_upload_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("mobile_uploads.id", ondelete="SET NULL"),
        nullable=True,
    )
    recon_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    subdomain_limit: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    priority: Mapped[str] = mapped_column(String(20), default="normal", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ADDENDUM-CRITICAL-5 §1.3 — public-scan marker + onboarding demo marker.
    is_public: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    public_slug: Mapped[str | None] = mapped_column(
        String(32), nullable=True, unique=True, index=True
    )
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # --- ADR-029 M9.0 AI pipeline foundation ---
    # Q3 Phase-3 (Drift #65 resolution): intermediate executive-summary store
    # at M9; full Report architecture (PDF/HTML + R2 + API) forward-pinned to M10.
    executive_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Q8 Phase-8: flipped True when any AI pipeline stage falls back per SPEC §8.6;
    # COMPLETED status is preserved when outputs are produced via fallback.
    ai_pipeline_degraded: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )


class ScanJob(Base, TimestampMixin, TenantMixin):
    __tablename__ = "scan_jobs"

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    engine: Mapped[str] = mapped_column(String(50), nullable=False)
    target_url: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    idempotency_key: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False
    )
    finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # M14: which on-prem agent this job was routed to (NULL = cloud worker).
    agent_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True, index=True)
    leased_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
