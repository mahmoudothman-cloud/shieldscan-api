from __future__ import annotations

from datetime import datetime
from enum import Enum as PyEnum
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantMixin, TimestampMixin


class SubdomainStatus(str, PyEnum):
    LIVE = "live"
    DEAD = "dead"
    TIMEOUT = "timeout"


class AttackSurface(Base, TimestampMixin, TenantMixin):
    __tablename__ = "attack_surface"
    __table_args__ = (
        UniqueConstraint("scan_id", "subdomain", name="uq_scan_subdomain"),
    )

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    root_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    subdomain: Mapped[str] = mapped_column(String(255), nullable=False)
    full_url: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[SubdomainStatus] = mapped_column(
        Enum(SubdomainStatus, name="subdomain_status"), nullable=False
    )
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tech_stack: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    last_probed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
