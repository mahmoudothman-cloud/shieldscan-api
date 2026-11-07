"""Public quick scans (M11 pre-work; ADDENDUM-CRITICAL-5 §2 "Public Scanning").

A ``PublicScan`` is the unauthenticated, top-of-funnel request record:
who asked (email, IP), for what (target URL), and which ``Scan`` row
carries the work. Results are addressed by ``slug`` — an unguessable
URL-safe token that is emailed to the requester — and expire.

Execution reuses the normal pipeline instead of the dedicated Go
executor the addendum sketched: the ``Scan`` is created inside a single
system organization (``settings.PUBLIC_SCAN_ORG_SLUG``) with
``is_public=True`` and ``ScanType.QUICK``; the orchestrator dispatches
the QUICK tool set directly on the target (no recon / subdomain
expansion) and the completions consumer finalises it without the AI
pipeline (zero AI spend on free scans). See DRIFT-LOG 2026-11-07.

Tenant table: ``organization_id`` is always the system org, so the
public routes set the RLS tenant context to it before any lookup.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantMixin, TimestampMixin


class PublicScan(Base, TimestampMixin, TenantMixin):
    __tablename__ = "public_scans"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )

    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(String(500), nullable=False)
    normalized_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    consent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    viewed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Conversion tracking (addendum §M10.5.5): set when the requester
    # registers from the result page. Filled by a later slice.
    converted_org_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
