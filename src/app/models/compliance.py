"""Compliance framework models (M10.C; Task 10.5; SPEC §DB tables 13-15).

Three GLOBAL reference tables — industry-standard compliance data shared
identically across all orgs:

    ComplianceFramework → ComplianceControl → CweControlMapping

Per SPEC line 345 these are explicitly NOT tenant-scoped: ``Base +
TimestampMixin``, **no TenantMixin, no RLS, not in TENANT_TABLES** (the
deliberate inverse of the M10.B reports table — precedent ``models/identity``).
Findings map to controls via the CWE string on ``Vulnerability.cwe_id``.
"""

from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class ComplianceFramework(Base, TimestampMixin):
    """A compliance framework (SOC 2, ISO 27001) — global reference data."""

    __tablename__ = "compliance_frameworks"

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    slug: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)


class ComplianceControl(Base, TimestampMixin):
    """An individual control within a framework — global reference data."""

    __tablename__ = "compliance_controls"

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    framework_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    control_id: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class CweControlMapping(Base, TimestampMixin):
    """A CWE → control mapping — global reference data. Findings join here
    via ``Vulnerability.cwe_id`` (e.g. ``"CWE-89"``)."""

    __tablename__ = "cwe_control_mappings"

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    cwe_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    control_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
