from __future__ import annotations

from datetime import datetime
from enum import Enum as PyEnum
from uuid import UUID, uuid4

from sqlalchemy import (
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantMixin, TimestampMixin
from app.models.raw_findings import EngineCategory, MobileOS, Severity


class VulnerabilityStatus(str, PyEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class Vulnerability(Base, TimestampMixin, TenantMixin):
    """Deduplicated, scored, AI-enriched finding promoted from raw_findings.

    Populated by the M9 AI pipeline (dedup + correlate + score + fix).
    Evidence columns carry only the most salient values from the primary
    source RawFinding; fuller per-tool evidence hangs off `evidence` rows.
    """

    __tablename__ = "vulnerabilities"

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Classification
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="severity"), nullable=False
    )
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    owasp: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    engine_category: Mapped[EngineCategory] = mapped_column(
        Enum(EngineCategory, name="engine_category"), nullable=False
    )

    # Primary evidence (most salient values — full evidence in `evidence` rows)
    target_url: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    code_file: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    code_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mobile_os: Mapped[MobileOS | None] = mapped_column(
        Enum(MobileOS, name="mobile_os"), nullable=True
    )
    mobile_permission: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mobile_component_name: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Dedup identity (may repeat across scans — used by scan comparison)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Status + assignment
    status: Mapped[VulnerabilityStatus] = mapped_column(
        Enum(VulnerabilityStatus, name="vulnerability_status"),
        nullable=False,
        default=VulnerabilityStatus.OPEN,
    )
    assigned_to: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # AI enrichment (spec §8.5)
    ai_fix_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Cross-layer corroboration (spec §8.3)
    corroborated_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # --- ADR-029 M9.0 AI pipeline foundation ---
    # Q5 Phase-5: reference to the Qdrant point representing this vuln's embedding
    # (deterministic id); enables correlation explainability + future cross-scan dedup.
    qdrant_point_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), nullable=True
    )
    # Q6 Phase-6: per-raw-finding traceability — the raw_findings this vuln was
    # promoted from (hybrid clustering; one Vulnerability per dedup-cluster).
    raw_finding_ids: Mapped[list[UUID] | None] = mapped_column(
        ARRAY(PgUUID(as_uuid=True)), nullable=True
    )
    # --- ADR-031 M9.B AI pipeline: correlation + scoring ---
    # Q8: union-find cluster grouping id for cross-layer correlation (Path B link;
    # not a FK — a cluster-grouping UUID). Indexed for the Y2 vulnerability_count
    # DISTINCT(correlation_cluster_id) adapter.
    correlation_cluster_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), nullable=True, index=True
    )
    # Q11: composite SPEC §8.3 final_score (base_cvss × corroboration ×
    # exploitability, capped 10.0). Not indexed — M10 ranking index forward-pinned.
    severity_score: Mapped[float | None] = mapped_column(Float, nullable=True)


class Evidence(Base, TimestampMixin, TenantMixin):
    """Per-tool evidence payload attached to a Vulnerability."""

    __tablename__ = "evidence"

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    vulnerability_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    request: Mapped[str | None] = mapped_column(Text, nullable=True)
    response: Mapped[str | None] = mapped_column(Text, nullable=True)
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_output_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)


class VulnerabilityHistory(Base, TimestampMixin, TenantMixin):
    """Append-only audit of Vulnerability.status transitions."""

    __tablename__ = "vulnerability_history"

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    vulnerability_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    from_status: Mapped[VulnerabilityStatus] = mapped_column(
        Enum(VulnerabilityStatus, name="vulnerability_status"), nullable=False
    )
    to_status: Mapped[VulnerabilityStatus] = mapped_column(
        Enum(VulnerabilityStatus, name="vulnerability_status"), nullable=False
    )
    changed_by: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
