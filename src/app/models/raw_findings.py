from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum as PyEnum
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantMixin, TimestampMixin


class Severity(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EngineCategory(str, PyEnum):
    # SPECIFICATION.md §5.3 + ADDENDUM-TOOLS-5 §2.1 (spa) + §4 (discovery).
    DAST = "dast"
    SAST = "sast"
    SCA = "sca"
    MOBILE = "mobile"
    INFRASTRUCTURE = "infrastructure"
    RECON = "recon"
    SSL = "ssl"
    API = "api"
    IAC = "iac"
    SECRETS = "secrets"
    CONTAINER = "container"
    SPA = "spa"
    DISCOVERY = "discovery"


class MobileOS(str, PyEnum):
    ANDROID = "android"
    IOS = "ios"


class RawFinding(Base, TimestampMixin, TenantMixin):
    """Unprocessed output from a scan tool, normalized to one row per finding.

    Lives 90 days per SPECIFICATION.md §5.4; AI pipeline dedups + promotes
    into `vulnerabilities`. Nullable evidence groups reflect tool category:
    web/API tools populate target_url/parameter/request/response; SAST tools
    populate code_file/code_line/code_snippet; MobSF populates mobile_*;
    SSLyze populates cipher_suite/cert_subject.
    """

    __tablename__ = "raw_findings"
    __table_args__ = (
        # ADDENDUM-TOOLS-5 §8.2 — exact index name required; orchestrator
        # later queries pg_indexes for this partial index to fast-path
        # "show me all verified live secrets" lookups.
        Index(
            "idx_raw_findings_verified_secret",
            "scan_id",
            postgresql_where=text("secret_verified = TRUE"),
        ),
    )

    # --- Identity (organization_id supplied by TenantMixin) ---
    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    scan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tool_name: Mapped[str] = mapped_column(String(50), nullable=False)
    engine_category: Mapped[EngineCategory] = mapped_column(
        Enum(EngineCategory, name="engine_category"), nullable=False
    )

    # --- Classification ---
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="severity"), nullable=False
    )
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    owasp: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # --- Categorical (SPEC §7.3 schema extension; M6-close-followup, ADR-024) ---
    # Optional/nullable; columns-ready posture per Path A.
    # Pydantic ingest schema + CompletionsConsumer extension deferred to a
    # future findings-ingest task per ADR-024 "Python ingest scope" subsection.
    references: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    additional_cwes: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    # --- Evidence: web / API (DAST, API tools) ---
    target_url: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    request: Mapped[str | None] = mapped_column(Text, nullable=True)  # 4KB truncated by tool
    response: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Evidence: source code (SAST, SCA) ---
    code_file: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    code_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Evidence: mobile (MobSF) ---
    mobile_os: Mapped[MobileOS | None] = mapped_column(
        Enum(MobileOS, name="mobile_os"), nullable=True
    )
    mobile_permission: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mobile_component_name: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # --- Evidence: SSL/TLS (SSLyze) ---
    cipher_suite: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cert_subject: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # --- Metadata ---
    raw_output_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )

    # --- ADDENDUM-TOOLS-5 §8: trufflehog verified-secret flag ---
    # NULL   → not a secret finding
    # TRUE   → trufflehog verified the credential is currently live (rotate NOW)
    # FALSE  → pattern-matched only (Gitleaks or trufflehog unverified)
    secret_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    # --- ADR-029 M9.0 AI pipeline foundation (Q6 Phase-6 promotion state) ---
    # Set when this raw finding is promoted into a Vulnerability (M9.A activation
    # populates these; M9.0 only adds the columns). Enables idempotent re-promotion
    # + orphan detection.
    promoted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    vulnerability_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
