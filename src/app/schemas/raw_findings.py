"""Pydantic schemas for the RawFinding ingest path.

Mirrors the SQLAlchemy model ``app.models.raw_findings.RawFinding``
(post-Phase-2 of M6-close-followup, including the 4 SPEC §7.3
extension fields per ADR-024). Used by ``CompletionsConsumer`` to
validate ``event["findings"]`` entries before bulk-insert into the
``raw_findings`` table.

**Cross-repo wire-format invariant (load-bearing).** ``model_config
= ConfigDict(extra="forbid")`` mirrors the engine-side
``DisallowUnknownFields`` discipline (per
``shieldscan-engine/internal/events/events.go`` line 12-13). If the
engine adds a field to ``RawFinding`` without a synchronized Pydantic
schema update, ingest will reject the payload at the
CompletionsConsumer layer — a forcing-function regression guard
against silent cross-repo schema drift. Same shape as ADR-024's
synchronized extension workflow (Engine struct → Python schema).

**Field-name aliases for engine ↔ model deltas.** A handful of
fields differ in name between engine wire format and Python model:

- Engine ``permission`` → Python ``mobile_permission``
- Engine ``component_name`` → Python ``mobile_component_name``
- Engine ``org_id`` (per-finding) → ignored at insert time; the
  authoritative org scope comes from ``scan_job.organization_id``
  per the RLS-grounded lookup chain in CompletionsConsumer.

Pydantic ``Field(alias=...)`` + ``populate_by_name=True`` handles
the wire-to-Python translation; engine emissions validate without
adapter shims at the consumer layer.

**ScanID + OrgID per-finding semantics.** Both are populated by the
engine processor (per ``events.go`` Run() docstring lines 71-72) but
the consumer ignores them at insert time — see Lean A on Deviation 1
in the M6-followup-Phase-0 surface (RawFinding has no ``job_id``
column; per-finding ``scan_id``/``org_id`` are derived from
``scan_job`` for atomicity guarantees). Including them in the schema
is required only because ``extra="forbid"`` would otherwise reject
them on the wire.

**References:**
- ADR-013 — Python sole writer (atomicity invariant for findings ingest)
- ADR-017 — Findings inline + sequencing (this schema validates the
  per-finding wire-format payload)
- ADR-024 — RawFinding schema extension (4 fields below; columns-ready
  posture closed by the consumer commit alongside this schema)
- ADR-025 (shieldscan-docs §13) — Pydantic strictness decision +
  this implementation
- SPEC §7.3 — Job Completion wire format (canonical RawFinding shape)
- SPEC §5.3 — engine_category enum (mirrored in the Literal below)
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# Type aliases for the Literal enums; mirrors SQLAlchemy Enum constraints.
Severity = Literal["critical", "high", "medium", "low", "info"]
EngineCategory = Literal[
    "dast",
    "sast",
    "sca",
    "mobile",
    "infrastructure",
    "recon",
    "ssl",
    "api",
    "iac",
    "secrets",
    "container",
    "spa",
    "discovery",
]
MobileOS = Literal["android", "ios"]


class RawFindingCreate(BaseModel):
    """Pydantic schema for one entry in a ``job_completed`` event's
    ``findings`` array.

    Validation contract:

    - **Required:** ``tool_name``, ``engine_category``, ``title``,
      ``severity``, ``finding_type``, ``fingerprint``, ``discovered_at``.
      Engine ``NativeRunner.Run`` enriches ``DiscoveredAt`` and
      ``Fingerprint`` post-parse (per ``events.go`` Run docstring) so
      every emitted finding carries them in practice.

    - **Optional:** all evidence groups (web/source/mobile/SSL),
      classification details (``cwe_id``, ``owasp``, ``cvss_score``),
      metadata (``raw_output_ref``, ``secret_verified``), the 4
      SPEC §7.3 extension fields (``references``, ``tags``,
      ``cvss_vector``, ``additional_cwes``).

    - **Strict:** ``extra="forbid"`` rejects unknown fields; mirrors
      engine ``DisallowUnknownFields``. Cross-repo drift surfaces at
      ingest, not silently in production.

    - **Engine-populated, consumer-ignored:** ``scan_id``, ``org_id``.
      Accepted on the wire (extra="forbid" forces inclusion) but
      discarded during ``finding_dicts`` assembly — the consumer
      uses ``scan_job.organization_id`` and ``scan_job.scan_id`` as
      the authoritative scope per the RLS-grounded lookup chain.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        populate_by_name=True,
    )

    # --- Identity (required) ---
    tool_name: str
    engine_category: EngineCategory

    # --- Identity (engine-populated, consumer-ignored at insert) ---
    # Accepted only because extra="forbid" would reject otherwise.
    # The consumer derives the authoritative scan/org scope from
    # scan_job, not from the per-finding payload (Lean A on
    # M6-followup-Phase-0 Deviation 1; RawFinding has no job_id column,
    # and per-finding org_id is redundant with the event-level org).
    scan_id: Optional[UUID] = None
    org_id: Optional[UUID] = None

    # --- Classification ---
    title: str
    description: Optional[str] = None
    severity: Severity
    finding_type: str
    cwe_id: Optional[str] = None
    owasp: Optional[str] = None
    cvss_score: Optional[float] = None

    # --- Evidence: web / API (DAST, API tools) ---
    target_url: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None

    # --- Evidence: source code (SAST, SCA) ---
    code_file: Optional[str] = None
    code_line: Optional[int] = None
    code_snippet: Optional[str] = None

    # --- Evidence: mobile (MobSF) ---
    # Engine wire JSON keys are bare (`permission`, `component_name`);
    # Python model uses `mobile_` prefix. Pydantic Field(alias=...)
    # bridges the two without an adapter shim at the consumer layer.
    mobile_os: Optional[MobileOS] = None
    mobile_permission: Optional[str] = Field(default=None, alias="permission")
    mobile_component_name: Optional[str] = Field(
        default=None, alias="component_name"
    )

    # --- Evidence: SSL/TLS (SSLyze) ---
    cipher_suite: Optional[str] = None
    cert_subject: Optional[str] = None

    # --- Categorical (SPEC §7.3 schema extension; ADR-024) ---
    # Optional/nullable on both sides (Engine omitempty + Python
    # Optional). Empty/absent values do not appear on the wire.
    references: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    cvss_vector: Optional[str] = None
    additional_cwes: Optional[list[str]] = None

    # --- Metadata ---
    # Engine wire key is `metadata` (RawFinding.Metadata, map[string]string);
    # Python model column is `tool_metadata` (`metadata` is reserved on
    # SQLAlchemy Declarative classes). Field(alias="metadata") bridges the
    # two, mirroring the mobile_* alias pattern above. Opening this field is
    # what lets nmap/zap/mobsf/trivy pass extra="forbid" ingest at all.
    tool_metadata: Optional[dict[str, str]] = Field(default=None, alias="metadata")
    raw_output_ref: Optional[str] = None
    discovered_at: datetime
    fingerprint: str

    # --- ADDENDUM-TOOLS-5 §8 (trufflehog verified-secret flag) ---
    secret_verified: Optional[bool] = None
