"""Tests for app.schemas.raw_findings.RawFindingCreate.

Validates the Pydantic strictness contract from ADR-025:

- Engine wire-format payloads (snake_case JSON, omitempty / Optional
  symmetry) round-trip through validation cleanly.
- Unknown fields are rejected (extra="forbid"); cross-repo schema-
  drift regression guard.
- Required-field omissions raise ValidationError.
- Severity + engine_category Literal enums reject invalid values.
- Mobile field aliases (engine `permission` / `component_name` →
  Python `mobile_permission` / `mobile_component_name`) translate
  correctly.

Reference: ADR-025 (shieldscan-docs SPECIFICATION.md §13);
M6-followup-Phase-0 deviation surface (mobile name mismatch).
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.raw_findings import RawFindingCreate


# ---------------------------------------------------------------- helpers


def _minimal_payload(**overrides) -> dict:
    """Build a minimal valid payload — only the 7 required fields.

    Mirrors the engine wire format (snake_case keys, RFC3339 timestamp).
    """
    base = {
        "tool_name": "nuclei",
        "engine_category": "dast",
        "title": "XSS in q parameter",
        "severity": "high",
        "finding_type": "xss",
        "fingerprint": "deadbeef" * 8,
        "discovered_at": "2026-05-03T12:00:00Z",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------- happy path


def test_minimal_payload_validates() -> None:
    """Only the 7 required fields → validates; all optional fields nil."""
    finding = RawFindingCreate.model_validate(_minimal_payload())
    assert finding.tool_name == "nuclei"
    assert finding.engine_category == "dast"
    assert finding.severity == "high"
    assert finding.references is None
    assert finding.tags is None
    assert finding.cvss_vector is None
    assert finding.additional_cwes is None
    assert finding.target_url is None
    assert finding.mobile_os is None
    assert finding.mobile_permission is None
    assert finding.mobile_component_name is None
    assert finding.secret_verified is None


def test_full_payload_validates() -> None:
    """All fields populated — validates; values preserved verbatim.

    Mirrors the canonical engine fixture
    `internal/events/testdata/job_completed_python_v1.json` (post-§7.3
    Phase 3) finding[0] shape, with mobile + SSL evidence groups added
    for completeness.
    """
    payload = _minimal_payload(
        scan_id=str(uuid4()),
        org_id=str(uuid4()),
        description="Reflected XSS",
        cwe_id="CWE-79",
        owasp="A03:2021",
        cvss_score=7.4,
        target_url="https://app.example.com/search?q=<x>",
        parameter="q",
        payload="<script>",
        request="GET /search?q=...",
        response="HTTP/1.1 200 OK",
        code_file="src/handler.py",
        code_line=42,
        code_snippet="def handle():",
        mobile_os="android",
        permission="android.permission.READ_SMS",  # alias for mobile_permission
        component_name="com.example.LoginActivity",  # alias for mobile_component_name
        cipher_suite="TLS_AES_256_GCM_SHA384",
        cert_subject="CN=example.com",
        raw_output_ref="r2://findings/scn_x/job_y.jsonl",
        secret_verified=True,
    )
    finding = RawFindingCreate.model_validate(payload)
    assert finding.cvss_score == 7.4
    assert finding.code_line == 42
    assert finding.mobile_os == "android"
    # Alias translation: wire `permission` → Python `mobile_permission`.
    assert finding.mobile_permission == "android.permission.READ_SMS"
    assert finding.mobile_component_name == "com.example.LoginActivity"
    assert finding.secret_verified is True


def test_spec_73_extension_fields_validate() -> None:
    """SPEC §7.3 schema extension fields (References, Tags, CVSSVector,
    AdditionalCWEs) accept their canonical engine-emitted shapes.

    Mirrors the canonical engine fixture finding[0] post-§7.3 Phase 3.
    Load-bearing for ADR-024's M9 §8.2 forward-pin: AdditionalCWEs is
    the multi-CWE-intersection container.
    """
    payload = _minimal_payload(
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
            "https://example.com/advisory/2024-001",
        ],
        tags=["xss", "owasp-top-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        additional_cwes=["CWE-20", "CWE-78"],
    )
    finding = RawFindingCreate.model_validate(payload)
    assert finding.references == [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        "https://example.com/advisory/2024-001",
    ]
    assert finding.tags == ["xss", "owasp-top-10"]
    assert finding.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert finding.additional_cwes == ["CWE-20", "CWE-78"]


# ---------------------------------------------------------------- strict rejection


def test_unknown_field_rejected() -> None:
    """extra="forbid" rejects unknown fields — cross-repo schema-drift
    regression guard per ADR-025.

    If the engine adds a field without a synchronized Pydantic update,
    ingest fails fast at validation rather than silently dropping data.
    """
    payload = _minimal_payload(future_engine_field="some-value")
    with pytest.raises(ValidationError) as excinfo:
        RawFindingCreate.model_validate(payload)
    assert "future_engine_field" in str(excinfo.value)


def test_severity_enum_violation() -> None:
    """Invalid severity raises ValidationError — Literal enum strictness."""
    payload = _minimal_payload(severity="Critical")  # uppercase invalid
    with pytest.raises(ValidationError) as excinfo:
        RawFindingCreate.model_validate(payload)
    assert "severity" in str(excinfo.value)


def test_engine_category_enum_violation() -> None:
    """Invalid engine_category raises ValidationError — Literal enum
    must match SPEC §5.3 exactly.
    """
    payload = _minimal_payload(engine_category="DAST")  # uppercase invalid
    with pytest.raises(ValidationError) as excinfo:
        RawFindingCreate.model_validate(payload)
    assert "engine_category" in str(excinfo.value)


def test_missing_required_field() -> None:
    """Omitting a required field (tool_name) raises ValidationError."""
    payload = _minimal_payload()
    del payload["tool_name"]
    with pytest.raises(ValidationError) as excinfo:
        RawFindingCreate.model_validate(payload)
    assert "tool_name" in str(excinfo.value)


# ---------------------------------------------------------------- engine wire-format symmetry


def test_omitempty_engine_emission_validates() -> None:
    """Engine emissions WITHOUT optional fields (omitempty drops them)
    must validate cleanly — the omitempty/Optional symmetry contract
    that ADR-024 + ADR-025 jointly maintain.

    This is the inverse of test_unknown_field_rejected: engine omits
    fields → Python accepts; engine adds unknown fields → Python rejects.
    """
    # Pre-§7.3 wire shape (no references/tags/cvss_vector/additional_cwes
    # keys at all). Should validate without error; the 4 new fields
    # default to None.
    payload = _minimal_payload()
    assert "references" not in payload
    assert "tags" not in payload
    assert "cvss_vector" not in payload
    assert "additional_cwes" not in payload
    finding = RawFindingCreate.model_validate(payload)
    assert finding.references is None
    assert finding.tags is None
    assert finding.cvss_vector is None
    assert finding.additional_cwes is None


def test_discovered_at_iso8601_parses() -> None:
    """discovered_at accepts ISO8601 string → datetime conversion."""
    payload = _minimal_payload(discovered_at="2026-05-03T14:34:27.123Z")
    finding = RawFindingCreate.model_validate(payload)
    assert isinstance(finding.discovered_at, datetime)
    assert finding.discovered_at.tzinfo is not None
