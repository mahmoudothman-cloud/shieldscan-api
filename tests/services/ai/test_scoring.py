"""Unit tests for the severity scoring formula (ADR-031 Q9-Q11; SPEC §8.3).

Pure-function coverage: multiplicative composition + 10.0 cap + default base_cvss,
corroboration multiplier (engine-distinct count), exploitability multiplier
(PoC-derivation via tool_name per PY5 V-UUE), and the CVSS band → enum mapping.
"""

from __future__ import annotations

import pytest

from app.models.raw_findings import Severity
from app.services.ai.scoring import (
    _map_score_to_severity_enum,
    compute_corroboration_multiplier,
    compute_exploitability_multiplier,
    compute_severity_score,
)


# ---------------------------------------------------------------- compute_severity_score


def test_compute_severity_score_multiplicative_composition():
    score = compute_severity_score(
        base_cvss=5.0, corroboration_multiplier=1.3, exploitability_multiplier=1.2
    )
    assert score == pytest.approx(7.8)


def test_compute_severity_score_caps_at_ten():
    score = compute_severity_score(
        base_cvss=9.8, corroboration_multiplier=1.3, exploitability_multiplier=1.2
    )
    assert score == 10.0  # 9.8 × 1.3 × 1.2 = 15.29 → capped


def test_compute_severity_score_default_base_cvss_when_null():
    # base_cvss None → default 5.0 (Q9); 5.0 × 1.0 × 1.0 = 5.0.
    score = compute_severity_score(
        base_cvss=None, corroboration_multiplier=1.0, exploitability_multiplier=1.0
    )
    assert score == 5.0


def test_compute_severity_score_mid_severity_no_cap():
    score = compute_severity_score(
        base_cvss=5.0, corroboration_multiplier=1.3, exploitability_multiplier=1.0
    )
    assert score == pytest.approx(6.5)  # below cap → meaningful ranking


# ---------------------------------------------------------------- corroboration


def test_compute_corroboration_multiplier_single_engine():
    assert compute_corroboration_multiplier(1) == 1.0


def test_compute_corroboration_multiplier_cross_engine():
    assert compute_corroboration_multiplier(2) == 1.3
    assert compute_corroboration_multiplier(3) == 1.3


# ---------------------------------------------------------------- exploitability (PY5)


def test_compute_exploitability_multiplier_poc_proven_nuclei():
    assert compute_exploitability_multiplier(["nuclei"]) == 1.2


def test_compute_exploitability_multiplier_poc_proven_sqlmap():
    assert compute_exploitability_multiplier(["semgrep", "sqlmap"]) == 1.2


def test_compute_exploitability_multiplier_default_when_not_poc():
    assert compute_exploitability_multiplier(["semgrep", "checkov"]) == 1.0


def test_compute_exploitability_multiplier_default_when_no_tools():
    assert compute_exploitability_multiplier([]) == 1.0


# ---------------------------------------------------------------- CVSS mapping (Q11)


def test_map_score_to_severity_enum_cvss_thresholds():
    assert _map_score_to_severity_enum(9.5) == Severity.CRITICAL
    assert _map_score_to_severity_enum(9.0) == Severity.CRITICAL
    assert _map_score_to_severity_enum(8.2) == Severity.HIGH
    assert _map_score_to_severity_enum(7.0) == Severity.HIGH
    assert _map_score_to_severity_enum(5.0) == Severity.MEDIUM
    assert _map_score_to_severity_enum(4.0) == Severity.MEDIUM
    assert _map_score_to_severity_enum(3.9) == Severity.LOW
    assert _map_score_to_severity_enum(0.0) == Severity.LOW
