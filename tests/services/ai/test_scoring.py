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
    base_cvss_for,
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
    assert _map_score_to_severity_enum(2.0) == Severity.LOW


def test_map_score_to_severity_enum_info_is_reachable():
    """INFO must be representable in scored output.

    With the original 4/0 band floors, everything under 4.0 became LOW and no
    score could ever map to INFO — which made INFO-based downstream filtering
    (e.g. excluding observations from fix generation) impossible.
    """
    assert _map_score_to_severity_enum(1.9) == Severity.INFO
    assert _map_score_to_severity_enum(1.0) == Severity.INFO
    assert _map_score_to_severity_enum(0.0) == Severity.INFO


# ---------------------------------------------------------------- base_cvss_for


def test_base_cvss_for_prefers_real_cvss_over_asserted_severity():
    # A tool that DID emit a CVSS vector wins over the severity-derived base.
    assert base_cvss_for(9.8, Severity.LOW) == 9.8
    assert base_cvss_for(0.0, Severity.CRITICAL) == 0.0  # 0.0 is a value, not null


def test_base_cvss_for_derives_from_asserted_severity_when_cvss_null():
    assert base_cvss_for(None, Severity.CRITICAL) == 9.0
    assert base_cvss_for(None, Severity.HIGH) == 7.0
    assert base_cvss_for(None, Severity.MEDIUM) == 5.0
    assert base_cvss_for(None, Severity.LOW) == 3.0
    assert base_cvss_for(None, Severity.INFO) == 1.0


def test_base_cvss_for_falls_back_to_default_when_severity_unknown():
    assert base_cvss_for(None, None) == 5.0


# ------------------------------------------------- band-preservation invariants


@pytest.mark.parametrize(
    "asserted",
    [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ],
)
def test_single_multiplier_cannot_change_asserted_tier(asserted):
    """A lone exploitability bump (1.2) must not promote across a band.

    The base values are chosen against the band floors precisely so that one
    multiplier refines the ranking WITHIN a tier without overriding what the tool
    asserted — e.g. 7.0 × 1.2 = 8.4, still HIGH.
    """
    score = compute_severity_score(
        base_cvss=base_cvss_for(None, asserted),
        corroboration_multiplier=1.0,
        exploitability_multiplier=1.2,
    )
    assert _map_score_to_severity_enum(score) == asserted


def test_high_with_poc_stays_high():
    score = compute_severity_score(
        base_cvss=base_cvss_for(None, Severity.HIGH),
        corroboration_multiplier=1.0,
        exploitability_multiplier=1.2,
    )
    assert score == pytest.approx(8.4)
    assert _map_score_to_severity_enum(score) == Severity.HIGH


def test_cross_engine_corroboration_can_promote_high_to_critical():
    """Corroboration IS the signal worth promoting on: 7.0 × 1.3 × 1.2 → 10.0."""
    score = compute_severity_score(
        base_cvss=base_cvss_for(None, Severity.HIGH),
        corroboration_multiplier=1.3,
        exploitability_multiplier=1.2,
    )
    assert score == 10.0  # 10.92 → capped
    assert _map_score_to_severity_enum(score) == Severity.CRITICAL


def test_asserted_severities_do_not_all_collapse_to_medium():
    """Regression: the flat default erased every tool's severity assertion.

    38 of 39 raw findings on a live scan carried no CVSS, so every scored
    Vulnerability landed on 5.0 → MEDIUM and the report had zero differentiation.
    """
    scored = {
        asserted: _map_score_to_severity_enum(
            compute_severity_score(
                base_cvss=base_cvss_for(None, asserted),
                corroboration_multiplier=1.0,
                exploitability_multiplier=1.0,
            )
        )
        for asserted in Severity
    }
    assert scored == {s: s for s in Severity}
