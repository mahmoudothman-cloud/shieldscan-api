"""Severity scoring formula (ADR-031 Q9-Q11; SPEC §8.3).

final_score = base_cvss × corroboration_multiplier × exploitability_multiplier,
capped at 10.0. Pure + sync (no DB/AI). The C2 pipeline integration derives the
distinct-engine count + contributing tool names from the correlation cluster,
calls compute_severity_score per Vulnerability, and maps the result to the enum.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.models.raw_findings import Severity

# PoC-proven tools (Q10 + PY5 V-UUE pre-grounding): matched against
# RawFinding.tool_name — NOT engine_name, which does not exist on the model.
POC_PROVEN_TOOL_NAMES: frozenset[str] = frozenset({"nuclei", "sqlmap"})

_DEFAULT_BASE_CVSS = 5.0  # Q9: medium default when the asserted severity is unknown
_MAX_SEVERITY_SCORE = 10.0

# Asserted-severity → base CVSS.
#
# Scanners assert risk qualitatively (ZAP Risk, nuclei severity, the sslyze rule
# table) and almost never emit a CVSS vector: cvss_score is null on nearly every
# raw finding. Feeding the flat _DEFAULT_BASE_CVSS into compute_severity_score
# collapsed every scored Vulnerability onto ~5.0 → MEDIUM, erasing the tools'
# own severity assertions from the report. Mapping the asserted severity onto the
# CVSS scale keeps the multiplier formula meaningful when real CVSS is absent.
#
# The values are chosen against _CVSS_SEVERITY_BANDS so that a SINGLE multiplier
# cannot move a finding out of its asserted tier (7.0 × 1.2 = 8.4, still HIGH),
# while cross-engine corroboration — the signal worth promoting on — can
# (7.0 × 1.3 × 1.2 → capped 10.0 → CRITICAL).
_SEVERITY_BASE_CVSS: dict[Severity, float] = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}

# SPEC §8.3 corroboration multipliers (Q12: engine-distinct count within cluster).
_CORROBORATION_SINGLE = 1.0
_CORROBORATION_MULTI = 1.3  # corroborated by 2+ engines (DAST + SAST)

# Standard CVSS band → Severity enum (Q11), highest band first.
#
# The LOW floor is 2.0 (not 0.0) so INFO is reachable in scored output. With the
# original 4/0 floors anything under 4.0 became LOW and an INFO finding could not
# survive scoring — which in turn made INFO-based filtering downstream impossible.
_CVSS_SEVERITY_BANDS: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (2.0, Severity.LOW),
    (0.0, Severity.INFO),
)


def base_cvss_for(
    cvss_score: float | None, asserted_severity: Severity | None
) -> float:
    """Resolve the scoring base for one finding (SPEC §8.3 base_cvss).

    Precedence: a real CVSS score when the tool emitted one → the base derived
    from the tool's asserted severity → _DEFAULT_BASE_CVSS for an unknown
    severity. Never returns None, so compute_severity_score's own null-default is
    only reachable by direct callers.
    """
    if cvss_score is not None:
        return cvss_score
    if asserted_severity is not None:
        return _SEVERITY_BASE_CVSS.get(asserted_severity, _DEFAULT_BASE_CVSS)
    return _DEFAULT_BASE_CVSS


def compute_corroboration_multiplier(engine_count: int) -> float:
    """SPEC §8.3 corroboration multiplier from the cluster's distinct-engine count.

    1.0 for a single engine; 1.3 for 2+ engines. The 1.5 production-facing tier is
    forward-pinned (Q10) — production-facing detection metadata is not captured at
    M9.B.
    """
    return _CORROBORATION_MULTI if engine_count >= 2 else _CORROBORATION_SINGLE


def compute_exploitability_multiplier(tool_names: Iterable[str]) -> float:
    """SPEC §8.3 exploitability multiplier (Q10 D hybrid).

    1.2 when any contributing tool proved exploitability (Nuclei/SQLMap PoC per
    RawFinding.tool_name); otherwise 1.0. The 0.8 (auth-only) and 1.5
    (public+unauth) tiers default to 1.0 at M9.B — URL heuristics are insufficient;
    forward-pinned to M9.C/D + production-readiness.
    """
    if any(name and name.lower() in POC_PROVEN_TOOL_NAMES for name in tool_names):
        return 1.2
    return 1.0


def compute_severity_score(
    *,
    base_cvss: float | None,
    corroboration_multiplier: float,
    exploitability_multiplier: float,
) -> float:
    """SPEC §8.3 final_score = base_cvss × corroboration × exploitability (Q9).

    base_cvss defaults to 5.0 when null; the result is capped at 10.0 to preserve
    CVSS-scale semantics.
    """
    base = base_cvss if base_cvss is not None else _DEFAULT_BASE_CVSS
    score = base * corroboration_multiplier * exploitability_multiplier
    return min(score, _MAX_SEVERITY_SCORE)


def _map_score_to_severity_enum(score: float) -> Severity:
    """Map a numeric severity_score to the Severity enum (Q11 standard CVSS bands)."""
    for threshold, severity in _CVSS_SEVERITY_BANDS:
        if score >= threshold:
            return severity
    return Severity.INFO  # unreachable for score >= 0 (the 0.0 band catches it)
