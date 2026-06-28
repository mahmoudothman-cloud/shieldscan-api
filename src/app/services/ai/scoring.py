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

_DEFAULT_BASE_CVSS = 5.0  # Q9: medium default when cvss_score is null
_MAX_SEVERITY_SCORE = 10.0

# SPEC §8.3 corroboration multipliers (Q12: engine-distinct count within cluster).
_CORROBORATION_SINGLE = 1.0
_CORROBORATION_MULTI = 1.3  # corroborated by 2+ engines (DAST + SAST)

# Standard CVSS band → Severity enum (Q11), highest band first.
_CVSS_SEVERITY_BANDS: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.0, Severity.LOW),
)


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
    return Severity.LOW
