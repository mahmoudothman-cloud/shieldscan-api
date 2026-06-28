"""CWE parent-child hierarchy for the correlation algorithm (ADR-031 Q5).

A curated top-~50 web-app CWE coverage based on the MITRE CWE-1000 Research View.
Forward-pin: embedded MITRE CWE library at production-readiness when CWE diversity
exceeds the hardcoded coverage (per ADR-031 §Rejected Alternatives — embed data
file / pip library both deferred for pre-launch scale).
"""

from __future__ import annotations

from collections import defaultdict

# Curated CWE parent → children relationships (MITRE CWE-1000 Research View).
# Used by correlation_score (ADR-031 Q1) for the cwe_parent 0.25 weight when two
# findings share a parent/child CWE (but not an exact CWE — see is_parent_child).
CWE_PARENT_CHILD: dict[str, set[str]] = {
    # Injection family (CWE-74 root)
    "CWE-74": {"CWE-89", "CWE-78", "CWE-79", "CWE-94", "CWE-91", "CWE-90", "CWE-643"},
    "CWE-89": {"CWE-943"},  # SQL injection → query-language-specific
    "CWE-79": {
        "CWE-80",
        "CWE-81",
        "CWE-83",
        "CWE-84",
        "CWE-87",
    },  # XSS variants
    "CWE-94": {"CWE-95", "CWE-96", "CWE-97", "CWE-98"},  # code injection variants
    # Path traversal (CWE-22 root)
    "CWE-22": {"CWE-23", "CWE-24", "CWE-25", "CWE-36", "CWE-37"},
    # Authentication (CWE-287 root)
    "CWE-287": {
        "CWE-256",
        "CWE-259",
        "CWE-262",
        "CWE-307",
        "CWE-521",
        "CWE-620",
    },
    # Authorization / access control (CWE-285 root)
    "CWE-285": {"CWE-862", "CWE-863", "CWE-732", "CWE-639"},
    # Information exposure (CWE-200 root)
    "CWE-200": {"CWE-201", "CWE-202", "CWE-203", "CWE-209", "CWE-215", "CWE-538"},
    # Cryptographic issues (CWE-310 root)
    "CWE-310": {"CWE-311", "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-916"},
    # SSRF (CWE-918), CSRF (CWE-352), deserialization (CWE-502) — common web roots
    "CWE-913": {"CWE-915", "CWE-470"},
}


class CWEHierarchy:
    """Curated CWE parent-child lookup for ShieldScan-likely vulnerabilities.

    Holds the parent→children map plus a pre-computed reverse (child→parents) map
    so ``is_parent_child`` is an O(1) set membership check in either direction.
    """

    def __init__(self, parent_child_map: dict[str, set[str]] | None = None) -> None:
        self._parent_child = parent_child_map or CWE_PARENT_CHILD
        # Pre-compute the reverse map for child → parent lookups.
        self._child_parent: dict[str, set[str]] = defaultdict(set)
        for parent, children in self._parent_child.items():
            for child in children:
                self._child_parent[child].add(parent)

    def is_parent_child(self, cwe_a: str | None, cwe_b: str | None) -> bool:
        """True if cwe_a and cwe_b are in a parent-child relationship (either way).

        Returns False for None inputs or identical CWE ids — the caller scores an
        exact CWE match separately (cwe_exact 0.40 vs cwe_parent 0.25).
        """
        if not cwe_a or not cwe_b or cwe_a == cwe_b:
            return False
        if cwe_b in self._parent_child.get(cwe_a, set()):
            return True
        if cwe_a in self._parent_child.get(cwe_b, set()):
            return True
        return False


# Module-level singleton accessor (Q7-M9.0 D.a pattern, mirrors clients.py).
_cwe_hierarchy_singleton: CWEHierarchy | None = None


def get_cwe_hierarchy() -> CWEHierarchy:
    """Return the process-wide CWEHierarchy singleton (lazy-constructed)."""
    global _cwe_hierarchy_singleton
    if _cwe_hierarchy_singleton is None:
        _cwe_hierarchy_singleton = CWEHierarchy()
    return _cwe_hierarchy_singleton
