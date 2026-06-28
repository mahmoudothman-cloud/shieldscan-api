"""Cross-layer correlation algorithm (ADR-031 Q1-Q8; SPEC §8.2).

Rule-based weighted scoring over Vulnerability pairs of differing engine_category
(DAST↔SAST, cross-engine generalised). Pure + sync (no DB, no AI per Q1 D.a); the
C2 pipeline integration loads the scan's Vulnerabilities, builds the route_map,
scores cross-engine pairs, and assigns correlation_cluster_id via union-find.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Sequence
from itertools import combinations
from urllib.parse import urlparse
from uuid import UUID

from app.models.vulnerabilities import Vulnerability
from app.services.ai.cwe_hierarchy import CWEHierarchy, get_cwe_hierarchy

# SPEC §8.2 canonical correlation weights + threshold.
CORRELATION_WEIGHTS: dict[str, float] = {
    "cwe_exact": 0.40,
    "cwe_parent": 0.25,
    "url_path": 0.20,
    "finding_type": 0.30,
    "parameter_name": 0.15,
}
CORRELATION_THRESHOLD = 0.75  # ≥ → correlated (Q1)

# Multi-language parameter-binding regexes (Q7 B.b'): Flask/Werkzeug, Django named
# groups, FastAPI/Starlette path params, Express, Spring annotations.
_PARAM_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<(?:\w+:)?(\w+)>"),  # Flask/Werkzeug <int:id>
    re.compile(r"\(\?P<(\w+)>"),  # Django named group
    re.compile(r"\{(\w+)\}"),  # FastAPI/Starlette {id}
    re.compile(r"req\.(?:params|query|body)\.(\w+)"),  # Express
    re.compile(r"@(?:RequestParam|PathVariable)[^)]*?\b(\w+)\s*[,)]"),  # Spring
)
_MIN_PARAM_LEN = 3
_IGNORED_PATH_SEGMENTS = {"api", "v1", "v2", "v3", ""}


def _normalize_param(name: str) -> str:
    """Lowercase + strip to alphanumerics (Q7 C.b normalized comparison)."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def extract_params_from_url(url: str | None) -> set[str]:
    """Extract normalized query-parameter names from a URL (Q7 A.c')."""
    if not url:
        return set()
    parsed = urlparse(url)
    params: set[str] = set()
    if parsed.query:
        for pair in parsed.query.split("&"):
            norm = _normalize_param(pair.split("=", 1)[0])
            if len(norm) >= _MIN_PARAM_LEN:
                params.add(norm)
    return params


def extract_params_from_snippet(snippet: str | None) -> set[str]:
    """Extract parameter names from a code snippet via multi-language regex (Q7 B.b')."""
    if not snippet:
        return set()
    params: set[str] = set()
    for pattern in _PARAM_PATTERNS:
        for match in pattern.findall(snippet):
            norm = _normalize_param(match)
            if len(norm) >= _MIN_PARAM_LEN:
                params.add(norm)
    return params


def _extract_params_combined(
    *, target_url: str | None, parameter: str | None, code_snippet: str | None
) -> set[str]:
    """Union of URL query params + the explicit parameter + snippet params (Q7)."""
    params = extract_params_from_url(target_url)
    if parameter:
        norm = _normalize_param(parameter)
        if len(norm) >= _MIN_PARAM_LEN:
            params.add(norm)
    params |= extract_params_from_snippet(code_snippet)
    return params


def build_route_map(vulnerabilities: Iterable[Vulnerability]) -> dict[str, str]:
    """Heuristic 1-to-1 URL-path ↔ code_file map (Q6).

    Maps a URL path to a code_file when the path's last meaningful segment matches
    a code_file basename (sans extension). Conservative: a basename shared by >1
    code_file is ambiguous and skipped, minimising false positives.
    """
    vulns = list(vulnerabilities)
    basename_index: dict[str, set[str]] = {}
    for cf in {v.code_file for v in vulns if v.code_file}:
        base = cf.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
        basename_index.setdefault(base, set()).add(cf)

    route_map: dict[str, str] = {}
    for path in {urlparse(v.target_url).path for v in vulns if v.target_url}:
        segments = [s for s in path.lower().split("/") if s not in _IGNORED_PATH_SEGMENTS]
        if not segments:
            continue
        matches = basename_index.get(segments[-1])
        if matches and len(matches) == 1:
            route_map[path] = next(iter(matches))
    return route_map


def _check_url_path_match(
    vuln_a: Vulnerability, vuln_b: Vulnerability, route_map: dict[str, str]
) -> bool:
    """Asymmetric url_path match tried both directions (Q4 max-not-sum).

    A DAST URL path may map (via route_map) to a SAST code_file. Tried a→b and
    b→a; either direction counts once.
    """
    if vuln_a.target_url and vuln_b.code_file:
        if route_map.get(urlparse(vuln_a.target_url).path) == vuln_b.code_file:
            return True
    if vuln_b.target_url and vuln_a.code_file:
        if route_map.get(urlparse(vuln_b.target_url).path) == vuln_a.code_file:
            return True
    return False


def correlation_score(
    vuln_a: Vulnerability,
    vuln_b: Vulnerability,
    *,
    route_map: dict[str, str],
    cwe_hierarchy: CWEHierarchy | None = None,
    snippet_a: str | None = None,
    snippet_b: str | None = None,
) -> float:
    """SPEC §8.2 weighted correlation score for a Vulnerability pair (Q1 + Q4).

    Sync + pure (Q1 D.a). Neutral naming (vuln_a/vuln_b) generalises across
    engine_categories. snippet_a/snippet_b are optional code snippets the caller
    may load from raw_findings for richer parameter extraction (Vulnerability rows
    carry no snippet).
    """
    hierarchy = cwe_hierarchy or get_cwe_hierarchy()
    score = 0.0

    # CWE: exact (0.40) takes precedence over parent/child (0.25); never both.
    if vuln_a.cwe_id and vuln_b.cwe_id and vuln_a.cwe_id == vuln_b.cwe_id:
        score += CORRELATION_WEIGHTS["cwe_exact"]
    elif hierarchy.is_parent_child(vuln_a.cwe_id, vuln_b.cwe_id):
        score += CORRELATION_WEIGHTS["cwe_parent"]

    if vuln_a.finding_type == vuln_b.finding_type:
        score += CORRELATION_WEIGHTS["finding_type"]

    if _check_url_path_match(vuln_a, vuln_b, route_map):
        score += CORRELATION_WEIGHTS["url_path"]

    params_a = _extract_params_combined(
        target_url=vuln_a.target_url, parameter=vuln_a.parameter, code_snippet=snippet_a
    )
    params_b = _extract_params_combined(
        target_url=vuln_b.target_url, parameter=vuln_b.parameter, code_snippet=snippet_b
    )
    if params_a & params_b:
        score += CORRELATION_WEIGHTS["parameter_name"]

    return score


def iter_cross_engine_pairs(
    vulnerabilities: Sequence[Vulnerability],
) -> Iterator[tuple[Vulnerability, Vulnerability]]:
    """Yield unordered Vulnerability pairs with differing engine_category (Q2 + Q4).

    itertools.combinations over the scan's Vulnerabilities; same-engine pairs are
    skipped (M9.A clustering already owns within-engine dedup).
    """
    for vuln_a, vuln_b in combinations(vulnerabilities, 2):
        if vuln_a.engine_category != vuln_b.engine_category:
            yield vuln_a, vuln_b


def union_find_clusters(
    vulnerabilities: Sequence[Vulnerability],
    correlated_pairs: Iterable[tuple[Vulnerability, Vulnerability]],
) -> dict[UUID, list[Vulnerability]]:
    """Group Vulnerabilities into clusters via union-find (Q8 transitive).

    A↔B + B↔C → {A, B, C} in one cluster (path compression). Returns
    {cluster-root vuln id → member Vulnerabilities}; only multi-member clusters
    (≥1 correlated pair) are returned.
    """
    parent: dict[UUID, UUID] = {v.id: v.id for v in vulnerabilities}

    def find(x: UUID) -> UUID:
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:  # path compression
            parent[x], x = root, parent[x]
        return root

    for vuln_a, vuln_b in correlated_pairs:
        parent[find(vuln_a.id)] = find(vuln_b.id)

    by_id = {v.id: v for v in vulnerabilities}
    grouped: dict[UUID, list[UUID]] = {}
    for vuln_id in parent:
        grouped.setdefault(find(vuln_id), []).append(vuln_id)
    return {
        root: [by_id[m] for m in members]
        for root, members in grouped.items()
        if len(members) > 1
    }
