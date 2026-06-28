"""Unit tests for the correlation algorithm (ADR-031 Q1-Q8; SPEC §8.2).

Pure-function coverage via lightweight attribute objects (no DB): correlation_score
weights + threshold + symmetry + max-not-sum, cross-engine pair iteration,
union-find clustering, route_map construction, and parameter extraction.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from app.models.raw_findings import EngineCategory
from app.services.ai.correlation import (
    CORRELATION_THRESHOLD,
    build_route_map,
    correlation_score,
    extract_params_from_snippet,
    extract_params_from_url,
    iter_cross_engine_pairs,
    union_find_clusters,
)


def _obj(**kw):
    base = dict(
        id=uuid4(),
        engine_category=EngineCategory.DAST,
        cwe_id="CWE-89",
        finding_type="sqli",
        target_url=None,
        parameter=None,
        code_file=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


# ---------------------------------------------------------------- correlation_score


def test_correlation_score_exact_cwe_finding_type_param_matches_above_threshold():
    a = _obj(parameter="userid")
    b = _obj(engine_category=EngineCategory.SAST, parameter="userid")
    score = correlation_score(a, b, route_map={})
    # cwe_exact 0.40 + finding_type 0.30 + parameter_name 0.15 = 0.85.
    assert score >= CORRELATION_THRESHOLD
    assert score == 0.85


def test_correlation_score_distinct_cwe_below_threshold():
    a = _obj(cwe_id="CWE-89", finding_type="sqli", parameter="userid")
    b = _obj(
        engine_category=EngineCategory.SAST,
        cwe_id="CWE-352",
        finding_type="csrf",
        parameter="token",
    )
    assert correlation_score(a, b, route_map={}) < CORRELATION_THRESHOLD


def test_correlation_score_cwe_parent_child_partial_weight():
    # CWE-74 (parent) ↔ CWE-89 (child); distinct finding_type + no param isolates
    # the cwe_parent 0.25 weight (not cwe_exact 0.40).
    a = _obj(cwe_id="CWE-74", finding_type="injection")
    b = _obj(engine_category=EngineCategory.SAST, cwe_id="CWE-89", finding_type="sqli")
    assert correlation_score(a, b, route_map={}) == 0.25


def test_correlation_score_symmetric_pair_order():
    a = _obj(parameter="userid")
    b = _obj(engine_category=EngineCategory.SAST, parameter="userid")
    assert correlation_score(a, b, route_map={}) == correlation_score(
        b, a, route_map={}
    )


def test_correlation_score_asymmetric_url_path_max_not_sum():
    # Both directions would match the route_map; url_path must count once (0.20),
    # never 0.40. Distinct CWE + finding_type + no param isolates url_path.
    a = _obj(
        cwe_id="CWE-89", finding_type="sqli",
        target_url="https://x.com/users", code_file="routes/users.py",
    )
    b = _obj(
        engine_category=EngineCategory.SAST, cwe_id="CWE-22", finding_type="lfi",
        target_url="https://x.com/users", code_file="routes/users.py",
    )
    route_map = {"/users": "routes/users.py"}
    assert correlation_score(a, b, route_map=route_map) == 0.20


def test_correlation_score_zero_when_all_attributes_distinct():
    a = _obj(cwe_id="CWE-89", finding_type="sqli", parameter="userid")
    b = _obj(
        engine_category=EngineCategory.SAST,
        cwe_id="CWE-79", finding_type="xss", parameter="comment",
    )
    assert correlation_score(a, b, route_map={}) == 0.0


# ---------------------------------------------------------------- pair iteration


def test_iter_cross_engine_pairs_yields_only_cross_engine():
    d1 = _obj(engine_category=EngineCategory.DAST)
    s1 = _obj(engine_category=EngineCategory.SAST)
    d2 = _obj(engine_category=EngineCategory.DAST)
    pairs = list(iter_cross_engine_pairs([d1, s1, d2]))
    assert len(pairs) == 2  # (d1,s1) + (s1,d2); (d1,d2) skipped (same engine)
    assert all(x.engine_category != y.engine_category for x, y in pairs)


def test_iter_cross_engine_pairs_empty_when_single_engine():
    d1 = _obj(engine_category=EngineCategory.DAST)
    d2 = _obj(engine_category=EngineCategory.DAST)
    assert list(iter_cross_engine_pairs([d1, d2])) == []


# ---------------------------------------------------------------- union-find


def test_union_find_clusters_transitive_a_b_c_single_cluster():
    a, b, c = _obj(), _obj(), _obj()
    clusters = union_find_clusters([a, b, c], [(a, b), (b, c)])
    assert len(clusters) == 1
    members = next(iter(clusters.values()))
    assert {v.id for v in members} == {a.id, b.id, c.id}


def test_union_find_clusters_independent_pairs_distinct_clusters():
    a, b, c, d = _obj(), _obj(), _obj(), _obj()
    clusters = union_find_clusters([a, b, c, d], [(a, b), (c, d)])
    assert len(clusters) == 2
    assert all(len(members) == 2 for members in clusters.values())


# ---------------------------------------------------------------- route_map


def test_build_route_map_conservative_one_to_one():
    vulns = [
        _obj(target_url="https://x.com/api/users", code_file=None),
        _obj(engine_category=EngineCategory.SAST, target_url=None, code_file="routes/users.py"),
    ]
    route_map = build_route_map(vulns)
    assert route_map.get("/api/users") == "routes/users.py"


def test_build_route_map_skips_ambiguous_basename():
    # Two code_files share basename "users" → ambiguous → path is not mapped.
    vulns = [
        _obj(target_url="https://x.com/users", code_file=None),
        _obj(engine_category=EngineCategory.SAST, target_url=None, code_file="a/users.py"),
        _obj(engine_category=EngineCategory.SAST, target_url=None, code_file="b/users.go"),
    ]
    assert "/users" not in build_route_map(vulns)


def test_build_route_map_handles_empty_inputs():
    assert build_route_map([]) == {}


# ---------------------------------------------------------------- param extraction


def test_extract_params_from_url_filters_short_and_normalizes():
    params = extract_params_from_url("https://x.com/a?userid=1&q=2")
    assert "userid" in params
    assert "q" not in params  # len < 3 filtered


def test_extract_params_from_url_normalized_comparison():
    # "User-ID" → normalized lowercase alphanumeric "userid".
    assert extract_params_from_url("https://x.com/a?User-ID=5") == {"userid"}


def test_extract_params_from_snippet_multi_language_regex():
    snippet = "@app.route('/u/<int:userid>') {productid} req.query.orderref"
    params = extract_params_from_snippet(snippet)
    assert {"userid", "productid", "orderref"} <= params
