"""Unit tests for the CWE parent-child hierarchy (ADR-031 Q5).

Uses a minimal custom hierarchy for focused unit testing (Q15 C.b) plus a check
of the real default dict (Q15 C.a) and the module-level singleton accessor.
"""

from __future__ import annotations

from app.services.ai import cwe_hierarchy as cwe_mod
from app.services.ai.cwe_hierarchy import (
    CWE_PARENT_CHILD,
    CWEHierarchy,
    get_cwe_hierarchy,
)

# Minimal hierarchy (Q15 C.b): A → {B, C}.
_MINIMAL = {"CWE-A": {"CWE-B", "CWE-C"}}


def test_cwe_hierarchy_is_parent_child_bidirectional():
    h = CWEHierarchy(_MINIMAL)
    assert h.is_parent_child("CWE-A", "CWE-B") is True  # parent → child
    assert h.is_parent_child("CWE-B", "CWE-A") is True  # child → parent


def test_cwe_hierarchy_returns_false_for_unrelated_cwes():
    h = CWEHierarchy(_MINIMAL)
    assert h.is_parent_child("CWE-B", "CWE-C") is False  # siblings, not parent/child


def test_cwe_hierarchy_returns_false_for_identical_cwes():
    h = CWEHierarchy(_MINIMAL)
    assert h.is_parent_child("CWE-A", "CWE-A") is False  # caller scores exact separately


def test_cwe_hierarchy_returns_false_for_none_inputs():
    h = CWEHierarchy(_MINIMAL)
    assert h.is_parent_child(None, "CWE-A") is False
    assert h.is_parent_child("CWE-A", None) is False
    assert h.is_parent_child(None, None) is False


def test_cwe_hierarchy_minimal_dict_initialization():
    h = CWEHierarchy(_MINIMAL)
    assert h.is_parent_child("CWE-A", "CWE-C") is True
    assert h.is_parent_child("CWE-A", "CWE-Z") is False  # unknown child


def test_cwe_hierarchy_default_dict_uses_real_top_50():
    h = CWEHierarchy()  # default CWE_PARENT_CHILD
    # CWE-74 (injection root) → CWE-89 (SQLi) is a curated parent-child pair.
    assert h.is_parent_child("CWE-74", "CWE-89") is True
    assert "CWE-74" in CWE_PARENT_CHILD


def test_get_cwe_hierarchy_module_singleton():
    cwe_mod._cwe_hierarchy_singleton = None  # reset for a clean check
    first = get_cwe_hierarchy()
    second = get_cwe_hierarchy()
    assert first is second  # same instance returned (singleton)
    assert isinstance(first, CWEHierarchy)


def test_cwe_hierarchy_reverse_child_parent_lookup():
    # Reverse lookup: querying child → parent direction must also resolve.
    h = CWEHierarchy({"CWE-74": {"CWE-89"}})
    assert h.is_parent_child("CWE-89", "CWE-74") is True
