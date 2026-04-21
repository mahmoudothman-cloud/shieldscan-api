"""Tests for app.services.api_keys — Task 2.2.

Covers generate_api_key + verify_api_key. The hardening beyond the
plan's single test is deliberate: these utilities become the
authentication path in Task 2.4, so regressions here break tenant
isolation.
"""

from __future__ import annotations

import inspect

import pytest


# ---------------------------------------------------------------- generate


def test_generate_api_key_returns_plain_and_hash():
    """Plan-verbatim contract check."""
    from app.services.api_keys import generate_api_key

    plain, key_hash, prefix = generate_api_key(env="live")
    assert plain.startswith("ss_live_")
    assert len(plain) == 48  # "ss_live_" (8) + 40 random chars
    assert prefix == plain[:12]  # first 12 chars shown to user
    assert key_hash != plain


def test_env_appears_in_prefix():
    """env switches the infix: ss_live_... vs ss_test_..., same length
    (both env labels are 4 chars, so prefix[:12] still splits 8+4)."""
    from app.services.api_keys import generate_api_key

    live_plain, _, live_prefix = generate_api_key(env="live")
    test_plain, _, test_prefix = generate_api_key(env="test")

    assert live_plain.startswith("ss_live_")
    assert test_plain.startswith("ss_test_")
    assert live_prefix.startswith("ss_live_")
    assert test_prefix.startswith("ss_test_")
    # Both prefixes are plain[:12] — 8 chars env label + 4 random.
    assert len(live_prefix) == 12
    assert len(test_prefix) == 12


def test_two_keys_are_distinct():
    """Each call must draw fresh entropy — no RNG seeding / caching bug."""
    from app.services.api_keys import generate_api_key

    a_plain, a_hash, a_prefix = generate_api_key(env="live")
    b_plain, b_hash, b_prefix = generate_api_key(env="live")
    assert a_plain != b_plain
    assert a_hash != b_hash
    assert a_prefix != b_prefix


def test_hash_is_not_the_plain_value():
    """Documents intent: storing the hash, never the plain key."""
    from app.services.api_keys import generate_api_key

    plain, key_hash, _ = generate_api_key(env="live")
    assert key_hash != plain
    assert plain not in key_hash
    # SHA-256 hex digest is 64 chars; plain is 48 chars. Length alone
    # is enough to rule out an accidental identity.
    assert len(key_hash) == 64


# ---------------------------------------------------------------- verify


def test_verify_api_key_accepts_matching_plain():
    from app.services.api_keys import generate_api_key, verify_api_key

    plain, key_hash, _ = generate_api_key(env="live")
    assert verify_api_key(plain, key_hash) is True


def test_verify_api_key_rejects_wrong_plain():
    from app.services.api_keys import generate_api_key, verify_api_key

    plain, key_hash, _ = generate_api_key(env="live")
    # Flip the last char — still valid base64url, still correct length,
    # still correct prefix, but wrong key.
    tampered = plain[:-1] + ("A" if plain[-1] != "A" else "B")
    assert tampered != plain
    assert verify_api_key(tampered, key_hash) is False


def test_verify_api_key_uses_constant_time_comparison():
    """Regression guard: verify_api_key MUST use hmac.compare_digest,
    not `==`. Pure black-box tests can't distinguish the two because
    both return the same booleans — so we inspect the source.

    See DRIFT-LOG.md 2026-04-21 — the plan literal uses `==`; this
    deviates to close a timing-attack vector on the API-key auth path.
    """
    from app.services import api_keys

    source = inspect.getsource(api_keys.verify_api_key)
    assert "compare_digest" in source, (
        "verify_api_key must use hmac.compare_digest for constant-time "
        "comparison. A `==` comparison leaks timing information that can "
        "be used to recover the stored hash byte-by-byte."
    )
