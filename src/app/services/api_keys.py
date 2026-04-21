"""API key generation and validation (Task 2.2).

Format: ``ss_<env>_<40-char-random>`` where ``<env>`` is ``live`` or
``test`` (both 4 chars), giving a stable ``plain[:12]`` prefix the
frontend can display after creation (``ss_live_abcd``).

We store the SHA-256 of the plain key; the plain value is returned
exactly once (at creation) and never persisted. Verification uses
``hmac.compare_digest`` for constant-time comparison — ``==`` would
leak timing information about the stored hash.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

# 8 chars of "ss_<env>_" + 4 chars of randomness = the displayed prefix.
PREFIX_LEN = 12
# The random tail after the "ss_<env>_" envelope.
RANDOM_LEN = 40


def generate_api_key(env: str = "live") -> tuple[str, str, str]:
    """Return ``(plain_key, sha256_hash, prefix_for_display)``.

    ``plain_key`` is the only time the caller sees the key in the
    clear. Store ``sha256_hash`` (and ``prefix`` for UX) — never the
    plain value.
    """
    # token_urlsafe(30) -> 40 base64url chars; [:40] is defensive in
    # case Python's implementation ever rounds up.
    random_part = secrets.token_urlsafe(30)[:RANDOM_LEN]
    plain = f"ss_{env}_{random_part}"
    key_hash = hashlib.sha256(plain.encode("utf-8")).hexdigest()
    prefix = plain[:PREFIX_LEN]
    return plain, key_hash, prefix


def verify_api_key(plain: str, stored_hash: str) -> bool:
    """Constant-time comparison of sha256(plain) against ``stored_hash``.

    Uses ``hmac.compare_digest`` rather than ``==`` — see DRIFT-LOG.md
    2026-04-21. Both arguments are ASCII hex digests of fixed length
    (64 chars), so ``compare_digest`` is safe against the length-leak
    caveat noted in the stdlib docs.
    """
    candidate_hash = hashlib.sha256(plain.encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate_hash, stored_hash)
