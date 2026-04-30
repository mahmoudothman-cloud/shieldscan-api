"""Project-credential encryption + AuthType enum (Task 3.X).

Encryption: Fernet (AES-128-CBC + HMAC-SHA256), single-key MVP.
``settings.FERNET_KEY`` is the canonical 32-byte url-safe-base64 key.
Multi-key rotation via ``MultiFernet`` is deferred to the OPS milestone
(see DRIFT-LOG 2026-04-30 entry 5; mirrors SPEC §10.1 promise).

Storage layout:
  * ``project_credentials.auth_type`` — plaintext, indexable
    discriminator (one of ``AuthType``).
  * ``project_credentials.encrypted_data`` — Fernet ciphertext of
    ``json.dumps({...secret_fields...}).encode()``. Bytes column.

The encryption envelope intentionally does NOT include ``auth_type`` —
that lives in its own column for query/audit purposes. The encrypted
JSON contains only the auth_type-specific secret fields (e.g.
``{"username": ..., "password": ...}`` for basic).

Logging discipline: this module does NOT log decrypted plaintext, the
ciphertext blob, or any field name from the input dict. Fernet
operations are pure functions — no logger calls at all.
"""

from __future__ import annotations

import json
from enum import Enum as PyEnum
from typing import Final

from cryptography.fernet import Fernet

from app.config import settings


class AuthType(str, PyEnum):
    """Canonical credential auth-type values.

    Lifted from M1's inline comment in ``app/models/projects.py``
    (``# cookie | bearer | basic | form | custom_header``) into a
    proper enum at Task 3.X. Adding a new value REQUIRES updating
    the discriminated-union schema in ``app/schemas/credentials.py``
    and the ``CANONICAL_AUTH_TYPES`` test pin below.

    String values are stable contract: scan-engine consumers query
    by ``auth_type`` and fail loudly on unknown values rather than
    silently skip.
    """

    BASIC = "basic"
    BEARER = "bearer"
    COOKIE = "cookie"
    FORM = "form"
    CUSTOM_HEADER = "custom_header"


# Test pin for the canonical 5-value set (matches M1 schema comment).
CANONICAL_AUTH_TYPES: Final[frozenset[str]] = frozenset(
    {"basic", "bearer", "cookie", "form", "custom_header"}
)


# Single-key Fernet for MVP. Multi-key rotation (MultiFernet) is an
# OPS-milestone concern — SPEC §10.1's "key rotation support" promise
# is captured in DRIFT-LOG 2026-04-30 entry 5.
def _fernet() -> Fernet:
    """Build a Fernet instance from the configured key.

    Re-instantiation per call is intentional: Fernet objects are cheap
    to construct (~microseconds), and a per-call instance avoids any
    risk of long-lived references holding the key in memory longer
    than needed (defense-in-depth against memory-dump attacks — the
    key is in settings anyway, but the principle holds).
    """
    return Fernet(settings.FERNET_KEY.encode())


def encrypt_credential(payload: dict) -> bytes:
    """Encrypt a credential payload dict to Fernet ciphertext bytes.

    ``payload`` should contain ONLY the secret fields for the credential's
    auth_type (e.g. ``{"username": ..., "password": ...}`` for basic).
    The ``auth_type`` discriminator is stored in its own column, NOT in
    the encrypted blob.
    """
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return _fernet().encrypt(plaintext)


def decrypt_credential(blob: bytes) -> dict:
    """Decrypt a Fernet ciphertext blob back to the original payload dict.

    Used by scan-time consumers (later milestone). Task 3.X exercises
    this function in tests only — the PATCH/DELETE endpoints are
    write-only and never decrypt.
    """
    plaintext = _fernet().decrypt(blob)
    return json.loads(plaintext.decode("utf-8"))
