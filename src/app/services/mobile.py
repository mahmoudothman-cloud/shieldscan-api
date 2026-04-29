"""Mobile-upload validation helpers (Task 3.3).

Pure functions — no I/O, no DB. The route handler composes these to
turn an ``UploadFile`` into a validated, storage-ready blob.

Validation layers:
  1. Extension allow-list. ``.zip`` is intentionally absent — see
     DRIFT-LOG 2026-04-26 entry 1.
  2. Magic-bytes check. APK + IPA are both ZIP archives, so we accept
     any of the three ZIP local-/end-of-central-directory signatures
     (PK\\x03\\x04, PK\\x05\\x06, PK\\x07\\x08).
  3. Size — enforced in the route handler (depends on ``settings``).

Virus / malware scanning is intentionally NOT performed here. Mobile
upload accepts files as content-addressable blobs; static analysis +
malware indicators are a downstream scan-worker concern (see
DRIFT-LOG 2026-04-26 entry 3). The upload endpoint is not a security
gate.
"""

from __future__ import annotations

import os
from typing import Final

from app.models.mobile import MobilePlatform

# Allow-list. Plan literal also included ".zip"; dropped per Task 3.3
# DRIFT-LOG entry 1.
ALLOWED_EXTENSIONS: Final[frozenset[str]] = frozenset({".apk", ".ipa"})

# ZIP magic-byte prefixes — APK + IPA are both ZIP archives.
#   PK\x03\x04  local file header (any non-empty archive)
#   PK\x05\x06  end-of-central-directory (empty archive)
#   PK\x07\x08  data-descriptor (streamed archive — rare but valid)
_ZIP_MAGIC: Final[tuple[bytes, ...]] = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
)


def extract_extension(filename: str) -> str:
    """Lowercase extension including the dot. Empty string if none.

    Uses ``os.path.basename`` first so a path-traversal-style filename
    (e.g. ``../etc/passwd.apk``) still returns ``.apk`` — the route
    handler relies on this for the allow-list check, but the R2 key
    is decoupled from the filename anyway (PII hygiene).
    """
    base = os.path.basename(filename or "")
    _, ext = os.path.splitext(base)
    return ext.lower()


def is_allowed_extension(ext: str) -> bool:
    return ext in ALLOWED_EXTENSIONS


def has_zip_magic(content: bytes) -> bool:
    """True if ``content`` starts with any of the three ZIP signatures.

    Empty content returns False — see route handler test 18 (empty
    body is a 400 file_not_a_mobile_package).
    """
    if not content or len(content) < 4:
        return False
    return any(content.startswith(sig) for sig in _ZIP_MAGIC)


def platform_for_extension(ext: str) -> MobilePlatform:
    """Map an allow-listed extension to its platform enum.

    Raises ``ValueError`` for any other extension — the route handler
    guards against that with ``is_allowed_extension`` first, so this
    branch is unreachable in production but fail-loud-not-silent makes
    the contract obvious to readers.
    """
    if ext == ".apk":
        return MobilePlatform.ANDROID
    if ext == ".ipa":
        return MobilePlatform.IOS
    raise ValueError(f"unsupported mobile extension: {ext!r}")
