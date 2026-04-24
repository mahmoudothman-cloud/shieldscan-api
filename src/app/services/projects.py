"""Project-related service helpers (Task 3.1).

Currently ships ``extract_root_domain`` only; ``domain_verify.py`` will
land in Task 3.2 with the DNS TXT / meta-tag verification flows.

PSL vendoring carry-forward (M12.5)
-----------------------------------
``tldextract`` consults the Mozilla Public Suffix List. By default it
fetches+caches it on first use. For air-gapped on-prem deployments
(M12.5+) we'll need to ship a vendored snapshot — see DRIFT-LOG
2026-04-23 for the carry-forward.
"""

from __future__ import annotations

from urllib.parse import urlparse

import tldextract


# Single TLDExtract instance — internally caches the PSL. Constructed
# at import time so the first call doesn't pay PSL-fetch cost.
_extract = tldextract.TLDExtract(suffix_list_urls=())


def extract_root_domain(target_url: str) -> str:
    """Derive the registrable root domain from a target URL.

    Examples::

        https://www.example.com/path        → example.com
        https://api.example.co.uk           → example.co.uk
        https://app.example.com:8443        → example.com
        https://café.example.com            → example.com  (IDN)
        https://192.168.1.1                  → 192.168.1.1   (IP — passthrough)

    Implementation uses ``tldextract`` (Mozilla PSL aware) to handle
    multi-segment TLDs (`.co.uk`, `.com.au`, `.gov.sa`, …) correctly.
    Plain ``urlparse(...).hostname`` would butcher these cases.
    """
    if not target_url:
        raise ValueError("target_url is required")

    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    if not host:
        # Caller passed something un-parseable as a URL; surface as
        # a ValueError so the schema validator can render a 422.
        raise ValueError(f"could not extract host from {target_url!r}")

    extracted = _extract(host)
    # IP literal (no registered domain) — return host as-is.
    if not extracted.suffix:
        return host
    # `domain` is the registrable label, `suffix` is the public-suffix
    # (potentially multi-part like `co.uk`).
    return f"{extracted.domain}.{extracted.suffix}"
