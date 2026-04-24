"""Domain verification mechanisms (Task 3.2).

Two methods supported, per IMPLEMENTATION-PLAN.md §3.2:

  1. **DNS TXT record** — strong, requires DNS admin access.
     Lookup ``_shieldscan-verify.{root_domain}`` for any TXT record
     containing the project's verification token.

  2. **HTML meta tag** — weaker but more accessible (works on
     shared hosting / Squarespace / WP.com). Fetches ``target_url``
     and looks for
     ``<meta name="shieldscan-verification" content="<token>">``.

Security tightenings (per Task 3.2 §B refinement):
  - **``follow_redirects=False`` on the meta-tag fetch.** Without
    this, an attacker who controls a redirect handler at the
    customer's ``target_url`` could redirect us to an attacker page
    that contains the right meta tag. Verification would succeed
    for a domain the customer doesn't actually control.
  - **5-second DNS timeout** (``lifetime=5.0``) — dnspython default
    is 30s, which would block a worker thread on slow upstream DNS.
  - **Strict TLS verification** — httpx default; not opting out.

HTML parsing uses ``html.parser`` (stdlib) rather than a regex —
attribute-order variations + single-quoted attributes + self-closing
tags would defeat naive regex but are trivial for the structured
parser.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from html.parser import HTMLParser

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx


logger = logging.getLogger(__name__)


_DNS_LIFETIME = 5.0
_HTTP_TIMEOUT = 10.0
_VERIFY_SUBDOMAIN_PREFIX = "_shieldscan-verify"
_META_NAME = "shieldscan-verification"


@dataclass(frozen=True)
class VerifyResult:
    verified: bool
    # Machine-readable failure code; ``None`` on success. Surfaced
    # in the endpoint's 400 body (DRIFT-LOG: ops + customers see
    # WHY verification failed).
    failure_reason: str | None = None
    # Human-friendly hint of the record we expected to find — populated
    # on FAILURE so the customer sees what they need to add. Never
    # populated on success.
    expected_record: str | None = None


# ---------------------------------------------------------------- DNS TXT


def _expected_dns_record(root_domain: str, token: str) -> str:
    return f'_shieldscan-verify.{root_domain} TXT "{token}"'


async def verify_dns_txt(root_domain: str, expected_token: str) -> VerifyResult:
    """Resolve TXT records at ``_shieldscan-verify.<root_domain>`` and
    return verified=True if any record contains the expected token.

    Multiple TXT records at the same name are common (SPF, DKIM,
    other vendor verifications) — we match against ANY record, not
    requiring exact-single-match.
    """
    name = f"{_VERIFY_SUBDOMAIN_PREFIX}.{root_domain}"
    try:
        answer = await dns.asyncresolver.resolve(name, "TXT", lifetime=_DNS_LIFETIME)
    except dns.resolver.NXDOMAIN:
        return VerifyResult(
            verified=False,
            failure_reason="dns_nxdomain",
            expected_record=_expected_dns_record(root_domain, expected_token),
        )
    except dns.resolver.NoAnswer:
        return VerifyResult(
            verified=False,
            failure_reason="dns_no_answer",
            expected_record=_expected_dns_record(root_domain, expected_token),
        )
    except dns.exception.Timeout:
        return VerifyResult(
            verified=False,
            failure_reason="dns_timeout",
            expected_record=_expected_dns_record(root_domain, expected_token),
        )
    except Exception as e:
        # Unexpected DNS error (SERVFAIL, network issue, etc.) — log
        # and surface as a generic dns_error so ops can investigate
        # without leaking resolver internals to the customer.
        logger.error("DNS verify error for %s: %s", name, e)
        return VerifyResult(
            verified=False,
            failure_reason="dns_error",
            expected_record=_expected_dns_record(root_domain, expected_token),
        )

    # dnspython yields rdata items whose .strings attribute is a tuple
    # of bytes chunks (TXT records can be split into multiple <=255-byte
    # strings; concatenation is the consumer's job).
    for rdata in answer:
        # rdata.strings is tuple[bytes, ...]; join all chunks and decode.
        combined = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if expected_token in combined:
            return VerifyResult(verified=True)

    return VerifyResult(
        verified=False,
        failure_reason="dns_token_not_found",
        expected_record=_expected_dns_record(root_domain, expected_token),
    )


# ---------------------------------------------------------------- HTML meta tag


def _expected_meta_tag(token: str) -> str:
    return f'<meta name="{_META_NAME}" content="{token}">'


class _MetaTagFinder(HTMLParser):
    """Stream-parses HTML and records the ``content`` attribute of
    the first ``<meta name="shieldscan-verification" ...>`` tag it
    encounters.

    Using the stdlib parser (vs. a regex) handles attribute-order
    variations, single vs. double quotes, self-closing tags, mixed
    whitespace, and case-insensitive tag/attribute names — all of
    which a naive regex misses.
    """

    def __init__(self) -> None:
        super().__init__()
        self.found_content: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "meta" or self.found_content is not None:
            return
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        if attr_dict.get("name") == _META_NAME:
            self.found_content = attr_dict.get("content", "")

    # html.parser auto-handles `<meta ... />` self-closing form via
    # handle_startendtag, which by default delegates to handle_starttag
    # — so no override needed.


async def verify_meta_tag(target_url: str, expected_token: str) -> VerifyResult:
    """Fetch ``target_url`` and look for the verification meta tag.

    ``follow_redirects=False`` is load-bearing: a redirect-controlled
    target_url could otherwise be aimed at an attacker page that
    happens to carry the right meta tag. See module docstring for
    the security rationale.
    """
    try:
        async with httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT,
            follow_redirects=False,
        ) as client:
            resp = await client.get(target_url)
    except httpx.TimeoutException:
        return VerifyResult(
            verified=False,
            failure_reason="http_timeout",
            expected_record=_expected_meta_tag(expected_token),
        )
    except httpx.HTTPError as e:
        logger.warning("HTTP verify error for %s: %s", target_url, e)
        return VerifyResult(
            verified=False,
            failure_reason="http_connect_error",
            expected_record=_expected_meta_tag(expected_token),
        )

    # Reject any non-200 — including the 30x redirects we deliberately
    # didn't follow. A 30x means the server is trying to send us
    # somewhere else; verification fails until the customer points
    # target_url at the resource that actually serves the meta tag.
    if resp.status_code != 200:
        return VerifyResult(
            verified=False,
            failure_reason=f"http_status_{resp.status_code}",
            expected_record=_expected_meta_tag(expected_token),
        )

    finder = _MetaTagFinder()
    try:
        finder.feed(resp.text)
    except Exception as e:
        logger.warning("HTML parse error for %s: %s", target_url, e)
        return VerifyResult(
            verified=False,
            failure_reason="html_parse_error",
            expected_record=_expected_meta_tag(expected_token),
        )

    if finder.found_content == expected_token:
        return VerifyResult(verified=True)

    return VerifyResult(
        verified=False,
        failure_reason="meta_tag_token_mismatch"
        if finder.found_content is not None
        else "meta_tag_not_found",
        expected_record=_expected_meta_tag(expected_token),
    )
