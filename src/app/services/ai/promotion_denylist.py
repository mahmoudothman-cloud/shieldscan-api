"""Promotion-time finding denylist (config-driven).

Some tools emit advisories that are informational statements about the target
rather than findings — ZAP plugin 10109 "Modern Web Application" (this site is a
SPA) is the canonical case: 74 raw findings on a single live scan, promoting to
2 Vulnerabilities that carry no remediable content.

Filtering happens at PROMOTION (``_dedup_and_promote``), never at parse or
ingest: ``raw_findings`` is the 90-day audit record (SPEC §5.4) and must stay a
complete account of what each tool actually reported. A denylisted finding is
still parsed, still ingested, still embedded, still queryable — it simply does
not become a Vulnerability.

The list lives in configuration (``PROMOTION_DENYLIST_PLUGIN_IDS``) rather than
in code because it grows per target type; the same advisory can be noise for one
target and signal for another.
"""

from __future__ import annotations

from app.config import settings
from app.models.raw_findings import RawFinding

# tool_metadata key carrying the emitting tool's plugin/rule id. Set by the ZAP
# parser (engine ``internal/tools/docker/service/zap/parser.go``); other tools
# that adopt the same key are covered automatically.
PLUGIN_ID_METADATA_KEY = "plugin_id"


def denylisted_plugin_ids() -> frozenset[str]:
    """Parse the configured comma-separated plugin ids.

    Read per call (not cached) so an operator's env change takes effect on the
    next API start without a code path that can serve a stale list; the set is
    tiny, and this runs once per finding at promotion.
    """
    raw = settings.PROMOTION_DENYLIST_PLUGIN_IDS or ""
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def is_promotion_denylisted(
    finding: RawFinding, denylist: frozenset[str] | None = None
) -> bool:
    """True when this finding's plugin id is denylisted from promotion.

    Findings with no ``tool_metadata`` or no ``plugin_id`` are never denylisted —
    absence of the key is not a match.
    """
    ids = denylisted_plugin_ids() if denylist is None else denylist
    if not ids:
        return False
    metadata = finding.tool_metadata or {}
    plugin_id = metadata.get(PLUGIN_ID_METADATA_KEY)
    if plugin_id is None:
        return False
    return str(plugin_id) in ids
