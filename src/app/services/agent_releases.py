"""Latest public agent release, for the Agents page's "update available"
badge (On-Prem Agent Design v1.0 §5, distribution).

The heartbeat tells us what each agent runs; this tells us what it could
run. One GitHub API call a day per API process pool, cached in Redis;
failures are cached briefly as "unknown" so a GitHub hiccup costs one
request an hour, not one per page view. Never raises: the badge is a
nicety, the page is not.
"""

from __future__ import annotations

import logging
import re
from typing import Final

import httpx
from redis.asyncio import Redis

from app.config import settings

logger = logging.getLogger(__name__)

_CACHE_KEY: Final[str] = "shieldscan:agent:latest_version"
_UNKNOWN: Final[str] = "-"
_UNKNOWN_TTL_S: Final[int] = 3600
_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


async def latest_agent_version(redis: Redis) -> str | None:
    """``"v0.2.0"`` or None when disabled / not known."""
    repo = settings.AGENT_RELEASES_REPO.strip()
    if not repo:
        return None
    cached = await redis.get(_CACHE_KEY)
    if cached is not None:
        value = cached.decode() if isinstance(cached, bytes) else str(cached)
        return None if value == _UNKNOWN else value
    tag = await _fetch_latest_tag(repo)
    if tag is None:
        await redis.set(_CACHE_KEY, _UNKNOWN, ex=_UNKNOWN_TTL_S)
        return None
    await redis.set(_CACHE_KEY, tag, ex=settings.AGENT_RELEASES_CACHE_S)
    return tag


async def _fetch_latest_tag(repo: str) -> str | None:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(
                url,
                headers={"Accept": "application/vnd.github+json", "User-Agent": "shieldscan-api"},
            )
        if r.status_code != 200:
            logger.info("agent releases: %s answered %s", url, r.status_code)
            return None
        tag = r.json().get("tag_name")
        return tag if isinstance(tag, str) and _SEMVER.match(tag) else None
    except (httpx.HTTPError, ValueError) as exc:
        logger.info("agent releases: lookup failed: %s", exc)
        return None


def is_behind(running: str | None, latest: str | None) -> bool:
    """True when ``running`` is a lower semver than ``latest``. Dev builds
    (``0.1.0-dev+abc``) compare on their numeric prefix; unparseable
    strings are never "behind"."""
    if not running or not latest:
        return False
    a, b = _SEMVER.match(running), _SEMVER.match(latest)
    if a is None or b is None:
        return False
    return tuple(int(x) for x in a.groups()) < tuple(int(x) for x in b.groups())
