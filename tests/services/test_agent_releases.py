"""Latest-release lookup: cached, failure-tolerant, semver comparison."""

from __future__ import annotations

import pytest

from app.services import agent_releases as ar


@pytest.mark.parametrize(
    ("running", "latest", "behind"),
    [
        ("v0.1.0", "v0.2.0", True),
        ("v0.2.0", "v0.2.0", False),
        ("v1.0.0", "v0.9.9", False),
        ("0.1.0-dev+8ca52e6", "v0.1.0", False),
        ("0.0.9-dev+abc", "v0.1.0", True),
        ("dev", "v0.1.0", False),
        (None, "v0.1.0", False),
        ("v0.1.0", None, False),
    ],
)
def test_is_behind(running, latest, behind):
    assert ar.is_behind(running, latest) is behind


@pytest.mark.asyncio
async def test_latest_version_is_cached_and_failures_are_cached_briefly(fake_redis, monkeypatch):
    calls: list[str] = []

    async def fake_fetch(repo: str) -> str | None:
        calls.append(repo)
        return "v0.2.0" if len(calls) == 1 else None

    monkeypatch.setattr(ar, "_fetch_latest_tag", fake_fetch)
    await fake_redis.delete("shieldscan:agent:latest_version")

    assert await ar.latest_agent_version(fake_redis) == "v0.2.0"
    assert await ar.latest_agent_version(fake_redis) == "v0.2.0"  # cached
    assert calls == ["mahmoudothman-cloud/shieldscan-agent"]

    await fake_redis.delete("shieldscan:agent:latest_version")
    assert await ar.latest_agent_version(fake_redis) is None  # fetch failed
    assert await ar.latest_agent_version(fake_redis) is None  # negative cache, no refetch
    assert len(calls) == 2
    assert await fake_redis.ttl("shieldscan:agent:latest_version") <= 3600


@pytest.mark.asyncio
async def test_latest_version_disabled_when_repo_empty(fake_redis, monkeypatch):
    monkeypatch.setattr(ar.settings, "AGENT_RELEASES_REPO", "")
    assert await ar.latest_agent_version(fake_redis) is None
