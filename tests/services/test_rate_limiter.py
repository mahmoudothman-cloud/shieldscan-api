"""Tests for app.services.rate_limiter — Sub-task 2.3.0.

Uses fakeredis.aioredis so no live Redis is needed. The service is
algorithm-only (fixed window, INCR+EXPIRE); endpoint integration
lands in Sub-task 2.3.4.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from fakeredis import aioredis as fakeredis_aio

from app.services.rate_limiter import RateLimiter, RateLimitResult


@pytest_asyncio.fixture
async def redis_client():
    """Fresh isolated fakeredis per test — no cross-test state."""
    client = fakeredis_aio.FakeRedis(decode_responses=True)
    try:
        yield client
    finally:
        await client.flushall()
        await client.aclose()


@pytest_asyncio.fixture
async def limiter(redis_client):
    return RateLimiter(redis_client)


# ---------------------------------------------------------------- happy path


@pytest.mark.asyncio
async def test_first_request_allowed(limiter):
    r = await limiter.check("login_ip", "203.0.113.7", limit=5, window_seconds=900)
    assert isinstance(r, RateLimitResult)
    assert r.allowed is True
    assert r.count == 1
    assert r.remaining == 4
    assert r.limit == 5


@pytest.mark.asyncio
async def test_requests_under_limit_all_allowed(limiter):
    for i in range(5):
        r = await limiter.check("login_ip", "a.b.c.d", limit=5, window_seconds=900)
        assert r.allowed is True
        assert r.count == i + 1
    assert r.remaining == 0


@pytest.mark.asyncio
async def test_request_over_limit_denied(limiter):
    for _ in range(5):
        await limiter.check("login_ip", "a.b.c.d", limit=5, window_seconds=900)
    r = await limiter.check("login_ip", "a.b.c.d", limit=5, window_seconds=900)
    assert r.allowed is False
    assert r.count == 6
    assert r.remaining == 0


# ---------------------------------------------------------------- isolation


@pytest.mark.asyncio
async def test_different_identifiers_tracked_separately(limiter):
    """Two IPs hitting login must each get their own budget."""
    for _ in range(5):
        await limiter.check("login_ip", "ip_a", limit=5, window_seconds=900)
    # ip_a is now at the limit; ip_b must still have full budget.
    r = await limiter.check("login_ip", "ip_b", limit=5, window_seconds=900)
    assert r.allowed is True
    assert r.count == 1


@pytest.mark.asyncio
async def test_different_scopes_tracked_separately(limiter):
    """Login and register counters must not share a bucket."""
    for _ in range(3):
        await limiter.check("register", "ip_x", limit=3, window_seconds=3600)
    r = await limiter.check("login_ip", "ip_x", limit=5, window_seconds=900)
    # register is at cap (3/3); login is fresh.
    assert r.allowed is True
    assert r.count == 1


# ---------------------------------------------------------------- key shape


@pytest.mark.asyncio
async def test_key_shape_is_scope_identifier_bucket(limiter, redis_client):
    """Contract: `ratelimit:{scope}:{identifier}:{window_bucket}`.

    Enforced by SCAN — ops monitoring relies on this prefix shape to
    enumerate all windows for a given actor. A silent refactor that
    reorders the key segments breaks rate-limit dashboards.
    """
    await limiter.check("register", "192.0.2.1", limit=3, window_seconds=3600)

    # All keys for this (scope, identifier), any window.
    keys = [k async for k in redis_client.scan_iter(match="ratelimit:register:192.0.2.1:*")]
    assert len(keys) == 1
    # Every key must have exactly 4 colon-separated segments.
    segments = keys[0].split(":")
    assert segments[0] == "ratelimit"
    assert segments[1] == "register"
    assert segments[2] == "192.0.2.1"
    # Fourth segment is the unix-epoch bucket start — must be an int.
    int(segments[3])


@pytest.mark.asyncio
async def test_scan_match_on_scope_returns_all_counters(limiter, redis_client):
    """Catches silent prefix refactors that break rate-limit monitoring
    (per the user's 2.3.0 test addendum)."""
    await limiter.check("register", "ip_1", limit=3, window_seconds=3600)
    await limiter.check("register", "ip_2", limit=3, window_seconds=3600)
    await limiter.check("register", "ip_3", limit=3, window_seconds=3600)

    keys = [k async for k in redis_client.scan_iter(match="ratelimit:register:*")]
    assert len(keys) == 3
    assert all(k.startswith("ratelimit:register:") for k in keys)


# ---------------------------------------------------------------- expiry


@pytest.mark.asyncio
async def test_window_key_has_ttl_set(limiter, redis_client):
    """EXPIRE must be applied on first increment — otherwise keys
    accumulate forever and Redis OOMs under attack."""
    await limiter.check("register", "ip_x", limit=3, window_seconds=60)
    keys = [k async for k in redis_client.scan_iter(match="ratelimit:register:ip_x:*")]
    assert len(keys) == 1
    ttl = await redis_client.ttl(keys[0])
    # Window is 60s, cushion is 2x; TTL must be positive and <= 120.
    assert 0 < ttl <= 120


@pytest.mark.asyncio
async def test_boundary_burst_is_accepted_2x_limit(
    redis_client, monkeypatch
):
    """Fixed-window semantics: a request at T-epsilon lands in window N
    and a request at T+epsilon lands in window N+1. An attacker timing
    across the boundary can get up to 2x the limit in the minimum
    inter-request interval.

    This is NOT a bug — it is the documented trade-off of fixed window
    vs sliding-window-log (see rate_limiter.py module docstring and
    the Task 2.3 scope proposal). This test pins the behavior so a
    future refactor that *tightens* the algorithm (intentionally or
    otherwise) must be an explicit design choice, not an accident.
    """
    from app.services import rate_limiter as rl_module

    t = {"now": 1_000_000_000.000}  # arbitrary epoch, well inside a minute

    def fake_time():
        return t["now"]

    monkeypatch.setattr(rl_module.time, "time", fake_time)
    limiter = rl_module.RateLimiter(redis_client)

    # Fill window N to the cap (limit=5, 60s window).
    for _ in range(5):
        r = await limiter.check("login_ip", "attacker", limit=5, window_seconds=60)
        assert r.allowed is True
    # Still inside window N — 6th request denied.
    r = await limiter.check("login_ip", "attacker", limit=5, window_seconds=60)
    assert r.allowed is False

    # Jump across the boundary. 1_000_000_000 // 60 * 60 = 999_999_960
    # (window N starts at -40s). New window N+1 begins at 1_000_000_020.
    t["now"] = 1_000_000_020.001

    # All five requests in window N+1 must succeed — proving the 2x burst.
    for _ in range(5):
        r = await limiter.check("login_ip", "attacker", limit=5, window_seconds=60)
        assert r.allowed is True
    # Sixth in N+1 denied.
    r = await limiter.check("login_ip", "attacker", limit=5, window_seconds=60)
    assert r.allowed is False

    # Confirm two distinct keys now exist for this (scope, identifier).
    keys = [k async for k in redis_client.scan_iter(match="ratelimit:login_ip:attacker:*")]
    assert len(keys) == 2


@pytest.mark.asyncio
async def test_ttl_set_once_not_extended_on_each_hit(limiter, redis_client):
    """The TTL belongs to the window, not to the latest request —
    otherwise a steady request stream never expires and a burst at
    second-0 of a 1-hour window blocks until hour-2."""
    await limiter.check("register", "ip_y", limit=10, window_seconds=60)
    keys = [k async for k in redis_client.scan_iter(match="ratelimit:register:ip_y:*")]
    first_ttl = await redis_client.ttl(keys[0])
    # Second hit should NOT reset the TTL.
    await limiter.check("register", "ip_y", limit=10, window_seconds=60)
    second_ttl = await redis_client.ttl(keys[0])
    assert second_ttl <= first_ttl  # monotonically non-increasing
