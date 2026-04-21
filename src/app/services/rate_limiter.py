"""Redis fixed-window rate limiter (Sub-task 2.3.0).

Algorithm: fixed window via ``INCR`` + ``EXPIRE NX``. Worst-case
boundary burst is 2× the declared limit in ~1 second, which for the
M2 auth rates (3/hr register IP, 5/15min login IP, 10/hr login email)
is well below any practical brute-force velocity — bcrypt cost=12
already caps login verification at ~4 req/sec regardless.

Key shape (canonical across the app):

    ratelimit:{scope}:{identifier}:{window_bucket}

``window_bucket`` is the unix-epoch start of the current window, so
keys are deterministic and SCAN-friendly:

    SCAN MATCH "ratelimit:login_ip:203.0.113.7:*"   -> all windows for this IP
    SCAN MATCH "ratelimit:register:*"               -> every register counter

The interface is deliberately minimal — ``check(...) -> RateLimitResult``.
If we outgrow fixed-window (public write endpoints in M10+), swap the
impl for sliding-window-log behind the same interface.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import redis.asyncio as redis_asyncio


RATELIMIT_PREFIX = "ratelimit"


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    reset_at: int  # unix seconds when the current window ends
    count: int  # current count in this window (post-INCR)


class RateLimiter:
    """Fixed-window rate limiter backed by Redis.

    Instances are cheap; construct once per app and inject. Tests
    inject a ``fakeredis.aioredis.FakeRedis`` in place of the real
    client — the interface is identical.
    """

    def __init__(self, client: redis_asyncio.Redis) -> None:
        self._redis = client

    @staticmethod
    def _bucket(now: float, window_seconds: int) -> int:
        return int(now // window_seconds) * window_seconds

    @staticmethod
    def make_key(scope: str, identifier: str, window_bucket: int) -> str:
        # Shape chosen so `SCAN MATCH ratelimit:{scope}:{id}:*` lets
        # ops see all windows for a specific actor. See DRIFT-LOG
        # 2026-04-21 entry on rate-limit key ordering.
        return f"{RATELIMIT_PREFIX}:{scope}:{identifier}:{window_bucket}"

    async def check(
        self,
        scope: str,
        identifier: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitResult:
        """Increment the window counter, return whether the caller is
        under the limit. Non-blocking — callers translate
        ``allowed=False`` to HTTP 429 at the endpoint boundary.
        """
        now = time.time()
        bucket = self._bucket(now, window_seconds)
        key = self.make_key(scope, identifier, bucket)

        # INCR is atomic. EXPIRE with NX ensures the TTL is only set
        # on first increment (so the window "starts" deterministically
        # at the first hit). Two round-trips but each O(1); worth the
        # extra simplicity over a Lua script.
        count = await self._redis.incr(key)
        if count == 1:
            # 2x window TTL is a defensive cushion against clock drift
            # between the app and Redis; the logical window is still
            # ``window_seconds``.
            await self._redis.expire(key, window_seconds * 2)

        reset_at = bucket + window_seconds
        remaining = max(0, limit - count)
        allowed = count <= limit

        return RateLimitResult(
            allowed=allowed,
            limit=limit,
            remaining=remaining,
            reset_at=reset_at,
            count=count,
        )
