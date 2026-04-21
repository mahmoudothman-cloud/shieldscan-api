"""Async Redis singleton + FastAPI dependency (Task 2.3.0).

The application opens a single ``redis.asyncio.Redis`` client at
startup and closes it at shutdown. ``redis-py``'s async client is
connection-pooled internally, so a process-wide singleton is both
sufficient and idiomatic.

Tests override ``get_redis`` via ``app.dependency_overrides`` to
inject ``fakeredis.aioredis.FakeRedis``.
"""

from __future__ import annotations

from typing import AsyncIterator

import redis.asyncio as redis_asyncio

from app.config import settings

# Process-wide singleton. ``None`` until ``init_redis`` is called at
# application startup; production code should never use this directly
# — go through ``get_redis``.
_client: redis_asyncio.Redis | None = None


async def init_redis() -> redis_asyncio.Redis:
    """Initialize the module-level client. Safe to call multiple times."""
    global _client
    if _client is None:
        _client = redis_asyncio.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
    return _client


async def close_redis() -> None:
    """Close the module-level client. Called from FastAPI lifespan."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def get_redis() -> AsyncIterator[redis_asyncio.Redis]:
    """FastAPI dependency: yields the shared async Redis client.

    Auth fails closed if Redis is unavailable — see OPERATIONS-RUNBOOK
    §11.6 for the operational contract.
    """
    client = await init_redis()
    yield client
