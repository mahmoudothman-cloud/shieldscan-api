"""Redis primitives for scan orchestration (Task 4.1).

Four wrappers expose the M4 inter-service contract surface:

  ScanQueue          — LPUSH/BRPOP per-priority lists for job dispatch.
                       Worker (M5) pops with BRPOP across keys in
                       priority order via ``pop_any``.
  ProgressPublisher  — XADD per-scan Stream for progress events.
                       Streams (not Pub/Sub) per ADR-014 — the SSE
                       endpoint (4.4) needs ``Last-Event-ID`` replay
                       which only Streams provides.
  ProgressSubscriber — XRANGE for replay + XREAD BLOCK for live tail.
                       Separated from publisher for clean inject-the-
                       client testing.
  CancelPublisher    — Pub/Sub one-shot cancel. Live-only by design —
                       a worker not subscribed when cancel emits
                       cannot usefully consume a stale cancel.

Idempotency: NOT a queue concern. SPEC §7.5 + ADP-5 put the
SETNX-with-TTL claim on the WORKER side (M5 task 5.5). The
``ScanQueue.dispatch`` method does NOT inspect ``idempotency_key``
or dedupe — duplicate dispatches push duplicate items, by design.

ScanPriority enum: lives at the orchestrator boundary (Task 4.2),
NOT here. ``ScanQueue.dispatch`` accepts a string and raises
``ValueError`` on unknown priority — fail-loud rather than silent
drop. This lets the queue layer stay enum-agnostic so future
additions (an enterprise-tier ``urgent`` priority?) need only one
edit at the orchestrator boundary, not three.
"""

from __future__ import annotations

import json
from typing import AsyncIterator, Final

from redis.asyncio import Redis

# Per-scan Stream key. Naming convention SHIFT (vs SPEC §7.2's
# pre-ADR-014 "channel" wording): the key now refers to a Stream,
# not a Pub/Sub channel. SPEC §7.2 was patched in the same docs
# commit as ADR-014.
_PROGRESS_KEY_PREFIX: Final[str] = "shieldscan:progress:"

# Per-scan Pub/Sub channel for cancel signals — stays Pub/Sub.
# See ADR-014: cancel is one-shot live-only, no replay semantics.
_CANCEL_KEY_PREFIX: Final[str] = "shieldscan:cancel:"

# Job-dispatch list keys, per priority.
_QUEUE_KEY_PREFIX: Final[str] = "shieldscan:queue:"

# Priority order for ``pop_any`` — BRPOP across keys returns the
# first non-empty in argument order.
_PRIORITIES: Final[tuple[str, ...]] = ("critical", "high", "normal", "low")

# Approximate cap on per-scan progress stream length. ~1000 events
# covers ~60s of replay at peak emit rate per SPEC §6.4. Approximate
# trim (~) allows up to ~10% over for performance; tests assert ≤ 1100.
_PROGRESS_MAXLEN: Final[int] = 1000


# ================================================================ ScanQueue


class ScanQueue:
    """LPUSH/BRPOP wrapper over per-priority job-dispatch lists.

    Used by the orchestrator (4.2) to enqueue jobs and by the Go worker
    (M5) to dequeue. Priority is one of ``critical | high | normal |
    low``. Unknown priority raises ``ValueError`` — caller must
    validate via ``ScanPriority`` enum at the boundary (4.2).
    """

    PRIORITIES: Final[tuple[str, ...]] = _PRIORITIES

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    @staticmethod
    def _key(priority: str) -> str:
        if priority not in _PRIORITIES:
            raise ValueError(
                f"unknown priority {priority!r}; must be one of {_PRIORITIES}"
            )
        return f"{_QUEUE_KEY_PREFIX}{priority}"

    async def dispatch(self, priority: str, job: dict) -> None:
        """Push ``job`` (JSON-serialized) onto the priority queue.

        Note: does NOT dedupe by ``idempotency_key`` — that's a
        worker-side concern (SPEC §7.5). Duplicate dispatches push
        duplicates by design.
        """
        await self.redis.lpush(self._key(priority), json.dumps(job))

    async def pop(self, priority: str, timeout: int = 0) -> dict | None:
        """BRPOP a single priority. Returns the parsed job dict or
        ``None`` on timeout (empty queue + timeout elapsed)."""
        result = await self.redis.brpop(self._key(priority), timeout=timeout)
        if result is None:
            return None
        _key, raw = result
        return json.loads(raw)

    async def pop_any(self, timeout: int = 0) -> dict | None:
        """BRPOP across all priority keys in priority order. Critical
        drains before high, high before normal, normal before low.

        BRPOP with multiple keys returns the first non-empty, so
        passing keys in priority order naturally implements the
        priority drain.
        """
        keys = [self._key(p) for p in _PRIORITIES]
        result = await self.redis.brpop(keys, timeout=timeout)
        if result is None:
            return None
        _key, raw = result
        return json.loads(raw)


# ================================================================ ProgressPublisher / ProgressSubscriber


class ProgressPublisher:
    """XADD wrapper for the per-scan progress Stream.

    Stream key: ``shieldscan:progress:{scan_id}``.

    Each event is stored as a single field ``event`` containing the
    JSON-serialized payload. (Streams require field=value pairs at the
    XADD level; collapsing to one field avoids hand-decomposing the
    structure into top-level Stream fields and keeps the schema
    consumer-controlled.)

    MAXLEN ~ 1000 (approximate trim) — bounded retention for the
    SSE 60s replay window per SPEC §6.4 + ADR-014.
    """

    def __init__(self, redis: Redis, scan_id: str) -> None:
        self.redis = redis
        self.key = f"{_PROGRESS_KEY_PREFIX}{scan_id}"

    async def publish(self, event: dict) -> str:
        """Append ``event`` to the stream. Returns the assigned
        Stream entry id (``ms-seq`` format) — useful for tests and
        for SSE clients via the ``Last-Event-ID`` header."""
        return await self.redis.xadd(
            self.key,
            {"event": json.dumps(event)},
            maxlen=_PROGRESS_MAXLEN,
            approximate=True,
        )


class ProgressSubscriber:
    """XRANGE replay + XREAD BLOCK live tail for the per-scan stream.

    Two iterators:

      ``replay(since_id="-")``   — returns historical events from
                                   ``since_id`` up to the latest at
                                   call time. Use for the SSE
                                   reconnect path with ``Last-Event-ID``.
      ``live(last_id="$")``      — blocks for new events; ``$`` means
                                   "only events after this call".
                                   Pass the last replayed id to
                                   chain seamlessly from ``replay``.

    Both yield ``(entry_id: str, event: dict)`` tuples. ``entry_id``
    is the Stream id the SSE handler relays as ``id:`` per SPEC §6.4.
    """

    # XREAD BLOCK timeout in ms. 0 = block indefinitely; any positive
    # value periodically returns empty so the caller can check for
    # client disconnect. The SSE handler (4.4) sets a finite block to
    # honor ``await request.is_disconnected()`` checks.
    DEFAULT_BLOCK_MS: Final[int] = 0

    def __init__(self, redis: Redis, scan_id: str) -> None:
        self.redis = redis
        self.key = f"{_PROGRESS_KEY_PREFIX}{scan_id}"

    async def replay(self, since_id: str = "-") -> AsyncIterator[tuple[str, dict]]:
        """XRANGE from ``since_id`` (inclusive) to ``+`` (latest at
        call time). One-shot — exits when history is exhausted."""
        entries = await self.redis.xrange(self.key, min=since_id, max="+")
        for entry_id, fields in entries:
            yield entry_id, json.loads(fields["event"])

    async def live(
        self,
        last_id: str = "$",
        block_ms: int | None = None,
    ) -> AsyncIterator[tuple[str, dict]]:
        """XREAD BLOCK loop yielding new events as they're XADDed.

        ``last_id`` advances on each yielded event so the next XREAD
        picks up only what came after — no duplicates, no skips.
        ``$`` means "only events after this call started"; pass a
        concrete id to chain from a prior ``replay()`` cleanly.
        """
        block = self.DEFAULT_BLOCK_MS if block_ms is None else block_ms
        cursor = last_id
        while True:
            result = await self.redis.xread(
                {self.key: cursor},
                count=100,
                block=block,
            )
            if not result:
                # Empty result = block timeout elapsed (or stream
                # gone). Loop again — the SSE handler is responsible
                # for breaking out via disconnect check.
                continue
            for _stream_key, entries in result:
                for entry_id, fields in entries:
                    yield entry_id, json.loads(fields["event"])
                    cursor = entry_id


# ================================================================ CancelPublisher


class CancelPublisher:
    """Pub/Sub publisher for one-shot scan-cancel signals.

    Channel: ``shieldscan:cancel:{scan_id}``.

    Stays Pub/Sub (not Streams) per ADR-014 — cancel is a live-only
    signal. A worker not subscribed at emit time can't usefully
    cancel a job it doesn't have running, so replay would be misleading.
    """

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def publish_cancel(
        self, scan_id: str, reason: str = "user_requested"
    ) -> int:
        """Publish a ``cancel_requested`` event. Returns the Redis
        PUBLISH count (number of subscribers that received the
        message). Caller may log this for visibility."""
        event = {
            "event_type": "cancel_requested",
            "scan_id": scan_id,
            "reason": reason,
        }
        return await self.redis.publish(
            f"{_CANCEL_KEY_PREFIX}{scan_id}", json.dumps(event)
        )
