"""Tests for ``app.services.scan_queue`` primitives (Task 4.1).

Twelve tests pinning the contract of the four wrappers used by
M4 scan orchestration:

  ScanQueue          — LPUSH/BRPOP over per-priority lists
  ProgressPublisher  — XADD to per-scan Redis Streams (ADR-014)
  ProgressSubscriber — XRANGE replay + XREAD BLOCK live tail
  CancelPublisher    — Pub/Sub one-shot cancel signal

The primitives accept strings for priority + scan_id; the typed
``ScanPriority`` enum is intentionally a 4.2 boundary concern (the
orchestrator validates before reaching the queue).
"""

from __future__ import annotations

import asyncio
import json

import pytest

from app.services.scan_queue import (
    ScanQueue,
    ProgressPublisher,
    ProgressSubscriber,
    CancelPublisher,
)


# ============================================================ ScanQueue — 1-5


@pytest.mark.asyncio
async def test_dispatch_pop_round_trip(fake_redis):
    """LPUSH on dispatch, BRPOP on pop — payload round-trips intact."""
    q = ScanQueue(fake_redis)
    job = {"id": "job_a", "scan_id": "scn_1", "engine": "nuclei"}
    await q.dispatch("normal", job)
    popped = await q.pop("normal", timeout=1)
    assert popped == job


@pytest.mark.asyncio
async def test_pop_any_drains_critical_before_lower(fake_redis):
    """Worker-side multi-priority pop honors order:
    critical → high → normal → low."""
    q = ScanQueue(fake_redis)
    await q.dispatch("low", {"id": "low_job"})
    await q.dispatch("normal", {"id": "normal_job"})
    await q.dispatch("critical", {"id": "critical_job"})
    await q.dispatch("high", {"id": "high_job"})

    first = await q.pop_any(timeout=1)
    second = await q.pop_any(timeout=1)
    third = await q.pop_any(timeout=1)
    fourth = await q.pop_any(timeout=1)

    assert first["id"] == "critical_job"
    assert second["id"] == "high_job"
    assert third["id"] == "normal_job"
    assert fourth["id"] == "low_job"


@pytest.mark.asyncio
async def test_pop_returns_none_on_timeout_empty_queue(fake_redis):
    q = ScanQueue(fake_redis)
    result = await q.pop("normal", timeout=1)
    assert result is None


@pytest.mark.asyncio
async def test_dispatch_invalid_priority_raises(fake_redis):
    """Unknown priority is a 500-class bug, not a 4xx — orchestrator
    (4.2) is responsible for validating user input via ScanPriority
    enum BEFORE reaching the queue. Queue-level fail-loud."""
    q = ScanQueue(fake_redis)
    with pytest.raises(ValueError):
        await q.dispatch("URGENT", {"id": "x"})


@pytest.mark.asyncio
async def test_dispatch_does_not_dedupe_by_idempotency_key(fake_redis):
    """Idempotency is a WORKER-SIDE concern (SPEC §7.5; ADP-5).
    The queue-level wrapper does NOT inspect or dedupe by
    ``idempotency_key`` — duplicate dispatches push duplicate items.
    This test pins the negative contract so a future engineer
    doesn't add Python-side dedupe and break the M5 worker design."""
    q = ScanQueue(fake_redis)
    job = {"id": "j", "idempotency_key": "scn_x:nuclei:1234567890"}
    await q.dispatch("normal", job)
    await q.dispatch("normal", job)
    # Two pops both succeed — both items are present.
    a = await q.pop("normal", timeout=1)
    b = await q.pop("normal", timeout=1)
    assert a == job
    assert b == job


# ============================================================ ProgressPublisher / Subscriber — 6-10


@pytest.mark.asyncio
async def test_publish_appends_to_stream(fake_redis):
    """XADD lands; entry id non-empty; payload reads back via XRANGE."""
    pub = ProgressPublisher(fake_redis, scan_id="scn_p1")
    eid = await pub.publish({"event_type": "job_started", "engine": "nuclei"})
    assert isinstance(eid, str)
    assert "-" in eid  # Redis stream id format: ms-seq

    # Direct XRANGE on the underlying key — verifies the wrapper
    # actually wrote a Stream entry, not (e.g.) a Pub/Sub message.
    entries = await fake_redis.xrange("shieldscan:progress:scn_p1", "-", "+")
    assert len(entries) == 1
    _, fields = entries[0]
    assert json.loads(fields["event"]) == {
        "event_type": "job_started",
        "engine": "nuclei",
    }


@pytest.mark.asyncio
async def test_subscriber_live_iterator_yields_published(fake_redis):
    """Live tail (XREAD BLOCK) wakes when a publisher XADDs."""
    pub = ProgressPublisher(fake_redis, scan_id="scn_p2")
    sub = ProgressSubscriber(fake_redis, scan_id="scn_p2")

    received: list[tuple[str, dict]] = []

    async def consume():
        async for entry_id, event in sub.live(last_id="$"):
            received.append((entry_id, event))
            if len(received) >= 2:
                break

    task = asyncio.create_task(consume())
    # Tiny gap so the consumer's XREAD BLOCK is parked before XADD lands.
    await asyncio.sleep(0.05)
    await pub.publish({"event_type": "job_progress", "progress": 25})
    await pub.publish({"event_type": "job_progress", "progress": 50})
    await asyncio.wait_for(task, timeout=3.0)

    assert len(received) == 2
    assert received[0][1]["progress"] == 25
    assert received[1][1]["progress"] == 50


@pytest.mark.asyncio
async def test_subscriber_replay_returns_history(fake_redis):
    """Replay returns historical events from the stream.

    REGRESSION GUARD: This test requires Redis Streams semantics
    (XRANGE). It fails immediately if anyone switches the wrapper
    to Pub/Sub. See ADR-014 for the reasoning behind Streams-over-
    Pub/Sub. Don't "simplify" by reverting without reading ADR-014.
    """
    pub = ProgressPublisher(fake_redis, scan_id="scn_p3")
    await pub.publish({"event_type": "scan_status", "progress": 10})
    await pub.publish({"event_type": "scan_status", "progress": 30})
    await pub.publish({"event_type": "scan_status", "progress": 70})

    sub = ProgressSubscriber(fake_redis, scan_id="scn_p3")
    replayed = []
    async for entry_id, event in sub.replay(since_id="-"):
        replayed.append(event)
    assert [e["progress"] for e in replayed] == [10, 30, 70]


@pytest.mark.asyncio
async def test_subscriber_replay_then_live_seamless(fake_redis):
    """The SSE reconnect path: XRANGE picks up missed events, then
    XREAD BLOCK from last replayed id transitions cleanly to live —
    no duplicate, no skip."""
    pub = ProgressPublisher(fake_redis, scan_id="scn_p4")
    eid_1 = await pub.publish({"i": 1})
    eid_2 = await pub.publish({"i": 2})

    sub = ProgressSubscriber(fake_redis, scan_id="scn_p4")

    # Replay both historical events.
    replayed = []
    last_id = "-"
    async for entry_id, event in sub.replay(since_id="-"):
        replayed.append(event)
        last_id = entry_id

    assert [e["i"] for e in replayed] == [1, 2]
    assert last_id == eid_2

    # Now live-tail from last replayed id; publish a new one.
    received_live: list[dict] = []

    async def consume_live():
        async for entry_id, event in sub.live(last_id=last_id):
            received_live.append(event)
            break

    task = asyncio.create_task(consume_live())
    await asyncio.sleep(0.05)
    await pub.publish({"i": 3})
    await asyncio.wait_for(task, timeout=3.0)

    # Seamless: the replay covered 1+2, live picked up only 3 (no
    # duplicate of 2, no skip of 3).
    assert received_live == [{"i": 3}]


@pytest.mark.asyncio
async def test_progress_stream_max_len_caps_history(fake_redis):
    """Sustained publishes don't unbound the stream — MAXLEN trims.
    Approximate trim allows up to ~10% over the cap; cap is 1000."""
    pub = ProgressPublisher(fake_redis, scan_id="scn_p5")
    for i in range(2000):
        await pub.publish({"i": i})
    final_len = await fake_redis.xlen("shieldscan:progress:scn_p5")
    # Allow generous headroom over the 1000 nominal MAXLEN —
    # fakeredis's approximate trim is fairly tight in practice
    # (it usually trims to almost-exactly 1000), but we don't pin
    # to that since the underlying behavior is implementation-
    # defined per Redis semantics.
    assert final_len <= 1100, f"stream grew to {final_len}, expected ≤ 1100"
    assert final_len >= 100, "stream should retain a meaningful tail"


# ============================================================ CancelPublisher — 11


@pytest.mark.asyncio
async def test_publish_cancel_emits_pubsub_message(fake_redis):
    """Cancel is one-shot live-only Pub/Sub (NOT Streams).
    Worker that wasn't subscribed when cancel emits cannot usefully
    consume a stale cancel — fire-and-forget is correct."""
    cancel = CancelPublisher(fake_redis)

    pubsub = fake_redis.pubsub()
    await pubsub.subscribe("shieldscan:cancel:scn_c1")
    # Drain the subscription-ack message via listen() async iterator —
    # fakeredis's get_message timing is unreliable, listen() is the
    # canonical pattern (already used in test_domain_verify.py).
    received_event: dict | None = None

    async def consume():
        nonlocal received_event
        async for message in pubsub.listen():
            if message["type"] == "message":
                received_event = json.loads(message["data"])
                break

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.05)
    await cancel.publish_cancel("scn_c1", reason="user_requested")
    await asyncio.wait_for(task, timeout=3.0)

    assert received_event is not None
    assert received_event["event_type"] == "cancel_requested"
    assert received_event["scan_id"] == "scn_c1"
    assert received_event["reason"] == "user_requested"
    await pubsub.aclose()


# ============================================================ cross-primitive — 12


@pytest.mark.asyncio
async def test_separate_scan_ids_have_independent_streams(fake_redis):
    """Tenant-isolation-style pin at the Redis-key level: events for
    scn_a must NOT leak into scn_b's subscriber. Different scan_ids
    keyed onto different Stream keys."""
    pub_a = ProgressPublisher(fake_redis, scan_id="scn_a")
    pub_b = ProgressPublisher(fake_redis, scan_id="scn_b")

    await pub_a.publish({"src": "a", "i": 1})
    await pub_a.publish({"src": "a", "i": 2})
    await pub_b.publish({"src": "b", "i": 1})

    sub_a = ProgressSubscriber(fake_redis, scan_id="scn_a")
    a_events = []
    async for _, event in sub_a.replay(since_id="-"):
        a_events.append(event)

    sub_b = ProgressSubscriber(fake_redis, scan_id="scn_b")
    b_events = []
    async for _, event in sub_b.replay(since_id="-"):
        b_events.append(event)

    assert all(e["src"] == "a" for e in a_events)
    assert all(e["src"] == "b" for e in b_events)
    assert len(a_events) == 2
    assert len(b_events) == 1
