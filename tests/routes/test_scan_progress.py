"""Tests for SSE scan-progress endpoint (Task 4.4).

12 tests split across two surfaces:

  HTTP-level (4): connect-time auth/404 paths via the FastAPI client.
    These do NOT iterate the SSE body — sse-starlette + httpx
    ASGITransport buffer streaming chunks unreliably, making
    end-to-end body asserts hang on empty reads. We only assert
    status codes for the connection-establishment paths.

  Generator-level (8): event-flow contract via direct iteration of
    ``progress_generator`` (the module-level async function extracted
    in this task specifically to make event-flow testing tractable).
    These exercise the load-bearing semantics: live, replay, replay-
    then-live transition, format compliance, concurrency.

  HTTP-level:
   1. unauthenticated → 401
   2. cross-tenant scan_id → 404
   3. nonexistent scan → 404
   4. _parse_last_event_id graceful degradation cases (unit pin)

  Generator-level:
   5. live: published event yielded as SSE-shaped dict
   6. live: multiple events yielded in stream-id order
   7. concurrent generators on same scan both receive published event
   8. no Last-Event-ID → skips history (only future events)
   9. with Last-Event-ID → replays events strictly after that id
  10. replay-then-live transition is seamless (no skip, no duplicate)
  11. event format compliance: id/event/data keys per SPEC §6.4
  12. terminal scan replay: pre-published events come through XRANGE
"""

from __future__ import annotations

import asyncio
import json
from uuid import uuid4

import pytest
import pytest_asyncio

from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.scans import Scan, ScanStatus, ScanType
from app.routes.scans import _parse_last_event_id, progress_generator
from app.services.auth import create_access_token, hash_password
from app.services.scan_queue import ProgressPublisher
from tests.conftest import use_org


# ---------------------------------------------------------------- fixtures (HTTP-level)


@pytest_asyncio.fixture
async def progress_setup(client, db_session):
    """Org + admin + project + active scan + JWT/API-key headers.
    Used only by HTTP-level tests (1-3); generator-level tests use
    fake_redis + a fabricated scan_id directly."""
    org = Organization(name="SSE Org", slug=f"sse-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    user = User(
        email=f"sse-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("SsePass-1"),
        full_name="SSE",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )

    project = Project(
        organization_id=org.id,
        name="SSEApp",
        target_url="https://sse.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.QUICK,
        status=ScanStatus.RUNNING,
        priority="normal",
        config={},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    return {
        "org": org,
        "user": user,
        "scan": scan,
        "headers": {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"},
    }


@pytest_asyncio.fixture
async def other_org_scan(db_session):
    """Second org with its own scan — for cross-tenant test."""
    org = Organization(name="Other SSE Org", slug=f"oth-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"oth-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("OthPass-1"),
        full_name="Oth",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    project = Project(
        organization_id=org.id,
        name="OthApp",
        target_url="https://oth.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()
    scan = Scan(
        organization_id=org.id, project_id=project.id,
        scan_type=ScanType.QUICK, status=ScanStatus.RUNNING,
        priority="normal", config={},
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    return {"org": org, "scan": scan}


def _url(s):
    return f"/v1/orgs/{s['org'].id}/scans/{s['scan'].id}/progress"


# ============================================================ 1-3. HTTP-level connect tests


@pytest.mark.asyncio
async def test_progress_unauthenticated_returns_401(progress_setup, client):
    s = progress_setup
    r = await client.get(_url(s))
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_progress_cross_tenant_returns_404(progress_setup, other_org_scan, client):
    """Existence-hiding pin: scan_id from another org → 404, NOT a
    200 response with an empty stream. Stream must NOT establish
    for cross-tenant references."""
    s = progress_setup
    other = other_org_scan
    url = f"/v1/orgs/{s['org'].id}/scans/{other['scan'].id}/progress"
    r = await client.get(url, headers=s["headers"])
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_progress_nonexistent_scan_returns_404(progress_setup, client):
    s = progress_setup
    url = f"/v1/orgs/{s['org'].id}/scans/{uuid4()}/progress"
    r = await client.get(url, headers=s["headers"])
    assert r.status_code == 404


# ============================================================ 4. Last-Event-ID parser pin


def test_parse_last_event_id_handles_all_cases():
    """Unit pin for _parse_last_event_id graceful-degradation cases.

    Empty/None/malformed → "$" (live-only). Well-formed Redis stream
    id → echoed. "-" → echoed (replay all). DRIFT-LOG: rejecting
    malformed ids would break reconnect-recovery for clients with
    stale state — degrade gracefully instead.
    """
    assert _parse_last_event_id(None) == "$"
    assert _parse_last_event_id("") == "$"
    assert _parse_last_event_id("   ") == "$"
    assert _parse_last_event_id("-") == "-"
    assert _parse_last_event_id("1730000000000-0") == "1730000000000-0"
    assert _parse_last_event_id("1730000000000-42") == "1730000000000-42"
    # Malformed → degrade gracefully to "$"
    assert _parse_last_event_id("not-a-stream-id") == "$"
    assert _parse_last_event_id("123abc-0") == "$"
    assert _parse_last_event_id("123") == "$"


# ============================================================ helpers (generator-level)


async def _collect(gen, n: int, timeout: float = 3.0) -> list[dict]:
    """Drive a progress_generator for ``n`` events with a timeout.
    Cancels the generator after the n-th event so the test exits
    cleanly without waiting on the live phase's blocking XREAD."""
    received = []

    async def _consume():
        async for event in gen:
            received.append(event)
            if len(received) >= n:
                break

    await asyncio.wait_for(_consume(), timeout=timeout)
    return received


# ============================================================ 5-7. live event delivery


@pytest.mark.asyncio
async def test_progress_live_yields_published_event(fake_redis):
    """Plan-literal happy path: publish to the Stream, generator
    yields the event with id/event/data keys."""
    scan_id = str(uuid4())
    publisher = ProgressPublisher(fake_redis, scan_id=scan_id)

    gen = progress_generator(fake_redis, scan_id, "$")

    async def _publish_then_collect():
        # Tiny gap so the consumer's XREAD BLOCK is parked first.
        await asyncio.sleep(0.05)
        await publisher.publish(
            {"event_type": "job_progress", "engine": "nuclei", "progress": 50}
        )

    publish_task = asyncio.create_task(_publish_then_collect())
    try:
        events = await _collect(gen, 1)
    finally:
        publish_task.cancel()
        await gen.aclose()

    assert len(events) == 1
    assert events[0]["event"] == "job_progress"
    assert json.loads(events[0]["data"])["progress"] == 50


@pytest.mark.asyncio
async def test_progress_live_yields_multiple_events_in_order(fake_redis):
    scan_id = str(uuid4())
    publisher = ProgressPublisher(fake_redis, scan_id=scan_id)
    gen = progress_generator(fake_redis, scan_id, "$")

    async def _publish_three():
        await asyncio.sleep(0.05)
        await publisher.publish({"event_type": "job_progress", "i": 1})
        await publisher.publish({"event_type": "job_progress", "i": 2})
        await publisher.publish({"event_type": "job_progress", "i": 3})

    task = asyncio.create_task(_publish_three())
    try:
        events = await _collect(gen, 3)
    finally:
        task.cancel()
        await gen.aclose()

    assert [json.loads(e["data"])["i"] for e in events] == [1, 2, 3]


@pytest.mark.asyncio
async def test_progress_concurrent_generators_both_receive(fake_redis):
    """Two generators on the same scan_id both receive a published
    event. Validates that the underlying XREAD pattern is not using
    consumer-groups (which would deliver each event to exactly one
    of the two readers)."""
    scan_id = str(uuid4())
    publisher = ProgressPublisher(fake_redis, scan_id=scan_id)

    gen_a = progress_generator(fake_redis, scan_id, "$")
    gen_b = progress_generator(fake_redis, scan_id, "$")

    async def _publish():
        await asyncio.sleep(0.1)
        await publisher.publish({"event_type": "job_progress", "i": 42})

    task = asyncio.create_task(_publish())
    try:
        events_a, events_b = await asyncio.gather(
            _collect(gen_a, 1),
            _collect(gen_b, 1),
        )
    finally:
        task.cancel()
        await gen_a.aclose()
        await gen_b.aclose()

    assert json.loads(events_a[0]["data"])["i"] == 42
    assert json.loads(events_b[0]["data"])["i"] == 42


# ============================================================ 8-10. Last-Event-ID replay


@pytest.mark.asyncio
async def test_progress_no_last_event_id_skips_history(fake_redis):
    """last_event_id="$" → no replay; only events emitted after the
    generator starts. Pre-published events 1+2 should NOT arrive;
    only the live event 3."""
    scan_id = str(uuid4())
    publisher = ProgressPublisher(fake_redis, scan_id=scan_id)
    await publisher.publish({"event_type": "scan_status", "i": 1})
    await publisher.publish({"event_type": "scan_status", "i": 2})

    gen = progress_generator(fake_redis, scan_id, "$")

    async def _publish_live():
        await asyncio.sleep(0.05)
        await publisher.publish({"event_type": "scan_status", "i": 3})

    task = asyncio.create_task(_publish_live())
    try:
        events = await _collect(gen, 1)
    finally:
        task.cancel()
        await gen.aclose()

    assert json.loads(events[0]["data"])["i"] == 3


@pytest.mark.asyncio
async def test_progress_with_last_event_id_replays_after_id(fake_redis):
    """Pre-publish 3 events. Generator with last_event_id = event 2's
    stream id should replay events strictly after event 2, yielding
    only event 3."""
    scan_id = str(uuid4())
    publisher = ProgressPublisher(fake_redis, scan_id=scan_id)
    await publisher.publish({"event_type": "scan_status", "i": 1})
    eid_2 = await publisher.publish({"event_type": "scan_status", "i": 2})
    eid_3 = await publisher.publish({"event_type": "scan_status", "i": 3})

    gen = progress_generator(fake_redis, scan_id, eid_2)
    try:
        events = await _collect(gen, 1)
    finally:
        await gen.aclose()

    assert len(events) == 1
    assert events[0]["id"] == eid_3
    assert json.loads(events[0]["data"])["i"] == 3


@pytest.mark.asyncio
async def test_progress_replay_then_live_seamless(fake_redis):
    """Pre-publish 2 events. Generator with last_event_id="-" replays
    both, then publish a 3rd live; generator yields it. Verifies the
    XRANGE → XREAD-from-id seamless transition pinned by 4.1's wrapper
    test."""
    scan_id = str(uuid4())
    publisher = ProgressPublisher(fake_redis, scan_id=scan_id)
    eid_1 = await publisher.publish({"event_type": "scan_status", "i": 1})
    eid_2 = await publisher.publish({"event_type": "scan_status", "i": 2})

    gen = progress_generator(fake_redis, scan_id, "-")
    received = []

    async def _drive():
        async for event in gen:
            received.append(event)
            if len(received) == 2:
                # History replayed; publish a live event.
                await publisher.publish({"event_type": "scan_status", "i": 3})
            elif len(received) == 3:
                break

    try:
        await asyncio.wait_for(_drive(), timeout=3.0)
    finally:
        await gen.aclose()

    assert [json.loads(e["data"])["i"] for e in received] == [1, 2, 3]
    assert received[0]["id"] == eid_1
    assert received[1]["id"] == eid_2
    # No duplicate, no skip — live event 3 has a fresh id.
    assert received[2]["id"] != eid_2


# ============================================================ 11. format compliance


@pytest.mark.asyncio
async def test_progress_event_format_compliance(fake_redis):
    """Each yielded event has 'id', 'event', and 'data' keys per
    SPEC §6.4 SSE format. id is the actual Redis Stream id; event
    matches event_type; data is JSON-serialized payload."""
    scan_id = str(uuid4())
    publisher = ProgressPublisher(fake_redis, scan_id=scan_id)
    await publisher.publish(
        {"event_type": "finding_discovered", "severity": "high"}
    )

    gen = progress_generator(fake_redis, scan_id, "-")
    try:
        events = await _collect(gen, 1)
    finally:
        await gen.aclose()

    event = events[0]
    assert set(event.keys()) == {"id", "event", "data"}
    # id is a Redis Stream id: <ms>-<seq>.
    parts = event["id"].split("-")
    assert len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit()
    # event matches the published event_type.
    assert event["event"] == "finding_discovered"
    # data is JSON containing the original payload.
    parsed = json.loads(event["data"])
    assert parsed["severity"] == "high"


# ============================================================ 12. terminal scan replay


@pytest.mark.asyncio
async def test_progress_terminal_scan_replays_via_xrange(fake_redis):
    """Terminal scan: pre-published events come through XRANGE replay.
    No new live events arrive (workers don't publish to terminal
    scans). Generator returns the historical events to the consumer."""
    scan_id = str(uuid4())
    publisher = ProgressPublisher(fake_redis, scan_id=scan_id)
    await publisher.publish({"event_type": "scan_status", "i": 1})
    await publisher.publish({"event_type": "scan_status", "i": 2})

    gen = progress_generator(fake_redis, scan_id, "-")
    try:
        events = await _collect(gen, 2)
    finally:
        await gen.aclose()

    assert [json.loads(e["data"])["i"] for e in events] == [1, 2]
