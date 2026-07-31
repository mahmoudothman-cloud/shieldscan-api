"""End-to-end tests for the M10.D tool-health endpoint (Task 10.6; SPEC §6).

Covers the single org-scoped GET ``/orgs/{org_id}/tools/health`` — the
two-state per-tool availability roll-up derived from the worker heartbeat
fleet signal (``shieldscan:workers:*``). Worker keys are seeded directly
into fakeredis with the exact key/payload shape the engine's
``internal/worker/heartbeat.go`` publishes (no engine dependency).
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
import pytest_asyncio

from app.models.identity import Membership, MembershipRole, Organization, User
from app.services.auth import create_access_token, hash_password
from app.services.tool_health import KNOWN_ENGINES
from tests.conftest import use_org


async def _make_org_member(db_session):
    org = Organization(name="Tools Org", slug=f"toolsorg-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"tools-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("ToolsPass-1"),
        full_name="Tools Admin",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}
    return org, headers


@pytest_asyncio.fixture
async def member_org(db_session):
    """Org + admin user + membership: (org, headers)."""
    return await _make_org_member(db_session)


@pytest_asyncio.fixture
async def other_org_headers(db_session):
    _org, headers = await _make_org_member(db_session)
    return headers


def _seed_worker(fake_redis, worker_id, hostname, engines):
    """SETEX a worker key mirroring the engine heartbeat payload shape."""
    payload = {
        "hostname": hostname,
        "started_at": "2026-07-31T10:00:00Z",
        "concurrency": 4,
        "engines": engines,
        "worker_id": worker_id,
        "registered_at": "2026-07-31T10:00:20.123456789Z",
    }
    return fake_redis.set(
        f"shieldscan:workers:{worker_id}", json.dumps(payload), ex=60
    )


def _tools_by_engine(body):
    return {t["engine"]: t for t in body["tools"]}


@pytest.mark.asyncio
async def test_tool_health_two_worker_rollup(client, fake_redis, member_org):
    """Two live workers with overlapping engines → per-tool availability +
    live-worker counts; a known tool advertised by none → unavailable."""
    org, headers = member_org
    await _seed_worker(fake_redis, "w-alpha", "host-a", ["nuclei", "sslyze", "zap"])
    await _seed_worker(fake_redis, "w-beta", "host-b", ["nuclei", "checkov"])

    r = await client.get(f"/v1/orgs/{org.id}/tools/health", headers=headers)
    assert r.status_code == 200
    body = r.json()

    # Worker list: both present, last-seen + engines surfaced (G1.2 / G1.3).
    assert len(body["workers"]) == 2
    by_id = {w["worker_id"]: w for w in body["workers"]}
    assert by_id["w-alpha"]["hostname"] == "host-a"
    assert by_id["w-alpha"]["last_seen"] == "2026-07-31T10:00:20.123456789Z"
    assert by_id["w-alpha"]["engines"] == ["nuclei", "sslyze", "zap"]

    tools = _tools_by_engine(body)
    assert tools["nuclei"] == {
        "engine": "nuclei",
        "available": True,
        "live_worker_count": 2,
    }
    assert tools["sslyze"]["available"] is True
    assert tools["sslyze"]["live_worker_count"] == 1
    assert tools["checkov"]["live_worker_count"] == 1
    # A known api tool advertised by no live worker → unavailable (G1.1).
    assert tools["mobsf"] == {
        "engine": "mobsf",
        "available": False,
        "live_worker_count": 0,
    }
    assert "checked_at" in body


@pytest.mark.asyncio
async def test_tool_health_zero_workers_all_unavailable(client, fake_redis, member_org):
    """No live workers is a valid state: empty worker list + every known
    tool unavailable (200, not an error)."""
    org, headers = member_org
    r = await client.get(f"/v1/orgs/{org.id}/tools/health", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["workers"] == []
    tools = _tools_by_engine(body)
    # Every known api tool is present and unavailable.
    assert set(tools) == set(KNOWN_ENGINES)
    assert all(t["available"] is False for t in body["tools"])
    assert all(t["live_worker_count"] == 0 for t in body["tools"])


@pytest.mark.asyncio
async def test_tool_health_non_member_404(client, fake_redis, member_org, other_org_headers):
    """A user who is not a member of the org_id path → 404 (ADR-012
    collapse), mirroring the compliance cross-tenant behavior."""
    org, _headers = member_org
    r = await client.get(f"/v1/orgs/{org.id}/tools/health", headers=other_org_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_tool_health_surfaces_unknown_advertised_engine(client, fake_redis, member_org):
    """An engine a worker advertises but the api's known-set doesn't list is
    still surfaced as available (the cross-repo tool-name nuance — normalization
    forward-pinned)."""
    org, headers = member_org
    await _seed_worker(fake_redis, "w-x", "host-x", ["some-future-tool"])
    r = await client.get(f"/v1/orgs/{org.id}/tools/health", headers=headers)
    assert r.status_code == 200
    tools = _tools_by_engine(r.json())
    assert tools["some-future-tool"] == {
        "engine": "some-future-tool",
        "available": True,
        "live_worker_count": 1,
    }


@pytest.mark.skip(
    reason="Drain-awareness forward-pinned: the engine writes NO live worker "
    "drain-status signal (the CLAUDE.md Gotcha 8 `HSET worker:$id status "
    "draining` is an ops-runbook manual command, not written by worker code, "
    "per V-MMD). Availability is derived from heartbeat presence only. When a "
    "real per-tool/drain health signal lands, this asserts a draining worker's "
    "engines are excluded from the available roll-up."
)
@pytest.mark.asyncio
async def test_tool_health_draining_worker_excluded():  # pragma: no cover
    ...
