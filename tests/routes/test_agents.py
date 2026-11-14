"""On-prem agents: management, enrolment, gateway, routing (M14 slice 1)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio

from app.config import settings
from app.models.agents import Agent
from app.models.billing import OrgLimitOverride
from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.scans import ScanJob
from app.services.agents import agent_queue_key
from app.services.auth import create_access_token, hash_password
from app.services.plans import invalidate_limits
from tests.conftest import use_org


@pytest_asyncio.fixture
async def ctx(client, db_session, fake_redis):
    """Org on Free + an override agents.max=2 (Free has 0), an admin, a
    member, and an agent-bound project whose target is a loopback URL."""
    org = Organization(name="Agent Org", slug=f"ag-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    admin = User(
        email=f"adm-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("Pw-12345!"),
        full_name="Adm",
        email_verified=True,
    )
    member = User(
        email=f"mem-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("Pw-12345!"),
        full_name="Mem",
        email_verified=True,
    )
    db_session.add_all([admin, member])
    await db_session.flush()
    db_session.add_all(
        [
            Membership(user_id=admin.id, organization_id=org.id, role=MembershipRole.ADMIN),
            Membership(user_id=member.id, organization_id=org.id, role=MembershipRole.MEMBER),
            OrgLimitOverride(organization_id=org.id, key="agents.max", value=2, reason="test"),
            OrgLimitOverride(organization_id=org.id, key="projects.max", value=5, reason="test"),
        ]
    )
    project = Project(
        organization_id=org.id,
        name="Intranet ERP",
        target_url="http://10.0.0.5:8080",
        root_domain="10.0.0.5",
        domain_verified=False,
    )
    db_session.add(project)
    await db_session.commit()
    await invalidate_limits(fake_redis, org.id)
    settings.PLAN_LIMITS_ENFORCED = True
    yield {
        "org": org,
        "project": project,
        "admin": {"Authorization": f"Bearer {create_access_token(sub=str(admin.id))}"},
        "member": {"Authorization": f"Bearer {create_access_token(sub=str(member.id))}"},
    }
    settings.PLAN_LIMITS_ENFORCED = False


async def _create_and_enrol(client, c, name="dc1"):
    r = await client.post(f"/v1/orgs/{c['org'].id}/agents", json={"name": name}, headers=c["admin"])
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["agent"]["status"] == "pending" and created["enrolment_token"].startswith(
        "ss_enrol_"
    )
    assert "shieldscan-agent enroll" in created["enrol_command"]
    r = await client.post(
        "/v1/agent/enroll",
        json={
            "token": created["enrolment_token"],
            "version": "0.1.0",
            "hostname": "dc1.corp",
            "platform": "linux/amd64",
        },
    )
    assert r.status_code == 201, r.text
    enrolled = r.json()
    assert (
        enrolled["agent_key"].startswith("ss_agent_")
        and enrolled["agent_id"] == created["agent"]["id"]
    )
    return created["agent"]["id"], {"Authorization": f"Bearer {enrolled['agent_key']}"}


@pytest.mark.asyncio
async def test_create_enrol_heartbeat_list_revoke(client, ctx):
    c = ctx
    # Members cannot create agents; admins can.
    r = await client.post(f"/v1/orgs/{c['org'].id}/agents", json={"name": "x"}, headers=c["member"])
    assert r.status_code == 403
    agent_id, akey = await _create_and_enrol(client, c)

    # The token is one-time.
    r = await client.get(f"/v1/orgs/{c['org'].id}/agents", headers=c["member"])
    assert r.status_code == 200
    me = r.json()["agents"][0]
    assert (
        me["status"] == "active"
        and me["hostname"] == "dc1.corp"
        and me["key_prefix"].startswith("ss_agent_")
    )

    # Heartbeat carries tool health; the list shows it. Bad keys are 401.
    r = await client.post(
        "/v1/agent/heartbeat",
        json={"tools": {"nuclei": {"status": "ok", "version": "3.3"}}},
        headers=akey,
    )
    assert r.status_code == 200, r.text
    assert r.json()["cancel_scan_ids"] == [] and r.json()["poll_wait_s"] == 25
    r = await client.post(
        "/v1/agent/heartbeat", json={}, headers={"Authorization": "Bearer ss_agent_nope"}
    )
    assert r.status_code == 401
    r = await client.post(
        "/v1/agent/heartbeat", json={}, headers=c["admin"]
    )  # a JWT is not an agent key
    assert r.status_code == 401
    r = await client.get(f"/v1/orgs/{c['org'].id}/agents", headers=c["admin"])
    assert r.json()["agents"][0]["tools"]["nuclei"]["status"] == "ok"

    # Plan cap: agents.max=2 → the third create is a 402.
    await _create_and_enrol(client, c, name="dc2")
    r = await client.post(
        f"/v1/orgs/{c['org'].id}/agents", json={"name": "dc3"}, headers=c["admin"]
    )
    assert r.status_code == 402 and r.json()["detail"]["key"] == "agents.max"

    # Revoke: key dies at once.
    r = await client.delete(f"/v1/orgs/{c['org'].id}/agents/{agent_id}", headers=c["admin"])
    assert r.status_code == 204
    r = await client.post("/v1/agent/heartbeat", json={}, headers=akey)
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_enrol_rejects_unknown_expired_and_reused_tokens(client, ctx, db_session):
    c = ctx
    r = await client.post("/v1/agent/enroll", json={"token": "ss_enrol_nope"})
    assert r.status_code == 401
    r = await client.post(
        f"/v1/orgs/{c['org'].id}/agents", json={"name": "late"}, headers=c["admin"]
    )
    token = r.json()["enrolment_token"]
    agent = await db_session.get(Agent, r.json()["agent"]["id"])
    agent.enrolment_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    await db_session.commit()
    r = await client.post("/v1/agent/enroll", json={"token": token})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_bind_project_routes_scan_through_the_agent(client, ctx, db_session, fake_redis):
    c = ctx
    org, project = c["org"], c["project"]
    agent_id, akey = await _create_and_enrol(client, c)

    # Unbound + unverified → a full scan is refused as before (quick/mobile/
    # container never needed verification).
    r = await client.post(
        f"/v1/orgs/{org.id}/projects/{project.id}/scans",
        json={"scan_type": "full_web"},
        headers=c["admin"],
    )
    assert r.status_code == 403

    # Members cannot bind; admins can; an unknown agent is 404.
    r = await client.patch(
        f"/v1/orgs/{org.id}/projects/{project.id}", json={"agent_id": agent_id}, headers=c["member"]
    )
    assert r.status_code == 403
    r = await client.patch(
        f"/v1/orgs/{org.id}/projects/{project.id}",
        json={"agent_id": str(uuid4())},
        headers=c["admin"],
    )
    assert r.status_code == 404
    r = await client.patch(
        f"/v1/orgs/{org.id}/projects/{project.id}", json={"agent_id": agent_id}, headers=c["admin"]
    )
    assert r.status_code == 200, r.text
    assert r.json()["agent_id"] == agent_id and r.json()["domain_verified"] is False

    # Offline agent → 409 agent_offline, nothing queued.
    agent = await db_session.get(Agent, agent_id)
    agent.last_seen_at = datetime.now(timezone.utc) - timedelta(
        seconds=settings.AGENT_OFFLINE_AFTER_S + 5
    )
    await db_session.commit()
    r = await client.post(
        f"/v1/orgs/{org.id}/projects/{project.id}/scans",
        json={"scan_type": "quick"},
        headers=c["admin"],
    )
    assert r.status_code == 409 and r.json()["detail"]["error"] == "agent_offline"
    assert await fake_redis.llen(agent_queue_key(agent.id)) == 0

    # Heartbeat brings it back; a mobile scan is refused on an agent; a quick scan is queued to the agent, not the cloud.
    assert (await client.post("/v1/agent/heartbeat", json={}, headers=akey)).status_code == 200
    r = await client.post(
        f"/v1/orgs/{org.id}/projects/{project.id}/scans",
        json={"scan_type": "container"},
        headers=c["admin"],
    )
    assert r.status_code == 422
    r = await client.post(
        f"/v1/orgs/{org.id}/projects/{project.id}/scans",
        json={"scan_type": "quick"},
        headers=c["admin"],
    )
    assert r.status_code == 201, r.text
    scan_id = r.json()["id"]
    assert await fake_redis.llen(agent_queue_key(agent.id)) >= 1
    for prio in ("critical", "high", "normal", "low"):
        assert await fake_redis.llen(f"shieldscan:queue:{prio}") == 0

    # Long-poll hands the job out and leases it; a second poll is empty.
    r = await client.get("/v1/agent/jobs", params={"wait": 0}, headers=akey)
    assert r.status_code == 200, r.text
    job = r.json()
    assert job["scan_id"] == scan_id and job["organization_id"] == str(org.id)
    assert job["target"]["url"] == "http://10.0.0.5:8080"
    leased = await db_session.get(ScanJob, job["id"])
    await db_session.refresh(leased)
    assert (
        leased.agent_id == agent.id and leased.leased_at is not None and leased.status == "running"
    )
    r = await client.get("/v1/agent/jobs", params={"wait": 0}, headers=akey)
    assert r.status_code == 204

    # Progress events land in the scan's stream in the worker's shape.
    r = await client.post(
        f"/v1/agent/jobs/{job['id']}/events",
        json={
            "events": [
                {"event_type": "job_started", "engine": job["engine"]},
                {"event_type": "progress", "percent": 50},
            ]
        },
        headers=akey,
    )
    assert r.status_code == 202 and r.json()["accepted"] == 2
    entries = await fake_redis.xrange(f"shieldscan:progress:{scan_id}")
    assert len(entries) == 2
    first = json.loads(entries[0][1]["event"])
    assert (
        first["event_type"] == "job_started"
        and first["scan_id"] == scan_id
        and "timestamp" in first
    )

    # Completion is published on the completions channel with identity pinned.
    pubsub = fake_redis.pubsub()
    await pubsub.subscribe("shieldscan:completions")
    r = await client.post(
        f"/v1/agent/jobs/{job['id']}/complete",
        json={
            "status": "completed",
            "finding_count": 0,
            "organization_id": str(uuid4()),
            "scan_id": str(uuid4()),
        },
        headers=akey,
    )
    assert r.status_code == 202, r.text
    msg = None
    for _ in range(5):
        msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.5)
        if msg:
            break
    assert msg is not None
    published = json.loads(msg["data"])
    assert published["organization_id"] == str(org.id) and published["scan_id"] == scan_id
    assert published["job_id"] == job["id"] and published["engine"] == job["engine"]
    assert published["event_type"] == "job_completed" and published["event_seq"] == {
        "index": 1,
        "total": 1,
    }

    # Another org's agent cannot touch this job.
    r = await client.post(
        f"/v1/agent/jobs/{job['id']}/fail",
        json={"error_message": "x"},
        headers={"Authorization": "Bearer ss_agent_zzz"},
    )
    assert r.status_code == 401

    # Revoking the agent unbinds the project.
    r = await client.delete(f"/v1/orgs/{org.id}/agents/{agent_id}", headers=c["admin"])
    assert r.status_code == 204
    await db_session.refresh(project)
    assert project.agent_id is None


@pytest.mark.asyncio
async def test_http_target_allowed_only_for_private_hosts(client, ctx):
    c = ctx
    r = await client.post(
        f"/v1/orgs/{c['org'].id}/projects",
        json={"name": "pub", "target_url": "http://example.com"},
        headers=c["admin"],
    )
    assert r.status_code == 422
    for url in (
        "http://192.168.1.20",
        "http://127.0.0.1:3000",
        "http://erp.corp",
        "http://intranet",
    ):
        r = await client.post(
            f"/v1/orgs/{c['org'].id}/projects",
            json={"name": url, "target_url": url},
            headers=c["admin"],
        )
        assert r.status_code == 201, (url, r.text)
