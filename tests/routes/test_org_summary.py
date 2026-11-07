"""Tests for GET /v1/orgs/{org_id}/summary (M11 pre-work).

Scenarios:
  1. unauthenticated → 401; non-member → 404
  2. empty org → zeros and no last scan
  3. populated org → project split, scan counts (active / 30d), open
     vulnerabilities by severity with corroborated count, last finished
     scan carrying raw→unique counts
  4. resolved / false-positive vulnerabilities and archived projects are
     excluded; a scan finished 40 days ago is outside completed_30d
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from app.models.raw_findings import Severity
from app.models.scans import ScanStatus, ScanType
from app.models.vulnerabilities import Vulnerability, VulnerabilityStatus
from app.services.auth import create_access_token
from tests.routes.test_scan_reads import (
    _mk_job,
    _mk_org,
    _mk_project,
    _mk_raw,
    _mk_scan,
    _mk_vuln,
)


def _url(org_id):
    return f"/v1/orgs/{org_id}/summary"


@pytest_asyncio.fixture
async def empty_org(client, db_session):
    org, user = await _mk_org(db_session, "em")
    await db_session.commit()
    return {
        "org": org,
        "headers": {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"},
    }


@pytest_asyncio.fixture
async def rich_org(client, db_session):
    org, user = await _mk_org(db_session, "rich")
    p_ok = await _mk_project(db_session, org, "Shop", "https://shop.example.com")
    p_unv = await _mk_project(db_session, org, "Blog", "https://blog.example.com")
    p_unv.domain_verified = False
    p_arch = await _mk_project(db_session, org, "Old", "https://old.example.com")
    p_arch.archived_at = datetime.now(timezone.utc)

    now = datetime.now(timezone.utc)
    s_done = await _mk_scan(db_session, org, p_ok, status=ScanStatus.COMPLETED)
    s_done.completed_at = now - timedelta(hours=3)
    s_part = await _mk_scan(db_session, org, p_ok, status=ScanStatus.PARTIAL)
    s_part.completed_at = now - timedelta(days=2)
    s_stale = await _mk_scan(db_session, org, p_unv, scan_type=ScanType.QUICK,
                             status=ScanStatus.COMPLETED)
    s_stale.completed_at = now - timedelta(days=40)
    await _mk_scan(db_session, org, p_ok, status=ScanStatus.RUNNING)
    await _mk_scan(db_session, org, p_ok, status=ScanStatus.QUEUED)
    await _mk_scan(db_session, org, p_ok, status=ScanStatus.FAILED)

    await _mk_job(db_session, org, s_done, "nuclei", "completed", findings=10)
    await _mk_raw(db_session, org, s_done, 12)
    await _mk_vuln(db_session, org, s_done, p_ok, Severity.CRITICAL)
    await _mk_vuln(db_session, org, s_done, p_ok, Severity.HIGH)
    await _mk_vuln(db_session, org, s_done, p_ok, Severity.MEDIUM)
    await _mk_vuln(db_session, org, s_part, p_ok, Severity.HIGH)
    await _mk_vuln(db_session, org, s_part, p_ok, Severity.LOW)
    await db_session.flush()

    # One corroborated open critical; one resolved high; one false-positive low.
    vulns = (await db_session.execute(
        Vulnerability.__table__.select().where(Vulnerability.organization_id == org.id)
    )).all()
    ids = {(v.severity, v.scan_id): v.id for v in vulns}
    crit = await db_session.get(Vulnerability, ids[(Severity.CRITICAL, s_done.id)])
    crit.corroborated_count = 2
    hi_part = await db_session.get(Vulnerability, ids[(Severity.HIGH, s_part.id)])
    hi_part.status = VulnerabilityStatus.RESOLVED
    low_part = await db_session.get(Vulnerability, ids[(Severity.LOW, s_part.id)])
    low_part.status = VulnerabilityStatus.FALSE_POSITIVE

    await db_session.commit()
    await db_session.refresh(s_done)
    return {
        "org": org,
        "p_ok": p_ok,
        "s_done": s_done,
        "headers": {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"},
    }


@pytest.mark.asyncio
async def test_summary_auth(client, empty_org, rich_org):
    assert (await client.get(_url(empty_org["org"].id))).status_code == 401
    # rich_org's member asking for empty_org's summary → 404 (membership gate)
    r = await client.get(_url(empty_org["org"].id), headers=rich_org["headers"])
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_summary_empty_org(client, empty_org):
    r = await client.get(_url(empty_org["org"].id), headers=empty_org["headers"])
    assert r.status_code == 200
    body = r.json()
    assert body["projects"] == {"total": 0, "verified": 0, "unverified": 0}
    assert body["scans"] == {"total": 0, "active": 0, "completed_30d": 0}
    assert body["open_vulnerabilities"]["total"] == 0
    assert body["last_completed_scan"] is None


@pytest.mark.asyncio
async def test_summary_populated_org(client, rich_org):
    r = await client.get(_url(rich_org["org"].id), headers=rich_org["headers"])
    assert r.status_code == 200
    body = r.json()

    # Archived project excluded; unverified counted.
    assert body["projects"] == {"total": 2, "verified": 1, "unverified": 1}

    # 6 scans total; RUNNING + QUEUED active; COMPLETED(3h) + PARTIAL(2d)
    # inside 30d, the 40-day-old one outside, FAILED never counts.
    assert body["scans"] == {"total": 6, "active": 2, "completed_30d": 2}

    # Open only: critical 1 (corroborated), high 1 (the resolved one is
    # out), medium 1; low was marked false-positive.
    assert body["open_vulnerabilities"] == {
        "critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0,
        "total": 3, "corroborated": 1,
    }

    last = body["last_completed_scan"]
    assert last["id"] == str(rich_org["s_done"].id)
    assert last["project_name"] == "Shop"
    assert last["status"] == "completed"
    assert last["raw_finding_count"] == 12
    assert last["vulnerability_count"] == 3
