"""Tests for the public quick-scan endpoints (M11 pre-work).

    POST /v1/public/quick-scans
    GET  /v1/public/quick-scans/{slug}

Scenarios:
  1. validation: http target, missing consent, bad email → 422;
     bare hostname is accepted and normalised to https://
  2. happy path: 202 with slug + result URL; system org + project +
     Scan(is_public, QUICK) + PublicScan created; QUICK tools dispatched
     directly (no recon job); result link emailed; SCAN_DISPATCHED audited
     with no actor
  3. second scan of the same domain reuses the system project
  4. rate limits: IP hourly (429 rate_limited + Retry-After), email daily
     (429 email_limit_reached)
  5. GET: unknown slug 404; queued result shape; completed result shows
     score/grade, top-3 findings by severity, hidden_count, counts;
     viewed_count increments; expired → status "expired", no findings
  6. consumer: public scan with raw findings finalises COMPLETED inline
     (no AI pipeline enqueue), completed_at stamped
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.config import settings
from app.db.tenant_context import set_tenant_context
from app.models.audit import AuditLog
from app.models.identity import Organization
from app.models.projects import Project
from app.models.public_scans import PublicScan
from app.models.raw_findings import EngineCategory, RawFinding, Severity
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.services.completions_consumer import CompletionsConsumer
from app.services.public_scans import score_and_grade

URL = "/v1/public/quick-scans"


def _payload(**over):
    base = {
        "target_url": f"https://{uuid4().hex[:8]}.example.com/app",
        "email": f"owner-{uuid4().hex[:6]}@acme.com",
        "consent": True,
    }
    base.update(over)
    return base


async def _public_org(db_session) -> Organization:
    org = (
        await db_session.execute(
            select(Organization).where(Organization.slug == settings.PUBLIC_SCAN_ORG_SLUG)
        )
    ).scalar_one()
    await set_tenant_context(db_session, org.id)
    return org


async def _finish(db_session, org, slug: str, findings: list[tuple[Severity, str]]):
    """Mark the scan finished with the given raw findings (bypassing the
    consumer) so GET can be exercised deterministically."""
    public = (
        await db_session.execute(select(PublicScan).where(PublicScan.slug == slug))
    ).scalar_one()
    scan = await db_session.get(Scan, public.scan_id)
    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.now(timezone.utc)
    jobs = (
        (await db_session.execute(select(ScanJob).where(ScanJob.scan_id == scan.id)))
        .scalars()
        .all()
    )
    for j in jobs:
        j.status = "completed"
    for sev, title in findings:
        db_session.add(
            RawFinding(
                organization_id=org.id,
                scan_id=scan.id,
                tool_name="nuclei",
                engine_category=EngineCategory.DAST,
                finding_type="misconfiguration",
                severity=sev,
                title=title,
                description=f"{title} — details",
                target_url=public.target_url,
                fingerprint=uuid4().hex,
            )
        )
    await db_session.commit()
    return public, scan


# ---------------------------------------------------------------- validation


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        {"target_url": "http://plain.example.com"},
        {"consent": False},
        {"email": "not-an-email"},
        {"target_url": "https://user:pw@h.example.com"},
    ],
)
async def test_create_validation(client, bad):
    r = await client.post(URL, json=_payload(**bad))
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_create_accepts_bare_hostname(client):
    r = await client.post(URL, json=_payload(target_url="Shop.Example.com/"))
    assert r.status_code == 202, r.text
    assert r.json()["target_url"] == "https://shop.example.com"


# ---------------------------------------------------------------- create


@pytest.mark.asyncio
async def test_create_happy_path(client, db_session, fake_redis, email_service_stub):
    payload = _payload(target_url="https://shop.example.com/app", email="Owner@Acme.com")
    r = await client.post(URL, json=payload)
    assert r.status_code == 202, r.text
    body = r.json()
    slug = body["slug"]
    assert len(slug) >= 20
    assert body["status"] == "queued"
    assert body["result_url"] == f"{settings.APP_BASE_URL}/q/{slug}"
    assert r.headers["Location"] == f"{URL}/{slug}"

    org = await _public_org(db_session)
    public = (
        await db_session.execute(select(PublicScan).where(PublicScan.slug == slug))
    ).scalar_one()
    assert public.email == "owner@acme.com"
    assert public.normalized_domain == "shop.example.com"
    assert public.organization_id == org.id
    assert public.expires_at > datetime.now(timezone.utc) + timedelta(days=6)

    scan = await db_session.get(Scan, public.scan_id)
    assert scan.is_public is True
    assert scan.public_slug == slug
    assert scan.scan_type == ScanType.QUICK
    assert scan.status == ScanStatus.QUEUED

    project = await db_session.get(Project, public.project_id)
    assert project.name == "shop.example.com"
    assert project.domain_verified is False

    # Direct QUICK tool dispatch on the typed URL — no recon job.
    jobs = (
        (await db_session.execute(select(ScanJob).where(ScanJob.scan_id == scan.id)))
        .scalars()
        .all()
    )
    assert sorted(j.engine for j in jobs) == ["nuclei", "sslyze"]
    assert all(j.target_url == "https://shop.example.com/app" for j in jobs)
    queued = await fake_redis.lrange("shieldscan:queue:normal", 0, -1)
    assert len(queued) == 2
    payloads = [json.loads(q) for q in queued]
    assert all(p["scan_id"] == str(scan.id) for p in payloads)
    assert all(p["target"]["url"] == "https://shop.example.com/app" for p in payloads)
    # Passive template set, no severity filter (see PUBLIC_SCAN_TEMPLATE_TAGS).
    assert all(p["config"]["depth"] == "deep" for p in payloads)
    assert all(
        p["config"]["template_categories"] == ["misconfig", "exposure", "ssl", "dns", "tech"]
        for p in payloads
    )

    # Result link emailed.
    assert len(email_service_stub.outbox) == 1
    mail = email_service_stub.outbox[0]
    assert mail.to == "owner@acme.com"
    assert f"/q/{slug}" in mail.body

    # Dispatch audited as a system action (no actor).
    row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "scan.dispatched", AuditLog.resource_id == scan.id
            )
        )
    ).scalar_one()
    assert row.actor_id is None
    assert row.organization_id == org.id


@pytest.mark.asyncio
async def test_create_reuses_system_project_per_domain(client, db_session):
    r1 = await client.post(URL, json=_payload(target_url="https://reuse.example.com/a"))
    r2 = await client.post(URL, json=_payload(target_url="https://reuse.example.com/b"))
    assert r1.status_code == 202 and r2.status_code == 202
    await _public_org(db_session)
    rows = (
        (
            await db_session.execute(
                select(PublicScan).where(PublicScan.normalized_domain == "reuse.example.com")
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 2
    assert rows[0].project_id == rows[1].project_id
    assert rows[0].scan_id != rows[1].scan_id


# ---------------------------------------------------------------- rate limits


@pytest.mark.asyncio
async def test_ip_hourly_limit(client, monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_SCAN_IP_HOURLY_LIMIT", 2)
    assert (await client.post(URL, json=_payload())).status_code == 202
    assert (await client.post(URL, json=_payload())).status_code == 202
    r = await client.post(URL, json=_payload())
    assert r.status_code == 429
    assert r.json()["detail"] == "rate_limited"
    assert int(r.headers["Retry-After"]) > 0
    # A different client IP is unaffected.
    r = await client.post(URL, json=_payload(), headers={"CF-Connecting-IP": "203.0.113.9"})
    assert r.status_code == 202


@pytest.mark.asyncio
async def test_email_daily_limit(client):
    email = f"once-{uuid4().hex[:6]}@acme.com"
    assert (await client.post(URL, json=_payload(email=email))).status_code == 202
    r = await client.post(URL, json=_payload(email=email.upper()))
    assert r.status_code == 429
    assert r.json()["detail"] == "email_limit_reached"
    # Another address from the same IP still works.
    assert (await client.post(URL, json=_payload())).status_code == 202


# ---------------------------------------------------------------- read


@pytest.mark.asyncio
async def test_get_unknown_slug(client):
    assert (await client.get(f"{URL}/{uuid4().hex}")).status_code == 404
    assert (await client.get(f"{URL}/{'x' * 100}")).status_code == 404


@pytest.mark.asyncio
async def test_get_queued_then_completed(client, db_session):
    r = await client.post(URL, json=_payload(target_url="https://res.example.com"))
    slug = r.json()["slug"]

    r = await client.get(f"{URL}/{slug}")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "queued"
    assert body["engines_total"] == 2 and body["engines_finished"] == 0
    assert body["score"] is None and body["grade"] is None
    assert body["findings"] == [] and body["hidden_count"] == 0
    assert body["domain"] == "res.example.com"
    assert body["register_url"].endswith(f"/register?from={slug}")

    org = await _public_org(db_session)
    public, _ = await _finish(
        db_session,
        org,
        slug,
        [
            (Severity.LOW, "Missing X-Frame-Options"),
            (Severity.HIGH, "Exposed .git directory"),
            (Severity.MEDIUM, "CSP header missing"),
            (Severity.INFO, "Server header reveals nginx"),
            (Severity.MEDIUM, "Cookie without Secure flag"),
        ],
    )

    r = await client.get(f"{URL}/{slug}")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "completed"
    assert body["completed_at"] is not None
    assert body["engines_finished"] == 2
    # 100 - 15 - 7 - 7 - 2 - 0 = 69 → C
    assert body["score"] == 69 and body["grade"] == "C"
    assert body["findings_by_severity"] == {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 1,
        "info": 1,
        "total": 5,
    }
    titles = [f["title"] for f in body["findings"]]
    assert titles == ["Exposed .git directory", "CSP header missing", "Cookie without Secure flag"]
    assert body["findings"][0]["severity"] == "high"
    assert body["findings"][0]["engine"] == "nuclei"
    assert body["findings"][0]["summary"].startswith("Exposed .git directory")
    assert body["hidden_count"] == 2

    await db_session.refresh(public)
    assert public.viewed_count == 2


@pytest.mark.asyncio
async def test_get_expired(client, db_session):
    r = await client.post(URL, json=_payload(target_url="https://old.example.com"))
    slug = r.json()["slug"]
    org = await _public_org(db_session)
    public, _ = await _finish(db_session, org, slug, [(Severity.HIGH, "Something")])
    public.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    await db_session.commit()

    r = await client.get(f"{URL}/{slug}")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "expired"
    assert body["findings"] == []
    assert body["score"] is None
    assert body["findings_by_severity"]["total"] == 0


def test_score_and_grade_thresholds():
    class F:
        def __init__(self, s):
            self.severity = s

    assert score_and_grade([]) == (100, "A")
    assert score_and_grade([F(Severity.MEDIUM)]) == (93, "A")
    assert score_and_grade([F(Severity.HIGH), F(Severity.LOW)]) == (83, "B")
    assert score_and_grade([F(Severity.CRITICAL), F(Severity.HIGH)]) == (55, "D")
    assert score_and_grade([F(Severity.CRITICAL)] * 4) == (0, "F")


# ---------------------------------------------------------------- consumer


@pytest.mark.asyncio
async def test_consumer_finalises_public_scan_without_ai(
    client, db_session, fake_redis, session_factory
):
    r = await client.post(URL, json=_payload(target_url="https://fin.example.com"))
    slug = r.json()["slug"]
    org = await _public_org(db_session)
    public = (
        await db_session.execute(select(PublicScan).where(PublicScan.slug == slug))
    ).scalar_one()
    jobs = (
        (await db_session.execute(select(ScanJob).where(ScanJob.scan_id == public.scan_id)))
        .scalars()
        .all()
    )
    # Raw findings exist → a normal scan would go to ANALYZING here.
    db_session.add(
        RawFinding(
            organization_id=org.id,
            scan_id=public.scan_id,
            tool_name="nuclei",
            engine_category=EngineCategory.DAST,
            finding_type="misconfiguration",
            severity=Severity.MEDIUM,
            title="CSP header missing",
            target_url=public.target_url,
            fingerprint=uuid4().hex,
        )
    )
    await db_session.commit()
    await fake_redis.delete("shieldscan:queue:normal")

    consumer = CompletionsConsumer(session_factory=session_factory, redis=fake_redis)
    for job in jobs:
        await consumer._handle(
            {
                "event_type": "job_completed",
                "job_id": str(job.id),
                "scan_id": str(job.scan_id),
                "organization_id": str(job.organization_id),
                "engine": job.engine,
                "status": "completed",
                "finding_count": 1,
                "duration_ms": 100,
                "idempotency_key": job.idempotency_key,
                "timestamp": "2026-11-07T12:00:00Z",
            }
        )

    async with session_factory() as fresh:
        await set_tenant_context(fresh, org.id)
        scan = (await fresh.execute(select(Scan).where(Scan.id == public.scan_id))).scalar_one()
        assert scan.status == ScanStatus.COMPLETED
        assert scan.completed_at is not None
    assert await fake_redis.llen("shieldscan:ai_pipeline") == 0

    r = await client.get(f"{URL}/{slug}")
    assert r.json()["status"] == "completed"
    assert r.json()["grade"] == "A"
