"""Service-level tests for ``app.services.scan_compare.compute_diff`` —
identity-link version (2026-11-13).

Rows are seeded directly with the links the identity pass writes
(``previous_id`` / ``superseded_by_id`` / ``regression``), so the
partition logic is exercised deterministically without the pipeline.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio

from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.raw_findings import EngineCategory, Severity
from app.models.scans import Scan, ScanStatus, ScanType
from app.models.vulnerabilities import Vulnerability, VulnerabilityStatus
from app.services.auth import hash_password
from app.services.scan_compare import compute_diff, default_baseline
from tests.conftest import use_org


def _vuln(*, scan, title="x", severity=Severity.MEDIUM, status=VulnerabilityStatus.OPEN, **kw):
    return Vulnerability(
        scan_id=scan.id,
        project_id=scan.project_id,
        organization_id=scan.organization_id,
        title=title,
        severity=severity,
        status=status,
        finding_type="xss",
        engine_category=EngineCategory.DAST,
        fingerprint=uuid4().hex,
        **kw,
    )


async def _scan(
    db_session,
    org,
    project,
    *,
    when: datetime,
    scan_type=ScanType.QUICK,
    config=None,
    status=ScanStatus.COMPLETED,
):
    s = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=scan_type,
        status=status,
        priority="normal",
        config=config if config is not None else {"depth": "deep", "template_categories": []},
        created_at=when,
    )
    db_session.add(s)
    await db_session.flush()
    return s


@pytest_asyncio.fixture
async def ctx(db_session):
    org = Organization(name="Cmp Org", slug=f"cmp-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"cm-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("CmPass-1"),
        full_name="Cm",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN))
    project = Project(
        organization_id=org.id,
        name="CmpApp",
        target_url="https://cmp.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()
    t0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
    baseline = await _scan(db_session, org, project, when=t0)
    current = await _scan(db_session, org, project, when=t0 + timedelta(days=2))
    await db_session.commit()
    return {"org": org, "project": project, "baseline": baseline, "current": current, "t0": t0}


@pytest.mark.asyncio
async def test_partition_follows_identity_links(ctx, db_session):
    b, c = ctx["baseline"], ctx["current"]
    # persisting: b1 -> c1
    b1 = _vuln(scan=b, title="persist")
    db_session.add(b1)
    await db_session.flush()
    c1 = _vuln(scan=c, title="persist", previous_id=b1.id)
    db_session.add(c1)
    await db_session.flush()
    b1.superseded_by_id = c1.id
    # fixed: b2 auto-resolved by c
    b2 = _vuln(scan=b, title="fixed", status=VulnerabilityStatus.RESOLVED)
    # not covered: b3 still open, nothing in c
    b3 = _vuln(scan=b, title="uncovered")
    # triaged: b4 false positive, hidden
    b4 = _vuln(scan=b, title="fp", status=VulnerabilityStatus.FALSE_POSITIVE)
    # new: c2 no link; regression: c3 flagged
    c2 = _vuln(scan=c, title="brand new")
    c3 = _vuln(scan=c, title="came back", regression=True)
    db_session.add_all([b2, b3, b4, c2, c3])
    await db_session.commit()

    diff = await compute_diff(db_session, b, c)
    assert [v.title for v in diff.persisting] == ["persist"]
    assert diff.persisting[0].scan_id == c.id  # current's row is shown
    assert [v.title for v in diff.fixed] == ["fixed"]
    assert [v.title for v in diff.not_covered] == ["uncovered"]
    assert [v.title for v in diff.new] == ["brand new"]
    assert [v.title for v in diff.regressions] == ["came back"]
    assert diff.triaged_count == 1 and diff.truncated is False and diff.scope_covered is True
    assert diff.counts() == {
        "new": 1,
        "regressions": 1,
        "persisting": 1,
        "fixed": 1,
        "not_covered": 1,
        "triaged": 1,
    }


@pytest.mark.asyncio
async def test_chain_through_intermediate_scan_and_scope_flag(ctx, db_session):
    org, project, b, c, t0 = ctx["org"], ctx["project"], ctx["baseline"], ctx["current"], ctx["t0"]
    mid = await _scan(db_session, org, project, when=t0 + timedelta(days=1))
    b1 = _vuln(scan=b, title="via mid")
    db_session.add(b1)
    await db_session.flush()
    m1 = _vuln(scan=mid, title="via mid", previous_id=b1.id)
    db_session.add(m1)
    await db_session.flush()
    b1.superseded_by_id = m1.id
    c1 = _vuln(scan=c, title="via mid", previous_id=m1.id)
    db_session.add(c1)
    await db_session.flush()
    m1.superseded_by_id = c1.id
    # A baseline row resolved in the middle scan and absent from c → fixed.
    b2 = _vuln(scan=b, title="fixed in mid")
    db_session.add(b2)
    await db_session.flush()
    m2 = _vuln(
        scan=mid, title="fixed in mid", previous_id=b2.id, status=VulnerabilityStatus.RESOLVED
    )
    db_session.add(m2)
    await db_session.flush()
    b2.superseded_by_id = m2.id
    # Current is a narrower (quick-tag) scan than the baseline.
    c.config = {"depth": "deep", "template_categories": ["misconfig"]}
    await db_session.commit()

    diff = await compute_diff(db_session, b, c)
    assert [v.title for v in diff.persisting] == ["via mid"] and diff.persisting[0].id == c1.id
    assert [v.title for v in diff.fixed] == ["fixed in mid"]
    assert diff.scope_covered is False


@pytest.mark.asyncio
async def test_default_baseline_is_previous_finished_same_type(ctx, db_session):
    org, project, b, c, t0 = ctx["org"], ctx["project"], ctx["baseline"], ctx["current"], ctx["t0"]
    assert (await default_baseline(db_session, c)).id == b.id
    # A newer failed scan and a different type are skipped.
    await _scan(db_session, org, project, when=t0 + timedelta(days=1), status=ScanStatus.FAILED)
    await _scan(
        db_session, org, project, when=t0 + timedelta(days=1, hours=1), scan_type=ScanType.FULL_WEB
    )
    await db_session.commit()
    assert (await default_baseline(db_session, c)).id == b.id
    assert await default_baseline(db_session, b) is None


@pytest.mark.asyncio
async def test_truncation_cap(ctx, db_session):
    c = ctx["current"]
    db_session.add_all([_vuln(scan=c, title=f"n{i}") for i in range(5)])
    await db_session.commit()
    diff = await compute_diff(db_session, ctx["baseline"], c, cap_per_category=3)
    assert diff.truncated is True and len(diff.new) == 3
