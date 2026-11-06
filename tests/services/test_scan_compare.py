"""Service-level tests for ``app.services.scan_compare.compute_diff`` (Task 4.6).

Four tests pinning the diff algorithm:

  1. identical scans → all persisting, none new/resolved
  2. mixed (some new, some resolved, some persisting) → correct buckets
  3. empty baseline (first scan ever) → all current findings new
  4. truncation: cap respected per category, truncated=True flag set

Note: M9 AI pipeline normally populates the vulnerabilities table.
4.6 only READS — these tests seed Vulnerability rows directly to
exercise the diff logic deterministically.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
import pytest_asyncio

from app.models.identity import Membership, MembershipRole, Organization, User
from app.models.projects import Project
from app.models.raw_findings import EngineCategory, Severity
from app.models.scans import Scan, ScanStatus, ScanType
from app.models.vulnerabilities import Vulnerability
from app.services.auth import hash_password
from app.services.scan_compare import compute_diff
from tests.conftest import use_org


# ---------------------------------------------------------------- helpers


def _vuln(*, scan_id, project_id, org_id, fingerprint, title="x", severity=Severity.MEDIUM):
    """Build a Vulnerability ORM row with required fields populated."""
    return Vulnerability(
        scan_id=scan_id,
        project_id=project_id,
        organization_id=org_id,
        title=title,
        severity=severity,
        finding_type="xss",
        engine_category=EngineCategory.DAST,
        fingerprint=fingerprint,
    )


@pytest_asyncio.fixture
async def two_scans(db_session):
    """Single org + project + two completed scans. Returns dict
    with both scan_ids (caller seeds vulnerabilities)."""
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
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )

    project = Project(
        organization_id=org.id,
        name="CmpApp",
        target_url="https://cmp.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()

    baseline = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.QUICK,
        status=ScanStatus.COMPLETED,
        priority="normal",
        config={},
    )
    current = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.QUICK,
        status=ScanStatus.COMPLETED,
        priority="normal",
        config={},
    )
    db_session.add_all([baseline, current])
    await db_session.commit()
    await db_session.refresh(baseline)
    await db_session.refresh(current)

    return {
        "org": org,
        "project": project,
        "user": user,
        "baseline": baseline,
        "current": current,
    }


# ============================================================ 1. identical


@pytest.mark.asyncio
async def test_compute_diff_identical_scans_all_persisting(two_scans, db_session):
    s = two_scans
    fps = ["fp_" + ("a" * 60), "fp_" + ("b" * 60), "fp_" + ("c" * 60)]
    for fp in fps:
        db_session.add(_vuln(
            scan_id=s["baseline"].id,
            project_id=s["project"].id,
            org_id=s["org"].id,
            fingerprint=fp,
        ))
        db_session.add(_vuln(
            scan_id=s["current"].id,
            project_id=s["project"].id,
            org_id=s["org"].id,
            fingerprint=fp,
        ))
    await db_session.commit()

    new, resolved, persisting, truncated = await compute_diff(
        db_session, s["baseline"].id, s["current"].id
    )
    assert new == []
    assert resolved == []
    assert {v.fingerprint for v in persisting} == set(fps)
    assert truncated is False


# ============================================================ 2. mixed


@pytest.mark.asyncio
async def test_compute_diff_categorizes_correctly(two_scans, db_session):
    s = two_scans
    persisting_fp = "fp_persisting" + "0" * 49  # 64 chars
    resolved_fp = "fp_resolved" + "0" * 51
    new_fp = "fp_new" + "0" * 56

    # baseline: persisting + resolved
    db_session.add(_vuln(
        scan_id=s["baseline"].id, project_id=s["project"].id,
        org_id=s["org"].id, fingerprint=persisting_fp,
    ))
    db_session.add(_vuln(
        scan_id=s["baseline"].id, project_id=s["project"].id,
        org_id=s["org"].id, fingerprint=resolved_fp,
    ))
    # current: persisting + new
    db_session.add(_vuln(
        scan_id=s["current"].id, project_id=s["project"].id,
        org_id=s["org"].id, fingerprint=persisting_fp,
    ))
    db_session.add(_vuln(
        scan_id=s["current"].id, project_id=s["project"].id,
        org_id=s["org"].id, fingerprint=new_fp,
    ))
    await db_session.commit()

    new, resolved, persisting, truncated = await compute_diff(
        db_session, s["baseline"].id, s["current"].id
    )
    assert {v.fingerprint for v in new} == {new_fp}
    assert {v.fingerprint for v in resolved} == {resolved_fp}
    assert {v.fingerprint for v in persisting} == {persisting_fp}
    # Persisting returns the CURRENT scan's row (latest observation).
    assert persisting[0].scan_id == s["current"].id
    assert truncated is False


# ============================================================ 3. empty baseline


@pytest.mark.asyncio
async def test_compute_diff_empty_baseline_all_new(two_scans, db_session):
    s = two_scans
    fps = ["fp_" + str(i).zfill(61) for i in range(3)]
    for fp in fps:
        db_session.add(_vuln(
            scan_id=s["current"].id, project_id=s["project"].id,
            org_id=s["org"].id, fingerprint=fp,
        ))
    await db_session.commit()

    new, resolved, persisting, truncated = await compute_diff(
        db_session, s["baseline"].id, s["current"].id
    )
    assert {v.fingerprint for v in new} == set(fps)
    assert resolved == []
    assert persisting == []
    assert truncated is False


# ============================================================ 4. truncation


@pytest.mark.asyncio
async def test_compute_diff_truncates_at_cap(two_scans, db_session):
    s = two_scans
    # Seed 5 net-new findings; cap at 2 → truncated=True, exactly 2 returned.
    fps = ["fp_" + str(i).zfill(61) for i in range(5)]
    for fp in fps:
        db_session.add(_vuln(
            scan_id=s["current"].id, project_id=s["project"].id,
            org_id=s["org"].id, fingerprint=fp,
        ))
    await db_session.commit()

    new, resolved, persisting, truncated = await compute_diff(
        db_session, s["baseline"].id, s["current"].id, cap_per_category=2
    )
    assert len(new) == 2
    assert truncated is True
