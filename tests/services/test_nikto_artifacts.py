"""Cleanup of nikto findings that describe an error page rather than a site.

Nikto 2.1.5 cannot negotiate TLS, so against a target on port 443 it spoke
plain HTTP and parsed nginx's "400 Bad Request" page as the application
(engine Drift #71). What is pinned here:

  1. The scope test is the ARTIFACT, not a date. A plain-``http://``
     target_url on port 443 cannot occur unless TLS negotiation failed.
     A genuine plain-HTTP scan on port 80 must survive — nikto works fine
     over HTTP, and a date cutoff would have deleted those too.
  2. A vulnerability backed by BOTH artifacts and real findings is never
     touched, and blocks the whole run. There are none in production
     today; these tests are the only place that path is exercised, which
     is exactly why they exist.
  3. Deletion order: vulnerabilities before raw_findings, or the rows
     left behind cite evidence that no longer exists.
"""

from __future__ import annotations

import uuid
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models.identity import Organization
from app.models.projects import Project
from app.models.raw_findings import EngineCategory, RawFinding, Severity
from app.models.scans import Scan, ScanStatus, ScanType
from app.models.vulnerabilities import (
    Severity as VulnSeverity,
)
from app.models.vulnerabilities import (
    Vulnerability,
    VulnerabilityStatus,
)
from app.services.nikto_artifacts import apply_plan, build_plan
from tests.conftest import use_org

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def world(db_session):
    """A scan carrying every provenance case at once."""
    org = Organization(name="Nikto Org", slug=f"nk-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)

    project = Project(
        organization_id=org.id,
        name="NApp",
        target_url="https://n.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.COMPLETED,
        priority="normal",
        config={},
    )
    db_session.add(scan)
    await db_session.flush()

    def raw(tool: str, url: str, title: str) -> RawFinding:
        return RawFinding(
            organization_id=org.id,
            scan_id=scan.id,
            tool_name=tool,
            engine_category=EngineCategory.INFRASTRUCTURE,
            title=title,
            description=title,
            severity=Severity.LOW,
            finding_type=f"{tool}-x",
            target_url=url,
            fingerprint=uuid4().hex,
        )

    # Two artifacts: plain HTTP on the TLS port. Both trailing shapes.
    artifact_a = raw("nikto", "http://n.example.com:443/", "Artifact with a path")
    artifact_b = raw("nikto", "http://n.example.com:443", "Artifact, bare host")
    # A REAL nikto finding: plain HTTP on port 80, which nikto scans fine.
    real_nikto = raw("nikto", "http://n.example.com:80/admin/", "Real HTTP finding")
    # What a WORKING nikto produces once 2.5.0 lands: https on 443. Must
    # survive — the scope test is "failed to negotiate TLS", not "nikto
    # touched port 443".
    nikto_tls = raw("nikto", "https://n.example.com:443/", "Post-upgrade finding")
    # A real finding from another tool.
    real_zap = raw("zap", "https://n.example.com/", "Real zap finding")

    db_session.add_all([artifact_a, artifact_b, real_nikto, real_zap, nikto_tls])
    await db_session.flush()

    def vuln(title: str, raw_ids: list[uuid.UUID]) -> Vulnerability:
        return Vulnerability(
            organization_id=org.id,
            scan_id=scan.id,
            project_id=project.id,
            title=title,
            severity=VulnSeverity.LOW,
            finding_type="nikto-x",
            engine_category=EngineCategory.INFRASTRUCTURE,
            fingerprint=uuid4().hex,
            status=VulnerabilityStatus.OPEN,
            raw_finding_ids=raw_ids,
            ai_fix_is_fallback=False,
        )

    pure = vuln("Pure artifact vuln", [artifact_a.id, artifact_b.id])
    mixed = vuln("Mixed provenance vuln", [artifact_a.id, real_zap.id])
    untouched = vuln("Real vuln", [real_zap.id])
    # Cites an artifact plus an id whose raw_finding is already gone.
    # A dangling id is absent evidence, NOT evidence from another tool —
    # reading it as the latter would wrongly block the run.
    dangling = vuln("Artifact + dangling id", [artifact_b.id, uuid4()])
    db_session.add_all([pure, mixed, untouched, dangling])
    await db_session.commit()

    return {
        "org": org,
        "scan": scan,
        "artifact_a": artifact_a,
        "artifact_b": artifact_b,
        "real_nikto": real_nikto,
        "real_zap": real_zap,
        "nikto_tls": nikto_tls,
        "pure": pure,
        "mixed": mixed,
        "untouched": untouched,
        "dangling": dangling,
    }


# ---------------------------------------------------------------- scope


async def test_scope_is_the_artifact_not_the_tool(db_session, world):
    """A real nikto finding over plain HTTP must survive.

    Nikto works correctly over HTTP; only the TLS port is broken. Scoping
    by tool_name, or by a date cutoff, would delete real data.
    """
    plan = await build_plan(db_session)

    assert world["artifact_a"].id in plan.raw_finding_ids
    assert world["artifact_b"].id in plan.raw_finding_ids
    assert world["real_nikto"].id not in plan.raw_finding_ids, (
        "a plain-HTTP nikto scan on port 80 is real output, not an artifact"
    )
    assert world["nikto_tls"].id not in plan.raw_finding_ids, (
        "an https:// nikto finding on 443 is what a WORKING nikto produces; "
        "the scope must key on the failed TLS negotiation, not on port 443"
    )
    assert world["real_zap"].id not in plan.raw_finding_ids


async def test_scope_records_what_it_matched(db_session, world):
    plan = await build_plan(db_session)
    assert plan.target_urls == {
        "http://n.example.com:443/": 1,
        "http://n.example.com:443": 1,
    }
    assert plan.scans_touched == {world["scan"].id}


# ---------------------------------------------------------------- provenance


async def test_mixed_provenance_vulnerability_is_identified_not_deleted(
    db_session, world
):
    """The case the recon could not find in production data.

    Deleting the row loses the zap evidence; stripping only the nikto id
    leaves a promoted vulnerability scored from evidence that is gone.
    Neither is obviously right, so the run blocks and a human decides.
    """
    plan = await build_plan(db_session)

    assert world["pure"].id in plan.pure_vulnerability_ids
    assert world["mixed"].id not in plan.pure_vulnerability_ids

    assert len(plan.mixed_vulnerabilities) == 1
    m = plan.mixed_vulnerabilities[0]
    assert world["dangling"].id in plan.pure_vulnerability_ids, (
        "a dangling raw_finding_id is absent evidence, not evidence from "
        "another tool; counting it as real would block the run forever"
    )
    assert m["vulnerability_id"] == world["mixed"].id
    assert m["artifact_rows"] == 1
    assert m["real_rows"] == 1
    assert "zap" in m["tools"]
    assert plan.blocked


async def test_a_blocked_plan_deletes_nothing(db_session, world):
    """Half a cleanup is worse than none — the operator would believe it
    had finished."""
    plan = await build_plan(db_session)
    assert plan.blocked

    with pytest.raises(RuntimeError, match="BOTH nikto artifacts and real findings"):
        await apply_plan(db_session, plan)

    remaining = (
        await db_session.execute(
            select(RawFinding).where(RawFinding.scan_id == world["scan"].id)
        )
    ).scalars().all()
    assert len(remaining) == 5, "a blocked plan must not delete anything"


async def test_a_vulnerability_untouched_by_nikto_is_not_considered(
    db_session, world
):
    plan = await build_plan(db_session)
    ids = plan.pure_vulnerability_ids + [
        m["vulnerability_id"] for m in plan.mixed_vulnerabilities
    ]
    assert world["untouched"].id not in ids


# ---------------------------------------------------------------- apply


async def test_apply_deletes_artifacts_and_their_vulnerabilities(db_session, world):
    """The unblocked path. Remove the mixed vulnerability first, which is
    what a human would do after deciding."""
    await db_session.delete(world["mixed"])
    await db_session.commit()

    plan = await build_plan(db_session)
    assert not plan.blocked

    counts = await apply_plan(db_session, plan)
    await db_session.commit()

    assert counts["raw_findings"] == 2
    assert counts["vulnerabilities"] == 2, "the pure vuln and the dangling one"
    assert counts["scans_annotated"] == 1

    surviving = {
        r.id
        for r in (
            await db_session.execute(
                select(RawFinding).where(RawFinding.scan_id == world["scan"].id)
            )
        ).scalars()
    }
    assert surviving == {
        world["real_nikto"].id,
        world["real_zap"].id,
        world["nikto_tls"].id,
    }, "real findings must survive, including a working nikto's https output"

    vulns = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == world["scan"].id)
        )
    ).scalars().all()
    assert [v.id for v in vulns] == [world["untouched"].id]


async def test_apply_records_the_reason_on_the_scan(db_session, world):
    await db_session.delete(world["mixed"])
    await db_session.commit()

    plan = await build_plan(db_session)
    await apply_plan(db_session, plan)
    await db_session.commit()

    scan = (
        await db_session.execute(select(Scan).where(Scan.id == world["scan"].id))
    ).scalar_one()
    await db_session.refresh(scan)
    assert scan.error_message is not None
    assert "Drift #71" in scan.error_message


async def test_apply_is_idempotent(db_session, world):
    """Re-deriving the plan is what makes a second run safe: the rows are
    gone, so it matches nothing."""
    await db_session.delete(world["mixed"])
    await db_session.commit()

    await apply_plan(db_session, await build_plan(db_session))
    await db_session.commit()

    second = await build_plan(db_session)
    assert second.raw_finding_ids == []
    counts = await apply_plan(db_session, second)
    assert counts == {"vulnerabilities": 0, "raw_findings": 0, "scans_annotated": 0}


async def test_the_reason_is_recorded_once_however_often_it_runs(db_session, world):
    """A scan already carrying the reason must not collect a second copy.

    The re-derivation makes a second run a no-op in practice, but the
    annotation guard is what holds if rows are ever re-created — and a
    duplicated sentence in a customer-visible field is its own small
    defect.
    """
    from app.services.nikto_artifacts import CLEANUP_REASON

    world["scan"].error_message = CLEANUP_REASON
    await db_session.delete(world["mixed"])
    await db_session.commit()

    await apply_plan(db_session, await build_plan(db_session))
    await db_session.commit()

    scan = (
        await db_session.execute(select(Scan).where(Scan.id == world["scan"].id))
    ).scalar_one()
    await db_session.refresh(scan)
    assert scan.error_message.count("Drift #71") == 1


async def test_apply_does_not_overwrite_an_existing_scan_error_message(
    db_session, world
):
    """A scan may already carry a job-failure summary. Overwriting it
    would trade one lost explanation for another."""
    world["scan"].error_message = "4 of 25 scan jobs failed; partial results available"
    await db_session.delete(world["mixed"])
    await db_session.commit()

    await apply_plan(db_session, await build_plan(db_session))
    await db_session.commit()

    scan = (
        await db_session.execute(select(Scan).where(Scan.id == world["scan"].id))
    ).scalar_one()
    await db_session.refresh(scan)
    assert "4 of 25 scan jobs failed" in scan.error_message
    assert "Drift #71" in scan.error_message
