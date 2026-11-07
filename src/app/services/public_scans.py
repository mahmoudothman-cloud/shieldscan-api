"""Public quick-scan service (M11 pre-work; ADDENDUM-CRITICAL-5 §2).

Responsibilities:

* resolve (and lazily create) the single system organization that owns
  every public scan, and a project per normalized target domain;
* create the ``Scan`` (``is_public=True``, ``ScanType.QUICK``) and the
  ``PublicScan`` request record, then hand the scan to the orchestrator
  with a system identity;
* turn raw findings into the public result: a 0–100 score, a letter
  grade, the top-N findings, and the count of the rest.

Why raw findings and not vulnerabilities: public scans skip the AI
pipeline (completions consumer finalises them directly), so there are
no ``Vulnerability`` rows. Nuclei/sslyze titles and descriptions are
already readable; the AI explanation and fix are what the account
unlocks.

Scoring (addendum §M10.5.3, adapted to severities): start at 100,
subtract per raw finding — critical 30, high 15, medium 7, low 2,
info 0 — clamp to [0, 100]; A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, else F.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from uuid import UUID

import redis.asyncio as redis_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.tenant_context import set_tenant_context
from app.dependencies import AuthIdentity
from app.models.identity import Organization
from app.models.projects import Project
from app.models.public_scans import PublicScan
from app.models.raw_findings import RawFinding, Severity
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.schemas.public_scans import (
    PublicFinding,
    PublicScanResultResponse,
    PublicSeverityCounts,
)
from app.services.orchestrator import ScanOrchestrator
from app.services.projects import extract_root_domain

SEVERITY_PENALTY: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 2,
    Severity.INFO: 0,
}
_SEVERITY_RANK: dict[Severity, int] = {s: i for i, s in enumerate(Severity)}
_TERMINAL_JOB_STATUSES = frozenset({"completed", "failed", "canceled"})
_FINISHED_SCAN_STATUSES = frozenset({ScanStatus.COMPLETED, ScanStatus.PARTIAL})


def new_slug() -> str:
    """URL-safe, ~128-bit token. Unguessable by construction; the only
    way to a result page is the emailed link."""
    return secrets.token_urlsafe(16)


def normalized_domain_of(target_url: str) -> str:
    host = urlparse(target_url).hostname or ""
    return host.lower()


def score_and_grade(findings: list[RawFinding]) -> tuple[int, str]:
    score = 100 - sum(SEVERITY_PENALTY.get(f.severity, 0) for f in findings)
    score = max(0, min(100, score))
    if score >= 90:
        return score, "A"
    if score >= 75:
        return score, "B"
    if score >= 60:
        return score, "C"
    if score >= 40:
        return score, "D"
    return score, "F"


async def get_or_create_public_org(db: AsyncSession) -> Organization:
    """The system org that owns every public scan. ``organizations`` is
    not tenant-scoped, so this runs before any GUC is set. The org has
    no members: nobody can log into it; its scans are reachable only
    through the public routes."""
    slug = settings.PUBLIC_SCAN_ORG_SLUG
    org = (
        await db.execute(select(Organization).where(Organization.slug == slug))
    ).scalar_one_or_none()
    if org is None:
        org = Organization(name="ShieldScan Public Scans", slug=slug)
        db.add(org)
        await db.flush()
    return org


async def enter_public_tenant(db: AsyncSession) -> Organization:
    """Resolve the system org and set the RLS tenant context to it."""
    org = await get_or_create_public_org(db)
    await set_tenant_context(db, org.id)
    return org


async def _get_or_create_project(db: AsyncSession, org: Organization, target_url: str) -> Project:
    domain = normalized_domain_of(target_url)
    project = (
        await db.execute(
            select(Project).where(
                Project.organization_id == org.id,
                Project.name == domain,
                Project.archived_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if project is None:
        project = Project(
            organization_id=org.id,
            name=domain,
            target_url=f"https://{domain}",
            root_domain=extract_root_domain(target_url),
            domain_verified=False,
        )
        db.add(project)
        await db.flush()
    return project


async def create_public_scan(
    db: AsyncSession,
    redis: redis_asyncio.Redis,
    *,
    org: Organization,
    target_url: str,
    email: str,
    ip_address: str | None,
    user_agent: str | None,
) -> PublicScan:
    """Create project (if needed), Scan, PublicScan; dispatch. Commits
    (the orchestrator owns the transaction, as in ``create_scan``)."""
    project = await _get_or_create_project(db, org, target_url)
    now = datetime.now(timezone.utc)

    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.QUICK,
        status=ScanStatus.QUEUED,
        priority="normal",
        config={"public": True, "target_url": target_url},
        recon_enabled=False,
        subdomain_limit=1,
        is_public=True,
        public_slug=new_slug(),
    )
    db.add(scan)
    await db.flush()
    # Same eager-attach trick as routes/scans.py: the orchestrator reads
    # scan.project.target_url synchronously.
    scan.project = project  # type: ignore[attr-defined]

    public = PublicScan(
        organization_id=org.id,
        slug=scan.public_slug,
        scan_id=scan.id,
        project_id=project.id,
        email=email,
        target_url=target_url,
        normalized_domain=normalized_domain_of(target_url),
        ip_address=ip_address,
        user_agent=user_agent,
        consent_at=now,
        expires_at=now + timedelta(days=settings.PUBLIC_SCAN_RESULT_TTL_DAYS),
    )
    db.add(public)
    await db.flush()

    # System identity: no user, no API key. The orchestrator audits
    # SCAN_DISPATCHED with actor_id=None (system-driven, like the consumer).
    identity = AuthIdentity(kind="api_key", organization_id=org.id)
    orch = ScanOrchestrator(db, redis)
    await orch.dispatch(scan, identity, request_ip=ip_address, user_agent=user_agent)
    return public


async def get_public_scan_by_slug(db: AsyncSession, slug: str) -> PublicScan | None:
    return (
        await db.execute(select(PublicScan).where(PublicScan.slug == slug))
    ).scalar_one_or_none()


async def build_result(db: AsyncSession, public: PublicScan) -> PublicScanResultResponse:
    scan = await db.get(Scan, public.scan_id)
    now = datetime.now(timezone.utc)
    expired = public.expires_at <= now

    jobs = list(
        (await db.execute(select(ScanJob).where(ScanJob.scan_id == public.scan_id))).scalars()
    )
    engines_total = len(jobs)
    engines_finished = sum(1 for j in jobs if j.status in _TERMINAL_JOB_STATUSES)

    status = scan.status.value if scan is not None else "failed"
    findings: list[RawFinding] = []
    if scan is not None and not expired and scan.status in _FINISHED_SCAN_STATUSES:
        findings = list(
            (
                await db.execute(
                    select(RawFinding)
                    .where(RawFinding.scan_id == public.scan_id)
                    .order_by(RawFinding.severity, RawFinding.title)
                )
            ).scalars()
        )
        findings.sort(key=lambda f: (_SEVERITY_RANK[f.severity], f.title))

    counts = PublicSeverityCounts(total=len(findings))
    for f in findings:
        setattr(counts, f.severity.value, getattr(counts, f.severity.value) + 1)

    score: int | None = None
    grade: str | None = None
    if scan is not None and not expired and scan.status in _FINISHED_SCAN_STATUSES:
        score, grade = score_and_grade(findings)

    visible = findings[: settings.PUBLIC_SCAN_VISIBLE_FINDINGS]
    hidden = max(0, len(findings) - len(visible))

    return PublicScanResultResponse(
        slug=public.slug,
        status="expired" if expired else status,
        target_url=public.target_url,
        domain=public.normalized_domain,
        created_at=public.created_at,
        completed_at=scan.completed_at if scan is not None else None,
        expires_at=public.expires_at,
        engines_total=engines_total,
        engines_finished=engines_finished,
        score=score,
        grade=grade,
        findings_by_severity=counts,
        findings=[
            PublicFinding(
                title=f.title,
                severity=f.severity.value,
                engine=f.tool_name,
                summary=(f.description or "")[:400] or None,
                target_url=f.target_url,
            )
            for f in visible
        ],
        hidden_count=hidden,
        register_url=f"{settings.APP_BASE_URL}/register?from={public.slug}",
    )


async def count_recent_for_email(
    db: AsyncSession, org_id: UUID, email: str, since: datetime
) -> int:
    n = (
        await db.execute(
            select(func.count(PublicScan.id)).where(
                PublicScan.organization_id == org_id,
                PublicScan.email == email,
                PublicScan.created_at >= since,
            )
        )
    ).scalar_one()
    return int(n)
