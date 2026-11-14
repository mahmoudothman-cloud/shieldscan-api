"""Scan creation endpoint (Task 4.3).

Single endpoint:

    POST /v1/orgs/{org_id}/projects/{project_id}/scans   201 ScanResponse

Composes Task 4.2's ``ScanOrchestrator``. Auth via
``require_org_membership()`` — JWT or API key (CI/CD use case
matters, same as 3.3 mobile upload).

Validation chain (each layer fails before the next runs):

  1. ``require_org_membership`` dep — path.org_id ↔ identity → 404
  2. ``_load_project`` — project belongs to org_id → 404
  3. Pydantic ``ScanCreateRequest`` — shape, mutual exclusion,
     config bounds, public rejection → 422
  4. Domain-verified gate — non-mobile, non-container types
     require ``project.domain_verified`` → 403
  5. Mobile-upload existence + tenant + not-deleted check (when
     scan_type == MOBILE) → 404 on any miss
  6. Build Scan ORM row, flush
  7. Eager-attach ``scan.project`` (in-memory) so orchestrator's
     synchronous attribute access doesn't trigger lazy-load
  8. ``orchestrator.dispatch(scan, identity)`` — INSERTs jobs,
     audits ``SCAN_DISPATCHED``, COMMITs, dispatches to Redis
  9. Response: 201 ``ScanResponse`` with embedded ``jobs`` list

Single-transaction discipline (DRIFT-LOG 2026-04-30 H.1):
  Route flushes the Scan row but does NOT commit. The orchestrator
  commits the entire transaction (Scan + ScanJobs + audit) atomically.
  If anything before the commit fails, the whole tx rolls back. After
  commit, "ghost queued" rows are the visible-failure mode if Redis
  dispatch fails. No janitor recovers those — the "M5+ retry janitor"
  this comment used to name was never built. What exists (2026-08-20)
  is ``scripts/backfill_stranded_jobs.py``, which marks such rows
  FAILED so the parent scan can aggregate; it does not re-dispatch
  them. See engine Drift #70.

Audit emission (DRIFT-LOG):
  This route does NOT emit its own audit row. The orchestrator emits
  exactly one ``SCAN_DISPATCHED`` per scan-creation event. Adding a
  route-level audit would double-emit; pinned by
  ``test_create_scan_emits_exactly_one_scan_dispatched_audit``.
"""

from __future__ import annotations

import json
import logging
import time
from enum import Enum
from math import ceil
from typing import TypeVar
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import (
    AuthIdentity,
    get_db,
    get_real_ip,
    require_org_membership,
)
from app.models.mobile import MobileUpload
from app.models.projects import Project
from app.models.raw_findings import RawFinding, Severity
from app.models.recon import AttackSurface, SubdomainStatus
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.models.vulnerabilities import Vulnerability
from app.redis_client import get_redis
from app.schemas.projects import PageNumber, PaginationMeta, PerPage
from app.schemas.recon import AttackSurfaceResponse, SubdomainEntry
from app.schemas.scans import (
    PaginatedScansResponse,
    ScanCreateRequest,
    ScanDetailResponse,
    ScanJobDetail,
    ScanJobSummary,
    ScanListItem,
    ScanResponse,
    SeverityCounts,
)
from app.schemas.scan_compare import (
    ComparedFindingSummary,
    ComparedScan,
    ComparisonSummary,
    ScanComparisonRequest,
    ScanComparisonResponse,
)
from app.services.audit import ScanAction, audit
from app.services.orchestrator import ScanOrchestrator
from app.models.agents import Agent, AgentStatus
from app.services.agents import is_offline as is_agent_offline
from app.services.plan_enforcement import (
    clamp_subdomain_limit,
    require_feature,
    require_scan_capacity,
)
from app.services.plans import record_scan_usage
from app.services.scan_compare import MAX_FINDINGS_PER_CATEGORY, compute_diff, default_baseline
from app.services.scan_queue import (
    ProgressSubscriber,
    apply_cancel_state,
    publish_cancel_signal,
)

# SSE: sse-starlette EventSourceResponse — version 2.4.1+. ping=15s
# heartbeat keeps connection alive under proxy idle timeouts
# (Cloudflare 100s, AWS ALB 60s, nginx 60s default).
from sse_starlette.sse import EventSourceResponse

logger = logging.getLogger(__name__)


# Project-scoped router — Task 4.3 (POST /scans, future GET /scans).
# Lives under /orgs/{org_id}/projects/{project_id}/scans.
project_scans_router = APIRouter(
    prefix="/orgs/{org_id}/projects/{project_id}/scans",
    tags=["scans"],
)

# Scan-id-scoped router — Task 4.5 (DELETE cancel) + future M4 + M10
# operations (GET single, GET progress SSE, GET jobs, attack-surface).
# Lives under /orgs/{org_id}/scans/{scan_id}/...
# Two routers in one file matches the routes/projects.py precedent
# (CRUD + nested verify + credentials all in one router file).
scan_router = APIRouter(
    prefix="/orgs/{org_id}/scans",
    tags=["scans"],
)


_NOT_FOUND = HTTPException(status_code=404, detail="not_found")
_DOMAIN_NOT_VERIFIED = HTTPException(status_code=403, detail="domain_not_verified")
_SCAN_ALREADY_TERMINAL = HTTPException(status_code=409, detail="scan_already_terminal")
# Source-Ingestion Fix (TOOL-ARCH §3.2 addendum 9d6ab25):
# raised when a ScanType requires source acquisition but the bound
# project has no ``source_repo_url`` configured. Repairs the Drift
# #54 silent-no-op behavior at the request-validation layer per
# Q-FAILURE-MODE hard-fail lock. Schema validator cannot do this
# cross-field check (ScanCreateRequest has no Project reference);
# enforcement lives at the route handler where Project is already
# loaded.
_SOURCE_REPO_URL_REQUIRED = HTTPException(status_code=422, detail="source_repo_url_required")


# Active scan states — cancel is meaningful.
_ACTIVE_STATES: frozenset[ScanStatus] = frozenset(
    {
        ScanStatus.QUEUED,
        ScanStatus.RECONNING,
        ScanStatus.RUNNING,
        ScanStatus.ANALYZING,
    }
)

# Terminal-final states — cancel is a no-op past these (the work
# already concluded, not by user intent). 409 to signal the conflict.
_TERMINAL_FINAL: frozenset[ScanStatus] = frozenset(
    {
        ScanStatus.COMPLETED,
        ScanStatus.PARTIAL,
        ScanStatus.FAILED,
    }
)

# Scan types that bypass the domain-verified gate. Mobile = uploaded
# artifact is the bound asset. Container = image is the bound asset.
# project.target_url is informational for both, not an enforcement
# surface. QUICK (M11, dashboard design v1.0 flow F2): the passive
# read-only set (nuclei quick + sslyze) is exactly what the public
# endpoint already runs for anyone with an email address, so gating it
# behind DNS verification protects nothing; an unverified project can
# run quick scans while the owner sets up the TXT record. Full scans
# stay gated.
# M14: the agent runs the native tool subset (nuclei, httpx, subfinder,
# sslyze, nikto, wapiti, nmap); scan types needing MobSF, trivy, semgrep,
# zap etc. stay cloud-only.
_AGENT_UNSUPPORTED_SCAN_TYPES: frozenset[ScanType] = frozenset(
    {ScanType.MOBILE, ScanType.CONTAINER, ScanType.FULL_WEB_SOURCE, ScanType.FULL_SPECTRUM}
)

_DOMAIN_VERIFY_BYPASS: frozenset[ScanType] = frozenset(
    {ScanType.MOBILE, ScanType.CONTAINER, ScanType.QUICK}
)

# Source-Ingestion Fix: ScanTypes that dispatch ``trivy-fs`` and
# therefore require ``Project.source_repo_url`` to be set. Kept in
# sync with ``services.orchestrator._SOURCE_REQUIRING_SCAN_TYPES``;
# duplicated here to avoid a routes-side import of an orchestrator
# private symbol. Single source of truth for the set membership is
# the orchestrator constant.
_SOURCE_REQUIRING_SCAN_TYPES: frozenset[ScanType] = frozenset(
    {
        ScanType.FULL_WEB_SOURCE,
        ScanType.FULL_SPECTRUM,
    }
)


@project_scans_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=ScanResponse,
)
async def create_scan(
    org_id: UUID,
    project_id: UUID,
    body: ScanCreateRequest,
    request: Request,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    # Step 2: project lookup (404 on cross-tenant or missing).
    project = (
        await db.execute(
            select(Project).where(
                Project.id == project_id,
                Project.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if project is None:
        raise _NOT_FOUND

    # Step 4: domain-verified gate (Pydantic already rejected PUBLIC).
    # M14: an agent-bound project is authorised by the agent's enrolment
    # (On-Prem Agent Design v1.0 A5) — DNS cannot verify 10.0.0.5.
    if (
        body.scan_type not in _DOMAIN_VERIFY_BYPASS
        and not project.domain_verified
        and project.agent_id is None
    ):
        raise _DOMAIN_NOT_VERIFIED

    # Step 4a (M14): an agent-bound project needs its agent online, or the
    # scan would sit in a queue nobody reads. Fail at once, with the reason.
    if project.agent_id is not None:
        agent = (
            await db.execute(
                select(Agent).where(Agent.id == project.agent_id, Agent.organization_id == org_id)
            )
        ).scalar_one_or_none()
        if agent is None or agent.status != AgentStatus.ACTIVE or is_agent_offline(agent):
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "agent_offline",
                    "agent_id": str(project.agent_id),
                    "agent_name": agent.name if agent is not None else None,
                    "last_seen_at": agent.last_seen_at.isoformat()
                    if agent is not None and agent.last_seen_at
                    else None,
                },
            )
        if body.scan_type in _AGENT_UNSUPPORTED_SCAN_TYPES:
            raise HTTPException(status_code=422, detail="scan_type_not_supported_on_agent")

    # Step 4b: source-acquisition prerequisite gate per Source-Ingestion
    # Fix (TOOL-ARCH §3.2 addendum 9d6ab25). ScanTypes that dispatch
    # ``trivy-fs`` require ``Project.source_repo_url`` to be set
    # because the engine clones at job-pickup time per Q-WIRE
    # engine-clones lock; without a URL the dispatch would silently
    # no-op (Drift #54). Q-FAILURE-MODE hard-fail at the request-
    # validation layer.
    if body.scan_type in _SOURCE_REQUIRING_SCAN_TYPES and not project.source_repo_url:
        raise _SOURCE_REPO_URL_REQUIRED

    # Step 5: mobile-upload validation (when applicable).
    if body.scan_type == ScanType.MOBILE:
        upload = (
            await db.execute(
                select(MobileUpload).where(
                    MobileUpload.id == body.mobile_upload_id,
                    MobileUpload.organization_id == org_id,
                    MobileUpload.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        if upload is None:
            # 404 (not 403) — existence-hiding. Same discipline as
            # cross-tenant project lookups.
            raise _NOT_FOUND

    # Step 5b (M12 slice 2): plan checks. API-key callers (CLI, Action,
    # MCP) need cli_write; the scan type's period meter must have room;
    # recon never expands past the plan's subdomain cap.
    if identity.kind == "api_key":
        await require_feature(db, redis, org_id, "cli_write")
    eff = await require_scan_capacity(db, redis, org_id, body.scan_type)

    # Step 6: build + flush Scan row (no commit — orchestrator owns).
    scan = Scan(
        organization_id=org_id,
        project_id=project_id,
        scan_type=body.scan_type,
        status=ScanStatus.QUEUED,
        priority=body.priority.value,
        config=body.config,
        recon_enabled=body.recon_enabled,
        subdomain_limit=clamp_subdomain_limit(eff, body.subdomain_limit),
        mobile_upload_id=body.mobile_upload_id,
    )
    db.add(scan)
    await db.flush()

    # Step 6b: meter the scan against the org's period (M12 slice 1).
    # Same transaction as the Scan row: a dispatch failure rolls both back.
    await record_scan_usage(db, eff, org_id, scan.scan_type)

    # Step 7: eager-attach project in-memory so orchestrator's
    # synchronous scan.project.target_url access doesn't trigger
    # SQLAlchemy lazy-load (which raises MissingGreenlet in async).
    # Load-bearing — pinned by the eager-load regression test. Don't
    # remove "for cleanliness."
    scan.project = project  # type: ignore[assignment]

    # Step 8: orchestrator dispatch — audits + commits + queues.
    # Single-tx discipline (DRIFT-LOG H.1): orchestrator commits the
    # transaction we just flushed into. Caller MUST NOT commit again.
    orch = ScanOrchestrator(db, redis)
    jobs = await orch.dispatch(
        scan,
        identity,
        request_ip=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )

    # Step 9: response. Build from the in-memory ORM objects (already
    # post-commit, fresh state). No select_fresh needed — these are
    # the canonical post-write rows the orchestrator just wrote.
    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        organization_id=scan.organization_id,
        scan_type=scan.scan_type.value,
        status=scan.status.value,
        priority=scan.priority,
        recon_enabled=scan.recon_enabled,
        subdomain_limit=scan.subdomain_limit,
        mobile_upload_id=scan.mobile_upload_id,
        created_at=scan.created_at,
        jobs=[ScanJobSummary.model_validate(j) for j in jobs],
    )


# ================================================================ scan_router endpoints (Task 4.5+)


@scan_router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def cancel_scan(
    org_id: UUID,
    scan_id: UUID,
    request: Request,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    """Cancel an active scan (Task 4.5).

    State transitions:
      Active states (queued/reconning/running/analyzing) → CANCELED.
      Already-CANCELED → no-op state-wise, but emit a fresh audit row
        (event-not-state-change discipline; same as Task 3.2 reverify
        pin). 204 either way.
      Terminal-final (completed/partial/failed) → 409
        scan_already_terminal. The work concluded; cancel is
        semantically meaningless.

    Cancel-vs-completion race (DRIFT-LOG H.2 reversal): scan-level
    state is sticky. The completions consumer's
    ``_maybe_complete_scan`` short-circuits on CANCELED so a
    completion event arriving after this cancel does NOT overwrite
    the terminal CANCELED state. Cancel wins at scan-level
    aggregation (job-level cancel is M5+ worker-defined).

    Auth: ``require_org_membership()`` — JWT or API key. Any-member
    (no admin gate) — symmetric with scan-create (Task 4.3).

    Same-tx + commit-then-publish ordering (matches Task 4.2 +
    Task 4.3): UPDATE Scan.status + emit audit + COMMIT, then
    PUBLISH cancel signal to Redis. Pub/Sub publish is fire-and-
    forget; failure post-commit is acceptable per visible-failure
    discipline (the scan is canceled in PG either way).

    Worker-side cancel consumption is M5+ work — until then, the
    cancel signal goes into the void. See DRIFT-LOG 2026-04-30
    Task 4.5 worker-side-cancel entry.
    """
    scan = (
        await db.execute(
            select(Scan).where(
                Scan.id == scan_id,
                Scan.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if scan is None:
        raise _NOT_FOUND

    # Terminal-final guard. Idempotent CANCELED falls through to the
    # state transition + audit emission below (no-op write, fresh audit).
    if scan.status in _TERMINAL_FINAL:
        raise _SCAN_ALREADY_TERMINAL

    actor_id = identity.user.id if identity.user is not None else None
    api_key_prefix = identity.api_key.key_prefix if identity.api_key is not None else None

    # Shared kernel: flip state + emit SCAN_CANCELED audit (Drift #51
    # rule-of-three extraction at services/scan_queue.py).
    await apply_cancel_state(
        db,
        scan,
        actor_id=actor_id,
        reason="user_requested",
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
        api_key_prefix=api_key_prefix,
    )
    await db.commit()

    # Publish cancel signal to Redis post-commit. Fire-and-forget per
    # visible-failure discipline (durable PG state is source of truth).
    await publish_cancel_signal(redis, str(scan_id), reason="user_requested", logger=logger)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@scan_router.post(
    "/compare",
    status_code=status.HTTP_200_OK,
    response_model=ScanComparisonResponse,
)
async def compare_scans(
    org_id: UUID,
    body: ScanComparisonRequest,
    request: Request,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
):
    """Compare a scan with a baseline on identity links (Task 4.6,
    reworked 2026-11-13 — services/scan_compare.py).

    ``baseline_scan_id`` omitted → the project's previous finished scan
    of the same type; none → 404 ``no_baseline``. Both scans must be in
    this org (404 otherwise, existence-hiding), the same project (409
    ``scans_project_mismatch``), terminal (409 ``scan_not_terminal``)
    and the baseline older than the current (409 ``baseline_not_older``).
    Read-only apart from the SCAN_COMPARED audit row.
    """
    current = (
        await db.execute(
            select(Scan).where(Scan.id == body.current_scan_id, Scan.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if current is None:
        raise _NOT_FOUND
    _COMPARE_OK = {ScanStatus.COMPLETED, ScanStatus.PARTIAL}
    if current.status not in _COMPARE_OK:
        raise HTTPException(status_code=409, detail="scan_not_terminal")

    if body.baseline_scan_id is None:
        baseline = await default_baseline(db, current)
        if baseline is None:
            raise HTTPException(status_code=404, detail="no_baseline")
    else:
        baseline = (
            await db.execute(
                select(Scan).where(Scan.id == body.baseline_scan_id, Scan.organization_id == org_id)
            )
        ).scalar_one_or_none()
        if baseline is None:
            raise _NOT_FOUND
        if baseline.project_id != current.project_id:
            raise HTTPException(status_code=409, detail="scans_project_mismatch")
        if baseline.status not in _COMPARE_OK:
            raise HTTPException(status_code=409, detail="scan_not_terminal")
        if baseline.created_at >= current.created_at:
            raise HTTPException(status_code=409, detail="baseline_not_older")

    diff = await compute_diff(db, baseline, current)
    if diff.truncated:
        logger.warning(
            "scan_compare hit category cap of %d for org=%s, baseline=%s, current=%s",
            MAX_FINDINGS_PER_CATEGORY,
            org_id,
            baseline.id,
            current.id,
        )

    actor_id = identity.user.id if identity.user is not None else None
    audit_details: dict = {
        "baseline_scan_id": str(baseline.id),
        "current_scan_id": str(current.id),
        **{f"{k}_count": n for k, n in diff.counts().items()},
        "truncated": diff.truncated,
    }
    if identity.api_key is not None:
        audit_details["api_key_prefix"] = identity.api_key.key_prefix
    await audit(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        action=ScanAction.SCAN_COMPARED,
        resource_type="scan",
        resource_id=current.id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details=audit_details,  # type: ignore[arg-type]
    )
    await db.commit()

    def _rows(vs: list[Vulnerability]) -> list[ComparedFindingSummary]:
        return [ComparedFindingSummary.model_validate(v) for v in vs]

    return ScanComparisonResponse(
        baseline=ComparedScan.model_validate(baseline),
        current=ComparedScan.model_validate(current),
        summary=ComparisonSummary(
            **diff.counts(),
            truncated=diff.truncated,
            scope_covered=diff.scope_covered,
            scope_known=diff.scope_known,
        ),
        new=_rows(diff.new),
        regressions=_rows(diff.regressions),
        persisting=_rows(diff.persisting),
        fixed=_rows(diff.fixed),
        not_covered=_rows(diff.not_covered),
    )


# ================================================================ read endpoints (M11 pre-work)
#
# The dashboard, project page and scan page need three reads that the
# M4/M10 surface never shipped: an org-wide scans list, a project-scoped
# scans list, and a single-scan detail (the ``future GET`` the router
# comments above promised). Conventions carried over unchanged:
# require_org_membership + explicit organization_id filter (existence-
# hiding 404), offset pagination with PaginationMeta, CSV enum filters
# (M10.A), and no audit rows for reads.

_SCAN_SORT_COLUMNS = {
    "created_at": Scan.created_at,
    "completed_at": Scan.completed_at,
    "status": Scan.status,
}

# Job statuses that mean "this engine is done" for the N-of-M progress
# figure. Matches the completions consumer's terminal set.
_JOB_TERMINAL_STATUSES = ("completed", "failed", "canceled")

_E = TypeVar("_E", bound=Enum)


def _parse_csv_values(raw: str | None, enum_cls: type[_E], param: str) -> list[_E] | None:
    """CSV query param → enum members; 422 on an unknown token (M10.A Q2)."""
    if raw is None:
        return None
    members: list[_E] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            members.append(enum_cls(token))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"invalid {param} value: {token}") from None
    return members or None


async def _scan_rollups(
    db: AsyncSession, scan_ids: list[UUID]
) -> tuple[dict[UUID, tuple[int, int]], dict[UUID, int]]:
    """Per-scan (jobs_total, jobs_terminal) and vulnerability counts for
    one page of scans — two grouped queries, never N+1."""
    if not scan_ids:
        return {}, {}
    job_rows = (
        await db.execute(
            select(
                ScanJob.scan_id,
                func.count(ScanJob.id),
                func.count(ScanJob.id).filter(ScanJob.status.in_(_JOB_TERMINAL_STATUSES)),
            )
            .where(ScanJob.scan_id.in_(scan_ids))
            .group_by(ScanJob.scan_id)
        )
    ).all()
    jobs = {sid: (int(total), int(term)) for sid, total, term in job_rows}
    vuln_rows = (
        await db.execute(
            select(Vulnerability.scan_id, func.count(Vulnerability.id))
            .where(Vulnerability.scan_id.in_(scan_ids))
            .group_by(Vulnerability.scan_id)
        )
    ).all()
    vulns = {sid: int(n) for sid, n in vuln_rows}
    return jobs, vulns


async def _paginated_scans(
    db: AsyncSession,
    *,
    org_id: UUID,
    page: int,
    per_page: int,
    sort: str,
    status_filter: str | None,
    scan_type_filter: str | None,
    project_id: UUID | None,
) -> PaginatedScansResponse:
    descending = sort.startswith("-")
    sort_key = sort.lstrip("-")
    if sort_key not in _SCAN_SORT_COLUMNS:
        raise HTTPException(status_code=422, detail=f"invalid sort key: {sort_key}")

    where = [Scan.organization_id == org_id]
    statuses = _parse_csv_values(status_filter, ScanStatus, "status")
    if statuses:
        where.append(Scan.status.in_(statuses))
    types = _parse_csv_values(scan_type_filter, ScanType, "scan_type")
    if types:
        where.append(Scan.scan_type.in_(types))
    if project_id is not None:
        where.append(Scan.project_id == project_id)

    count_stmt = select(func.count(Scan.id))
    for clause in where:
        count_stmt = count_stmt.where(clause)
    total = (await db.execute(count_stmt)).scalar_one()

    col = _SCAN_SORT_COLUMNS[sort_key]
    stmt = select(Scan, Project.name).join(Project, Project.id == Scan.project_id)
    for clause in where:
        stmt = stmt.where(clause)
    # Deterministic secondary key so equal timestamps page stably.
    stmt = stmt.order_by(col.desc() if descending else col.asc(), Scan.id.desc())
    stmt = stmt.offset((page - 1) * per_page).limit(per_page)
    rows = (await db.execute(stmt)).all()

    jobs, vulns = await _scan_rollups(db, [scan.id for scan, _ in rows])

    items = []
    for scan, project_name in rows:
        jobs_total, jobs_terminal = jobs.get(scan.id, (0, 0))
        items.append(
            ScanListItem(
                id=scan.id,
                project_id=scan.project_id,
                project_name=project_name,
                scan_type=scan.scan_type.value,
                status=scan.status.value,
                priority=scan.priority,
                created_at=scan.created_at,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                jobs_total=jobs_total,
                jobs_terminal=jobs_terminal,
                vulnerability_count=vulns.get(scan.id, 0),
                ai_pipeline_degraded=scan.ai_pipeline_degraded,
            )
        )

    total_pages = max(1, ceil(total / per_page)) if total else 0
    return PaginatedScansResponse(
        items=items,
        pagination=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1,
        ),
    )


@scan_router.get("", response_model=PaginatedScansResponse)
async def list_org_scans(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    page: PageNumber = 1,
    per_page: PerPage = 20,
    sort: str = Query("-created_at"),
    status_: str | None = Query(None, alias="status"),
    scan_type: str | None = Query(None),
    project_id: UUID | None = Query(None),
) -> PaginatedScansResponse:
    """Org-wide scans list — the dashboard's "recent scans" and the
    /scans page. Newest first by default; ``status`` and ``scan_type``
    accept CSV; ``project_id`` narrows without a second route."""
    return await _paginated_scans(
        db,
        org_id=org_id,
        page=page,
        per_page=per_page,
        sort=sort,
        status_filter=status_,
        scan_type_filter=scan_type,
        project_id=project_id,
    )


@project_scans_router.get("", response_model=PaginatedScansResponse)
async def list_project_scans(
    org_id: UUID,
    project_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    page: PageNumber = 1,
    per_page: PerPage = 20,
    sort: str = Query("-created_at"),
    status_: str | None = Query(None, alias="status"),
    scan_type: str | None = Query(None),
) -> PaginatedScansResponse:
    """Project-scoped scans list (the project page's Scans tab). 404 when
    the project is missing or belongs to another tenant — the same
    existence-hiding as create_scan, so a wrong project_id never reads
    as an empty-but-valid list."""
    exists = (
        await db.execute(
            select(Project.id).where(Project.id == project_id, Project.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if exists is None:
        raise _NOT_FOUND
    return await _paginated_scans(
        db,
        org_id=org_id,
        page=page,
        per_page=per_page,
        sort=sort,
        status_filter=status_,
        scan_type_filter=scan_type,
        project_id=project_id,
    )


@scan_router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    org_id: UUID,
    scan_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
) -> ScanDetailResponse:
    """Single-scan header: identity, timing, outcome, per-engine jobs,
    raw/unique counts and severity totals. Pure read; the findings list
    and the executive narrative stay on their own endpoints."""
    row = (
        await db.execute(
            select(Scan, Project.name, Project.target_url)
            .join(Project, Project.id == Scan.project_id)
            .where(Scan.id == scan_id, Scan.organization_id == org_id)
        )
    ).one_or_none()
    if row is None:
        raise _NOT_FOUND
    scan, project_name, target_url = row

    job_rows = (
        (
            await db.execute(
                select(ScanJob).where(ScanJob.scan_id == scan_id).order_by(ScanJob.engine.asc())
            )
        )
        .scalars()
        .all()
    )

    raw_count = (
        await db.execute(select(func.count(RawFinding.id)).where(RawFinding.scan_id == scan_id))
    ).scalar_one()

    sev_rows = (
        await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.scan_id == scan_id)
            .group_by(Vulnerability.severity)
        )
    ).all()
    counts = {sev.value: int(n) for sev, n in sev_rows}
    severity_counts = SeverityCounts(**{s.value: counts.get(s.value, 0) for s in Severity})

    return ScanDetailResponse(
        id=scan.id,
        project_id=scan.project_id,
        project_name=project_name,
        target_url=target_url,
        organization_id=scan.organization_id,
        scan_type=scan.scan_type.value,
        status=scan.status.value,
        priority=scan.priority,
        recon_enabled=scan.recon_enabled,
        subdomain_limit=scan.subdomain_limit,
        mobile_upload_id=scan.mobile_upload_id,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        ai_pipeline_degraded=scan.ai_pipeline_degraded,
        executive_summary_available=bool(scan.executive_summary),
        jobs=[ScanJobDetail.model_validate(j) for j in job_rows],
        raw_finding_count=int(raw_count),
        vulnerability_count=sum(counts.values()),
        severity_counts=severity_counts,
    )


# ================================================================ SSE progress (Task 4.4)


# Block ms for ProgressSubscriber.live() — overrides the wrapper's
# default of 0 (block forever). Short blocks let the generator yield
# to sse-starlette's disconnect-detection scheduler frequently. 200ms
# = 5 iterations/sec; CPU cost negligible (loop body is empty when
# no events arrive). Critical for both test runtimes and production
# disconnect responsiveness.
_SSE_BLOCK_MS = 200

# Heartbeat interval. Stays comfortably under proxy idle timeouts
# (Cloudflare 100s, AWS ALB 60s, nginx 60s default). Pinned in
# DRIFT-LOG 2026-04-30 Task 4.4 ping=15 entry.
_SSE_PING_INTERVAL = 15  # seconds


def _parse_last_event_id(header: str | None) -> str:
    """Parse the ``Last-Event-ID`` header into a cursor for the
    progress generator.

    Returns one of:
      - ``"$"``   — no replay; live events only (default for empty/missing)
      - ``"-"``   — replay all history from beginning (test/debug client)
      - ``"<ms>-<seq>"`` — well-formed Redis stream id (replay since)

    Malformed inputs degrade gracefully to ``"$"`` (DRIFT-LOG: rejecting
    malformed ids is correct HTTP semantic but breaks reconnect-recovery
    for clients with stale state).
    """
    if not header:
        return "$"
    h = header.strip()
    if not h:
        return "$"
    if h == "-":
        return "-"
    if "-" in h:
        parts = h.split("-", 1)
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            return h
    return "$"


async def progress_generator(
    redis,
    scan_id_str: str,
    last_event_id: str,
):
    """Async generator yielding SSE event dicts for a scan's progress
    Stream.

    Extracted from the route handler so tests can iterate it directly
    without going through httpx ASGITransport — sse-starlette + ASGI
    in tests buffer streaming chunks unreliably, making end-to-end
    SSE asserts hang on empty reads. Generator-level tests are the
    canonical surface for the event-flow contract.

    See DRIFT-LOG 2026-04-30 Task 4.4 generator-extraction entry.
    """
    subscriber = ProgressSubscriber(redis, scan_id=scan_id_str)

    # Replay phase: XRANGE up to current latest. Skipped when
    # last_event_id == "$" (default — only future events).
    cursor = last_event_id
    if cursor != "$":
        async for entry_id, payload in subscriber.replay(since_id=cursor):
            # XRANGE is inclusive of since_id; if the client re-sent
            # the id of an event they already saw, skip it.
            if cursor not in ("-", "$") and entry_id == cursor:
                continue
            yield {
                "id": entry_id,
                "event": payload.get("event_type", "message"),
                "data": json.dumps(payload),
            }
            cursor = entry_id

    # Live phase: XREAD BLOCK from cursor. block_ms=200 lets the
    # generator wake periodically so sse-starlette can detect client
    # disconnect.
    live_cursor = cursor if cursor not in ("-", "$") else "$"
    async for entry_id, payload in subscriber.live(
        last_id=live_cursor,
        block_ms=_SSE_BLOCK_MS,
    ):
        yield {
            "id": entry_id,
            "event": payload.get("event_type", "message"),
            "data": json.dumps(payload),
        }


@scan_router.get("/{scan_id}/progress")
async def stream_scan_progress(
    org_id: UUID,
    scan_id: UUID,
    request: Request,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    """Stream scan progress events as Server-Sent Events (Task 4.4).

    GET /v1/orgs/{org_id}/scans/{scan_id}/progress
    Content-Type: text/event-stream

    Events flow Go worker -> Redis Streams -> this handler -> SSE client.
    Per ADR-014, progress events live on a Redis Stream
    (shieldscan:progress:{scan_id}); replay via XRANGE, live tail via
    XREAD BLOCK. The ProgressSubscriber wrapper from Task 4.1
    composes both seamlessly.

    Last-Event-ID semantics (SPEC 6.4):
      - Header absent or empty -> start at $ (only future events).
      - Header == "-" -> replay all history from beginning.
      - Header == <stream_id> -> replay events after that id.
      - Malformed header -> graceful degradation: treat as $.

    DB session lifetime (DRIFT-LOG 2026-04-30 Task 4.4 H.1):
      The session is closed immediately after scan lookup. Holding it
      open for the streaming phase would tie up a connection-pool slot
      per active SSE viewer (pool exhaustion at ~100 concurrent viewers).
      Streaming uses only Redis.

    Audit emission:
      None. Read-only operation; M10 GET endpoints will follow the
      same convention. INFO-level connect/disconnect logs provide
      operational visibility without polluting audit_logs.

    Auth: require_org_membership() - JWT or API key. CI/CD case is
    real (deploy pipeline watching scan progress).
    """
    # Step 1: scan lookup (404 on missing or cross-tenant). Same
    # existence-hiding discipline as cancel + compare.
    scan = (
        await db.execute(
            select(Scan).where(
                Scan.id == scan_id,
                Scan.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if scan is None:
        raise _NOT_FOUND

    # Step 2: read Last-Event-ID header (graceful degradation on
    # malformed values — see _parse_last_event_id docstring).
    last_event_id_header = request.headers.get("last-event-id")
    last_event_id = _parse_last_event_id(last_event_id_header)

    # Step 3: DB session lifetime — we're done with PG, only Redis
    # remains. Production note: the session is held open for the
    # connection's lifetime via FastAPI's request-scoped Depends
    # teardown. At ~100 concurrent SSE viewers the connection pool
    # would exhaust. The clean fix (explicit `await db.close()` here)
    # interferes with the test fixture's persistent-connection model
    # — the test's db_session shares one connection with the route
    # handler, and closing it would orphan subsequent test asserts.
    # Acceptable at MVP viewer counts (<20 concurrent). DRIFT-LOG
    # 2026-04-30 Task 4.4 H.1 entry tracks the deferred optimization;
    # ops milestone may revisit with a per-request session checkout
    # pattern that survives the close-after-lookup.

    # Step 4: instrument + build the generator. The generator function
    # is module-level (`progress_generator`) so tests can drive it
    # directly without going through httpx ASGITransport (which
    # buffers SSE chunks unreliably). The route here adds
    # request-scoped instrumentation (connect/disconnect logs).
    identity_kind = identity.kind
    start_ts = time.time()

    logger.info(
        "sse_progress_connected scan_id=%s identity_kind=%s last_event_id=%s",
        scan_id,
        identity_kind,
        (last_event_id_header or "").strip() or "(none)",
    )

    async def _instrumented():
        events_sent = 0
        try:
            async for event in progress_generator(redis, str(scan_id), last_event_id):
                yield event
                events_sent += 1
        finally:
            duration = time.time() - start_ts
            logger.info(
                "sse_progress_disconnected scan_id=%s duration_seconds=%.1f events_sent=%d",
                scan_id,
                duration,
                events_sent,
            )

    return EventSourceResponse(_instrumented(), ping=_SSE_PING_INTERVAL)


@scan_router.get(
    "/{scan_id}/attack-surface",
    response_model=AttackSurfaceResponse,
    summary="Get attack-surface for scan",
    description=(
        "Returns subdomain enumeration + probe results for a scan's recon "
        "phase. Per ADR-028, populated by phase-1 recon dispatch for web "
        "ScanTypes. Non-web ScanTypes (MOBILE/CONTAINER/API) and scans with "
        "no discovered surface return an empty payload (no recon rows)."
    ),
)
async def get_attack_surface(
    org_id: UUID,
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    identity: AuthIdentity = Depends(require_org_membership()),
) -> AttackSurfaceResponse:
    """Return the attack-surface for a scan (Task 8.3β per SPEC §6.3).

    Reads ``AttackSurface`` rows populated by the M8.1β.2 phase-1 recon
    dispatch (ADR-028). The endpoint is a pure read aggregation — no
    state mutation (ADR-013 sole-writer is unaffected).

    Auth: ``require_org_membership()`` (JWT or API key), any-member —
    symmetric with scan-create / cancel / progress. The dependency sets
    ``app.current_org_id`` (RLS GUC); the scan lookup additionally
    filters ``organization_id == org_id`` for existence-hiding
    (cross-tenant scan_id → 404, not 403).

    Y-decisions (ratified V-DDG this session):
      Y1: live = count(status==LIVE); dead = count(status in
          {DEAD, TIMEOUT}) — timeout bucketed as dead at the aggregate;
          each row still reports its true status in ``subdomains[]``.
      Y2: ``vulnerability_count`` joins the ``vulnerabilities`` table on
          ``target_url == full_url`` (SPEC-literal). The M9 AI pipeline
          populates that table; pre-M9 the count is 0. Forward-pinned.
      Y4: scan-not-found → 404; scan exists with no AttackSurface rows
          (incl. non-web ScanTypes) → 200 with an empty payload
          (consistent with ADR-028 Q2 i empty-AttackSurface-is-valid).
    """
    # Scan lookup with cross-tenant existence-hiding (404 not 403).
    scan = (
        await db.execute(
            select(Scan).where(
                Scan.id == scan_id,
                Scan.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if scan is None:
        raise _NOT_FOUND

    # AttackSurface rows for this scan (RLS-scoped via the org GUC the
    # auth dependency set; explicit scan_id filter narrows further).
    surface_rows = list(
        (await db.execute(select(AttackSurface).where(AttackSurface.scan_id == scan_id))).scalars()
    )

    # Y4: empty payload when no recon rows exist. root_domain is resolved
    # from the bound project's target_url via an explicit scalar query
    # (avoids an async lazy-load on scan.project).
    if not surface_rows:
        root_domain = (
            await db.execute(select(Project.target_url).where(Project.id == scan.project_id))
        ).scalar_one_or_none() or ""
        return AttackSurfaceResponse(
            root_domain=root_domain,
            total_discovered=0,
            live=0,
            dead=0,
            subdomains=[],
        )

    # Y2: per-subdomain vulnerability_count via Vulnerability.target_url ↔
    # AttackSurface.full_url join (SPEC-literal). 0 until M9 populates the
    # vulnerabilities table (forward-pinned).
    full_urls = [row.full_url for row in surface_rows]
    vuln_count_rows = (
        await db.execute(
            select(
                Vulnerability.target_url,
                func.count(Vulnerability.id),
            )
            .where(
                Vulnerability.scan_id == scan_id,
                Vulnerability.target_url.in_(full_urls),
            )
            .group_by(Vulnerability.target_url)
        )
    ).all()
    vuln_counts: dict[str, int] = {target_url: count for target_url, count in vuln_count_rows}

    # Y1: aggregate counts — timeout bucketed as dead; row-level status
    # preserved in the per-subdomain entries below.
    live_count = sum(1 for row in surface_rows if row.status == SubdomainStatus.LIVE)
    dead_count = sum(
        1 for row in surface_rows if row.status in {SubdomainStatus.DEAD, SubdomainStatus.TIMEOUT}
    )

    subdomains = [
        SubdomainEntry(
            url=row.full_url,
            status=row.status.value,
            status_code=row.status_code,
            tech_stack=row.tech_stack,
            vulnerability_count=vuln_counts.get(row.full_url, 0),
            last_probed_at=row.last_probed_at,
        )
        for row in surface_rows
    ]

    return AttackSurfaceResponse(
        root_domain=surface_rows[0].root_domain,
        total_discovered=len(surface_rows),
        live=live_count,
        dead=dead_count,
        subdomains=subdomains,
    )
