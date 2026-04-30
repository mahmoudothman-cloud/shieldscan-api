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
  dispatch fails (M5+ retry janitor recovers — see ADR-013).

Audit emission (DRIFT-LOG):
  This route does NOT emit its own audit row. The orchestrator emits
  exactly one ``SCAN_DISPATCHED`` per scan-creation event. Adding a
  route-level audit would double-emit; pinned by
  ``test_create_scan_emits_exactly_one_scan_dispatched_audit``.
"""

from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import (
    AuthIdentity,
    get_db,
    get_real_ip,
    require_org_membership,
)
from app.models.mobile import MobileUpload
from app.models.projects import Project
from app.models.scans import Scan, ScanStatus, ScanType
from app.redis_client import get_redis
from app.schemas.scans import (
    ScanCreateRequest,
    ScanJobSummary,
    ScanResponse,
)
from app.services.audit import ScanAction, audit
from app.services.orchestrator import ScanOrchestrator
from app.services.scan_queue import CancelPublisher

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
_DOMAIN_NOT_VERIFIED = HTTPException(
    status_code=403, detail="domain_not_verified"
)
_SCAN_ALREADY_TERMINAL = HTTPException(
    status_code=409, detail="scan_already_terminal"
)


# Active scan states — cancel is meaningful.
_ACTIVE_STATES: frozenset[ScanStatus] = frozenset({
    ScanStatus.QUEUED,
    ScanStatus.RECONNING,
    ScanStatus.RUNNING,
    ScanStatus.ANALYZING,
})

# Terminal-final states — cancel is a no-op past these (the work
# already concluded, not by user intent). 409 to signal the conflict.
_TERMINAL_FINAL: frozenset[ScanStatus] = frozenset({
    ScanStatus.COMPLETED,
    ScanStatus.PARTIAL,
    ScanStatus.FAILED,
})

# Scan types that bypass the domain-verified gate. Mobile = uploaded
# artifact is the bound asset. Container = image is the bound asset.
# project.target_url is informational for both, not an enforcement
# surface.
_DOMAIN_VERIFY_BYPASS: frozenset[ScanType] = frozenset(
    {ScanType.MOBILE, ScanType.CONTAINER}
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
    if (
        body.scan_type not in _DOMAIN_VERIFY_BYPASS
        and not project.domain_verified
    ):
        raise _DOMAIN_NOT_VERIFIED

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

    # Step 6: build + flush Scan row (no commit — orchestrator owns).
    scan = Scan(
        organization_id=org_id,
        project_id=project_id,
        scan_type=body.scan_type,
        status=ScanStatus.QUEUED,
        priority=body.priority.value,
        config=body.config,
        recon_enabled=body.recon_enabled,
        subdomain_limit=body.subdomain_limit,
        mobile_upload_id=body.mobile_upload_id,
    )
    db.add(scan)
    await db.flush()

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

    previous_status = scan.status
    scan.status = ScanStatus.CANCELED  # no-op if already CANCELED

    actor_id = identity.user.id if identity.user is not None else None
    details: dict = {
        "scan_type": scan.scan_type.value,
        "previous_status": previous_status.value,
        "reason": "user_requested",
    }
    if identity.api_key is not None:
        details["api_key_prefix"] = identity.api_key.key_prefix

    await audit(
        db,
        organization_id=scan.organization_id,
        actor_id=actor_id,
        action=ScanAction.SCAN_CANCELED,
        resource_type="scan",
        resource_id=scan.id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details=details,  # type: ignore[arg-type]
    )
    await db.commit()

    # Publish cancel signal to Redis. Fire-and-forget; if this fails
    # post-commit, the scan is canceled in PG (visible to user) but
    # in-flight Go workers (M5+) won't receive the abort. Until M5
    # ships the worker-side subscriber, this signal goes into the
    # void anyway — see DRIFT-LOG.
    cancel_publisher = CancelPublisher(redis)
    try:
        await cancel_publisher.publish_cancel(
            str(scan_id), reason="user_requested"
        )
    except Exception:
        logger.exception(
            "cancel publish failed for scan_id=%s; PG state already "
            "CANCELED, will surface as ghost-canceled if workers running",
            scan_id,
        )
        # Don't raise — state is durable in PG; visible-failure mode.

    return Response(status_code=status.HTTP_204_NO_CONTENT)
