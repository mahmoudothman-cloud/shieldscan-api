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

from fastapi import APIRouter, Depends, HTTPException, Request, status
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
from app.services.orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/orgs/{org_id}/projects/{project_id}/scans",
    tags=["scans"],
)


_NOT_FOUND = HTTPException(status_code=404, detail="not_found")
_DOMAIN_NOT_VERIFIED = HTTPException(
    status_code=403, detail="domain_not_verified"
)

# Scan types that bypass the domain-verified gate. Mobile = uploaded
# artifact is the bound asset. Container = image is the bound asset.
# project.target_url is informational for both, not an enforcement
# surface.
_DOMAIN_VERIFY_BYPASS: frozenset[ScanType] = frozenset(
    {ScanType.MOBILE, ScanType.CONTAINER}
)


@router.post(
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
