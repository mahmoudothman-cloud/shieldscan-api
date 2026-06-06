"""Project CRUD endpoints (Task 3.1).

Five endpoints under ``/v1/orgs/{org_id}/projects[/{id}]``:

    POST   /v1/orgs/{org_id}/projects          201 ProjectResponse
    GET    /v1/orgs/{org_id}/projects          200 PaginatedProjectsResponse
    GET    /v1/orgs/{org_id}/projects/{id}     200 ProjectResponse
    PATCH  /v1/orgs/{org_id}/projects/{id}     200 ProjectResponse
    DELETE /v1/orgs/{org_id}/projects/{id}     204 (soft-delete)

Tenant scoping is dual-layer:
  1. ``require_org_membership`` dep validates path-vs-identity org match
     (404 on mismatch — no existence leak) and SETs the GUC for RLS.
  2. Every query handler also includes ``WHERE organization_id =
     identity.organization_id`` as defense-in-depth (the projects table
     IS RLS-protected so this is redundant in normal operation, but
     the explicit WHERE survives any future RLS misconfiguration).

DELETE is a SOFT DELETE: sets ``archived_at = now()``. GET on an
archived project returns 200 with ``archived_at`` populated (per
Task 3.1 §6 decision: archived projects are reversible state, not
deleted state). List filter ``?archived=true`` includes archived;
default excludes them.

PATCH on ``target_url`` that changes ``root_domain`` auto-resets
``domain_verified=False`` and mints a fresh ``verification_token``
— prevents a verified-domain mismatch sneaking past after a target
change. See DRIFT-LOG 2026-04-23 entry on auto-reset.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from math import ceil
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import select_fresh
from app.dependencies import (
    AuthIdentity,
    check_rate_limits,
    get_db,
    get_rate_limiter,
    get_real_ip,
    require_org_membership,
)
from app.models.identity import MembershipRole
from app.models.projects import Project, ProjectCredential
from app.schemas.credentials import (
    CredentialRequest,
    CredentialResponse,
)
from app.redis_client import get_redis
from app.services.audit import ProjectAction, audit
from app.services.credentials import encrypt_credential
from app.services.projects import find_in_flight_scans_by_project
from app.services.scan_queue import apply_cancel_state, publish_cancel_signal
from app.schemas.projects import (
    PaginatedProjectsResponse,
    PaginationMeta,
    PageNumber,
    PerPage,
    ProjectCreateRequest,
    ProjectResponse,
    ProjectUpdateRequest,
    VerifyDomainFailure,
    VerifyDomainRequest,
    VerifyDomainSuccess,
)
from app.services.domain_verify import (
    VerifyResult,
    verify_dns_txt,
    verify_meta_tag,
)
from app.services.projects import extract_root_domain
from app.services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/orgs/{org_id}/projects", tags=["projects"])


_NOT_FOUND = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail="not_found",
)
_GONE = HTTPException(
    status_code=status.HTTP_410_GONE,
    detail="project_already_archived",
)
_INSUFFICIENT_ROLE = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="insufficient_role",
)
_PROJECT_ARCHIVED_CONFLICT = HTTPException(
    status_code=status.HTTP_409_CONFLICT,
    detail="project_archived",
)


# ---------------------------------------------------------------- admin-or-api-key dep (Task 3.X)


async def require_admin_or_api_key(
    identity: AuthIdentity = Depends(require_org_membership()),
) -> AuthIdentity:
    """Wrap ``require_org_membership`` with an admin role check that
    only applies to JWT callers.

    API-key callers bypass the role check: API keys are admin-equivalent
    at creation time (Task 2.4 requires admin JWT to mint a key), so
    any authenticated API-key call is by-construction privileged.
    Reusable for future admin-or-api-key endpoints.
    """
    if identity.kind == "api_key":
        return identity
    if identity.role != MembershipRole.ADMIN:
        raise _INSUFFICIENT_ROLE
    return identity


# ---------------------------------------------------------------- create


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=ProjectResponse,
)
async def create_project(
    org_id: UUID,
    body: ProjectCreateRequest,
    request: Request,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
):
    try:
        root_domain = extract_root_domain(body.target_url)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    project = Project(
        organization_id=org_id,
        name=body.name,
        target_url=body.target_url,
        root_domain=root_domain,
        source_repo_url=body.source_repo_url,
        container_image=body.container_image,
        # domain_verified defaults to False; verification_token auto-
        # generated via the model's default factory.
    )
    db.add(project)
    await db.flush()

    await audit(
        db,
        organization_id=org_id,
        actor_id=identity.user.id if identity.user is not None else None,
        action=ProjectAction.PROJECT_CREATED,
        resource_type="project",
        resource_id=project.id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    await db.commit()
    await db.refresh(project)

    return ProjectResponse.model_validate(project)


# ---------------------------------------------------------------- list


_SORT_COLUMNS = {
    "created_at": Project.created_at,
    "updated_at": Project.updated_at,
    "name": Project.name,
}


@router.get("", response_model=PaginatedProjectsResponse)
async def list_projects(
    org_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    page: PageNumber = 1,
    per_page: PerPage = 20,
    sort: str = Query("-created_at"),
    archived: bool = Query(False, description="Include archived projects"),
):
    # Validate sort key.
    descending = sort.startswith("-")
    sort_key = sort.lstrip("-")
    if sort_key not in _SORT_COLUMNS:
        raise HTTPException(
            status_code=422,
            detail=f"invalid sort key: {sort_key}",
        )

    # WHERE clause is shared between COUNT and SELECT to keep total
    # consistent with the items returned (per Task 3.1 watch item).
    base_where = [Project.organization_id == org_id]
    if not archived:
        base_where.append(Project.archived_at.is_(None))

    # Total count.
    count_stmt = select(func.count(Project.id))
    for clause in base_where:
        count_stmt = count_stmt.where(clause)
    total = (await db.execute(count_stmt)).scalar_one()

    # Items page.
    col = _SORT_COLUMNS[sort_key]
    stmt = select(Project)
    for clause in base_where:
        stmt = stmt.where(clause)
    stmt = stmt.order_by(col.desc() if descending else col.asc())
    stmt = stmt.offset((page - 1) * per_page).limit(per_page)
    rows = (await db.execute(stmt)).scalars().all()

    total_pages = max(1, ceil(total / per_page)) if total else 0
    return PaginatedProjectsResponse(
        items=[ProjectResponse.model_validate(r) for r in rows],
        pagination=PaginationMeta(
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
            has_next=page * per_page < total,
            has_prev=page > 1,
        ),
    )


# ---------------------------------------------------------------- single


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    org_id: UUID,
    project_id: UUID,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
):
    """Fetch a project by id. Archived projects return 200 with
    ``archived_at`` populated — soft-delete is reversible."""
    project = await _load_project(db, org_id, project_id)
    if project is None:
        raise _NOT_FOUND
    return ProjectResponse.model_validate(project)


# ---------------------------------------------------------------- patch


@router.patch("/{project_id}", response_model=ProjectResponse)
async def patch_project(
    org_id: UUID,
    project_id: UUID,
    body: ProjectUpdateRequest,
    request: Request,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
):
    project = await _load_project(db, org_id, project_id)
    if project is None:
        raise _NOT_FOUND

    update = body.model_dump(exclude_unset=True)

    # target_url change that alters root_domain auto-resets
    # verification state (DRIFT-LOG 2026-04-23). Same domain → no
    # reset (path/port-only changes don't invalidate the binding).
    if "target_url" in update:
        try:
            new_root = extract_root_domain(update["target_url"])
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        if new_root != project.root_domain:
            project.root_domain = new_root
            project.domain_verified = False
            project.verification_token = uuid4().hex

    # Apply mutable fields. Immutable fields are blocked at schema
    # level (extra="forbid") so anything in `update` is safe.
    for field, value in update.items():
        setattr(project, field, value)

    await audit(
        db,
        organization_id=org_id,
        actor_id=identity.user.id if identity.user is not None else None,
        action=ProjectAction.PROJECT_UPDATED,
        resource_type="project",
        resource_id=project.id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    await db.commit()
    await db.refresh(project)
    return ProjectResponse.model_validate(project)


# ---------------------------------------------------------------- delete (soft)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    org_id: UUID,
    project_id: UUID,
    request: Request,
    identity: AuthIdentity = Depends(require_org_membership(jwt_only=True)),
    db: AsyncSession = Depends(get_db),
):
    """Soft-delete: sets ``archived_at = now()``. Already-archived →
    410 Gone (idempotent-friendly signal, distinct from 404)."""
    project = await _load_project(db, org_id, project_id)
    if project is None:
        raise _NOT_FOUND
    if project.archived_at is not None:
        raise _GONE
    project.archived_at = datetime.now(timezone.utc)
    await audit(
        db,
        organization_id=org_id,
        actor_id=identity.user.id if identity.user is not None else None,
        action=ProjectAction.PROJECT_ARCHIVED,
        resource_type="project",
        resource_id=project.id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------- helpers


async def _load_project(
    db: AsyncSession, org_id: UUID, project_id: UUID
) -> Project | None:
    """Single-row fetch with explicit org_id filter. Defense-in-depth
    on top of RLS — keeps the WHERE clause visible at every callsite."""
    stmt = select(Project).where(
        Project.id == project_id,
        Project.organization_id == org_id,
    )
    return (await db.execute(stmt)).scalar_one_or_none()


# ---------------------------------------------------------------- domain verification (Task 3.2)


@router.post("/{project_id}/verify")
async def verify_domain(
    org_id: UUID,
    project_id: UUID,
    body: VerifyDomainRequest,
    request: Request,
    identity: AuthIdentity = Depends(require_org_membership()),
    db: AsyncSession = Depends(get_db),
    limiter: RateLimiter = Depends(get_rate_limiter),
):
    """Verify domain ownership for a project.

    Two methods supported:
      - ``dns_txt``  — DNS TXT record at ``_shieldscan-verify.<root>``
      - ``meta_tag`` — HTML meta tag in the ``target_url`` page

    Auth: JWT or API-key, any org member (verification is a setup
    action, not a security mutation in the 403-required sense).

    Rate-limited 5/hour per project (DNS lookups + outbound HTTP have
    real cost; legitimate users verify once at setup, occasionally
    on re-aim). Identifier = project_id, scope = ``project_domain_verify``.

    On success: ``project.domain_verified = True``, audit
    ``PROJECT_DOMAIN_VERIFIED``, return 200 with the project body.
    On failure: ``domain_verified`` left UNCHANGED (re-verify on
    already-verified project that fails keeps verified=True — DNS
    can be flaky; one failure shouldn't downgrade historical state).
    Audit ``PROJECT_DOMAIN_VERIFICATION_FAILED`` with reason in
    details. Return 400 with ``expected_record`` for UX.
    """
    # Per-project rate limit. Returning 429 (not silent-drop) here
    # because /verify is an authenticated endpoint where the caller
    # legitimately needs to know they're being throttled.
    await check_rate_limits(
        limiter,
        [("project_domain_verify", str(project_id), 5, 3600)],
    )

    project = await _load_project(db, org_id, project_id)
    if project is None:
        raise _NOT_FOUND

    # Dispatch on method.
    result: VerifyResult
    if body.method == "dns_txt":
        result = await verify_dns_txt(project.root_domain, project.verification_token)
    elif body.method == "meta_tag":
        result = await verify_meta_tag(project.target_url, project.verification_token)
    else:  # pragma: no cover — schema validator guards this
        raise HTTPException(status_code=422, detail="invalid method")

    actor_id = identity.user.id if identity.user is not None else None
    ip = get_real_ip(request)
    ua = request.headers.get("User-Agent")

    if result.verified:
        # Flip if not already verified; re-verify is idempotent (no
        # state change on an already-True row).
        was_already_verified = project.domain_verified
        if not was_already_verified:
            project.domain_verified = True
        await audit(
            db,
            organization_id=org_id,
            actor_id=actor_id,
            action=ProjectAction.PROJECT_DOMAIN_VERIFIED,
            resource_type="project",
            resource_id=project.id,
            ip_address=ip,
            user_agent=ua,
            details={"method": body.method},
        )
        await db.commit()
        await db.refresh(project)
        return VerifyDomainSuccess(
            method=body.method,
            project=ProjectResponse.model_validate(project),
        )

    # Failure path. domain_verified stays as-is — re-verify on an
    # already-verified project that fails today does NOT downgrade
    # to False (Task 3.2 #3 refinement; DNS is occasionally flaky).
    await audit(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        action=ProjectAction.PROJECT_DOMAIN_VERIFICATION_FAILED,
        resource_type="project",
        resource_id=project.id,
        ip_address=ip,
        user_agent=ua,
        details={"method": body.method, "reason": result.failure_reason},
    )
    await db.commit()
    raise HTTPException(
        status_code=400,
        detail=VerifyDomainFailure(
            method=body.method,
            failure_reason=result.failure_reason or "unknown",
            expected_record=result.expected_record or "",
        ).model_dump(),
    )


# ---------------------------------------------------------------- credentials (Task 3.X)


@router.patch(
    "/{project_id}/credentials",
    response_model=CredentialResponse,
)
async def patch_project_credentials(
    org_id: UUID,
    project_id: UUID,
    body: CredentialRequest,
    request: Request,
    identity: AuthIdentity = Depends(require_admin_or_api_key),
    db: AsyncSession = Depends(get_db),
):
    """Set or replace the project's auth credential.

    Replace-in-place semantics: each call fully replaces any existing
    credential for the project. Type changes (basic → bearer) work
    naturally — the auth_type column updates and a fresh
    ``encrypted_data`` blob is written.

    Atomicity: uses PostgreSQL UPSERT
    (``INSERT ... ON CONFLICT (project_id) DO UPDATE``) to avoid the
    SELECT-then-INSERT-or-UPDATE race window. The
    ``uq_project_credentials_project_id`` constraint
    (migration ``d4f6b1e9a527``) is the conflict target.

    Audit ``project.credential.set``. ``details`` carries
    ``auth_type`` only — never field names or values.

    Archived project → 409 ``project_archived``.
    """
    project = await _load_project(db, org_id, project_id)
    if project is None:
        raise _NOT_FOUND
    if project.archived_at is not None:
        raise _PROJECT_ARCHIVED_CONFLICT

    # Encrypt only the secret fields — auth_type lives in its own
    # column. Pydantic discriminator already stripped any extras
    # (extra="forbid" on each variant).
    payload = body.model_dump(mode="json", exclude={"auth_type"})
    blob = encrypt_credential(payload)

    # Atomic UPSERT — no SELECT-then-WRITE race window.
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    stmt = pg_insert(ProjectCredential).values(
        project_id=project_id,
        organization_id=org_id,
        auth_type=body.auth_type,
        encrypted_data=blob,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["project_id"],
        set_={
            "auth_type": body.auth_type,
            "encrypted_data": blob,
            "updated_at": datetime.now(timezone.utc),
        },
    )
    await db.execute(stmt)

    actor_id = identity.user.id if identity.user is not None else None
    await audit(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        action=ProjectAction.PROJECT_CREDENTIAL_SET,
        resource_type="project",
        resource_id=project_id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
        # NEVER include field names or values — auth_type only.
        details={"auth_type": body.auth_type},  # type: ignore[typeddict-unknown-key]
    )
    await db.commit()

    # ``select_fresh`` bypasses the session identity-map cache so a
    # second PATCH on the same project sees the freshly-UPSERTed row
    # rather than the first PATCH's cached snapshot. See
    # ``app.db.select_fresh`` + DEVELOPMENT-PATTERNS.md for context.
    cred = (
        await select_fresh(
            db,
            select(ProjectCredential).where(
                ProjectCredential.project_id == project_id
            ),
        )
    ).scalar_one()

    return CredentialResponse(
        auth_type=cred.auth_type,
        configured=True,
        updated_at=cred.updated_at,
    )


@router.delete(
    "/{project_id}/credentials",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_project_credentials(
    org_id: UUID,
    project_id: UUID,
    request: Request,
    identity: AuthIdentity = Depends(require_admin_or_api_key),
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    """Revoke the project's credential. 204 on success, even if no
    credential existed (idempotent). Archived project → 409.

    Credential Revocation Flow task (2026-05-28) — extends prior
    "clear credential" semantics with cascade-cancel of in-flight
    scans per SPEC §13 ADR-015 Addendum: Credential Lifecycle
    Extension. Endpoint semantics: revoke (= remove credential +
    cascade-cancel in-flight scans). Idempotency preserved: silent
    204 when no credential existed (no audit emission per
    Y-IDEMPOTENCY-SEMANTICS a default; existing pattern).

    Audit emission order (Y-AUDIT-EMISSION-ORDER a default per plan
    fdad021 §3.3):
      1. ``project.credential.revoked`` (NEW; Q6 b) — revoke-action
         precedes delete-effect
      2. ProjectCredential row hard-deleted (Q2 γ; per-project UNIQUE
         invariant preserved without partial-index relaxation)
      3. ``project.credential.deleted`` (existing; preserved for
         backward-compat)
      4. Cascade-cancel loop per Q4 a: for each in-flight scan, flip
         PG state → CANCELED + emit ``scan.canceled`` audit (Task 4.5
         reuse) + ``CancelPublisher.publish_cancel`` (Pub/Sub signal)

    Engine-side handling per Q1 (b) axis 4 + Q5 (a) ZERO scope: the
    engine cancel-watcher (V-FG; ``processor.go:181-322`` per-job
    ``jobCtx`` + ``spawnCancelWatcher`` + ``ctx.Done`` + 3
    goleak-clean exit paths per ADR-021 Rule 2) handles
    credential-revocation-cancel identically to user-initiated
    cancel — no event-payload distinction needed.

    Drift #51 (catalogued): plan §3.4 said "invoke existing
    ``cancel_scan(...)`` per scan"; empirically ``cancel_scan`` is a
    FastAPI route handler with Request/identity/redis deps, not
    directly callable. Resolution: inline equivalent logic in
    cascade loop (state flip + ``SCAN_CANCELED`` audit +
    ``CancelPublisher.publish_cancel``); preserves "Task 4.5 audit +
    Publisher infrastructure reused 1:1" claim conceptually.
    """
    project = await _load_project(db, org_id, project_id)
    if project is None:
        raise _NOT_FOUND
    if project.archived_at is not None:
        raise _PROJECT_ARCHIVED_CONFLICT

    cred = (
        await db.execute(
            select(ProjectCredential).where(
                ProjectCredential.project_id == project_id
            )
        )
    ).scalar_one_or_none()
    if cred is None:
        # Nothing to revoke — return 204 without an audit row
        # (Y-IDEMPOTENCY-SEMANTICS a; existing pattern preserved).
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    actor_id = identity.user.id if identity.user is not None else None
    ip_address = get_real_ip(request)
    user_agent = request.headers.get("User-Agent")

    # Step 1: PROJECT_CREDENTIAL_REVOKED audit (Q6 b; Y-AUDIT-EMISSION-ORDER a).
    await audit(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        action=ProjectAction.PROJECT_CREDENTIAL_REVOKED,
        resource_type="project",
        resource_id=project_id,
        ip_address=ip_address,
        user_agent=user_agent,
        details={"auth_type": cred.auth_type},  # type: ignore[typeddict-unknown-key]
    )

    # Step 2: hard-delete ProjectCredential row (Q2 γ).
    await db.delete(cred)

    # Step 3: PROJECT_CREDENTIAL_DELETED audit (existing; backward-compat).
    await audit(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        action=ProjectAction.PROJECT_CREDENTIAL_DELETED,
        resource_type="project",
        resource_id=project_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Step 4: cascade-cancel in-flight scans (Q4 a fan-out).
    # Note: cancel-targets are discovered BEFORE commit so the
    # credential delete + cascade-cancel-state-flips ship in one
    # atomic transaction (commit-then-publish ordering matches
    # Task 4.5 cancel_scan).
    in_flight = await find_in_flight_scans_by_project(db, project_id)
    cascade_signals: list[str] = []
    for scan in in_flight:
        # Shared kernel: flip state + emit SCAN_CANCELED audit (Drift
        # #51 rule-of-three extraction at services/scan_queue.py).
        # api_key_prefix=None per V-GD #2 (cascade caller does not
        # surface identity.api_key granularity in details).
        await apply_cancel_state(
            db,
            scan,
            actor_id=actor_id,
            reason="credential_revoked",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        cascade_signals.append(str(scan.id))

    await db.commit()

    # Step 5: publish cancel signals post-commit (Task 4.5 ordering;
    # fire-and-forget — durable PG state is the source of truth).
    for scan_id in cascade_signals:
        await publish_cancel_signal(
            redis, scan_id, reason="credential_revoked", logger=logger
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)
