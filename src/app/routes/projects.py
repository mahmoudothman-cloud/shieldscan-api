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

from app.dependencies import (
    AuthIdentity,
    get_db,
    require_org_membership,
)
from app.models.projects import Project
from app.schemas.projects import (
    PaginatedProjectsResponse,
    PaginationMeta,
    PageNumber,
    PerPage,
    ProjectCreateRequest,
    ProjectResponse,
    ProjectUpdateRequest,
)
from app.services.projects import extract_root_domain

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

    await db.commit()
    await db.refresh(project)
    return ProjectResponse.model_validate(project)


# ---------------------------------------------------------------- delete (soft)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    org_id: UUID,
    project_id: UUID,
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
