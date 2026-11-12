"""Platform-admin routes (M12 slice 3): ``/v1/admin/*``.

Gated by ``require_platform_admin`` (JWT + ``users.is_platform_admin``).
Catalog routes work on global tables; org routes switch the RLS context
to the target org and leave an ``admin.*`` audit row in that org's log.
"""

from __future__ import annotations

from uuid import UUID

import redis.asyncio as redis_asyncio
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import AuthIdentity, get_db, require_platform_admin
from app.redis_client import get_redis
from app.schemas.admin import (
    OrgAdminDetail,
    OrgAdminList,
    OverrideOut,
    OverrideSet,
    PlanAdminList,
    PlanAdminOut,
    PlanCreate,
    PlanPatch,
    PlanVersionCreate,
    PlanVersionOut,
    PlanVersionPublished,
    SubscriptionAssign,
    SubscriptionOut,
)
from app.services import admin_plans as svc
from app.services.admin_plans import AdminError

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_platform_admin)])


def _raise(e: AdminError) -> HTTPException:
    return HTTPException(status_code=e.status, detail=e.detail)


def _actor(identity: AuthIdentity) -> UUID | None:
    return identity.user.id if identity.user is not None else None


# ------------------------------------------------------------------ catalog


@router.get("/plans", response_model=PlanAdminList)
async def list_plans(db: AsyncSession = Depends(get_db)) -> PlanAdminList:
    return PlanAdminList(plans=await svc.list_plans(db))


@router.post("/plans", response_model=PlanAdminOut, status_code=status.HTTP_201_CREATED)
async def create_plan(body: PlanCreate, db: AsyncSession = Depends(get_db)) -> PlanAdminOut:
    try:
        plan = await svc.create_plan(
            db,
            code=body.code,
            name=body.name,
            description=body.description,
            rank=body.rank,
            is_public=body.is_public,
        )
    except AdminError as e:
        raise _raise(e)
    await db.commit()
    return next(p for p in await svc.list_plans(db) if p.id == plan.id)


@router.patch("/plans/{code}", response_model=PlanAdminOut)
async def patch_plan(
    code: str, body: PlanPatch, db: AsyncSession = Depends(get_db)
) -> PlanAdminOut:
    try:
        plan = await svc.get_plan(db, code)
        await svc.patch_plan(
            db,
            plan,
            name=body.name,
            description=body.description,
            rank=body.rank,
            is_public=body.is_public,
            archived=body.archived,
        )
    except AdminError as e:
        raise _raise(e)
    await db.commit()
    return next(p for p in await svc.list_plans(db) if p.id == plan.id)


@router.get("/plans/{code}/versions", response_model=list[PlanVersionOut])
async def list_versions(code: str, db: AsyncSession = Depends(get_db)) -> list[PlanVersionOut]:
    try:
        plan = await svc.get_plan(db, code)
    except AdminError as e:
        raise _raise(e)
    return await svc.list_versions(db, plan)


@router.post(
    "/plans/{code}/versions",
    response_model=PlanVersionPublished,
    status_code=status.HTTP_201_CREATED,
)
async def publish_version(
    code: str,
    body: PlanVersionCreate,
    identity: AuthIdentity = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
) -> PlanVersionPublished:
    try:
        plan = await svc.get_plan(db, code)
        out = await svc.publish_version(db, plan, body, actor_id=_actor(identity))
    except AdminError as e:
        raise _raise(e)
    await db.commit()
    return out


# ------------------------------------------------------------------ orgs


@router.get("/orgs", response_model=OrgAdminList)
async def list_orgs(
    q: str | None = Query(default=None, max_length=80),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> OrgAdminList:
    orgs, total = await svc.list_orgs(db, q=q, limit=limit, offset=offset)
    return OrgAdminList(orgs=orgs, total=total)


@router.get("/orgs/{org_id}", response_model=OrgAdminDetail)
async def org_detail(org_id: UUID, db: AsyncSession = Depends(get_db)) -> OrgAdminDetail:
    try:
        org = await svc.get_org(db, org_id)
    except AdminError as e:
        raise _raise(e)
    return await svc.org_detail(db, org)


@router.put("/orgs/{org_id}/overrides/{key}", response_model=OverrideOut)
async def set_override(
    org_id: UUID,
    key: str,
    body: OverrideSet,
    identity: AuthIdentity = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> OverrideOut:
    try:
        org = await svc.get_org(db, org_id)
        out = await svc.set_override(
            db,
            redis,
            org,
            key=key,
            value=body.value,
            reason=body.reason,
            expires_at=body.expires_at,
            actor_id=_actor(identity),
        )
    except AdminError as e:
        raise _raise(e)
    await db.commit()
    return out


@router.delete("/orgs/{org_id}/overrides/{key}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_override(
    org_id: UUID,
    key: str,
    identity: AuthIdentity = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> Response:
    try:
        org = await svc.get_org(db, org_id)
        await svc.remove_override(db, redis, org, key=key, actor_id=_actor(identity))
    except AdminError as e:
        raise _raise(e)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/orgs/{org_id}/subscription",
    response_model=SubscriptionOut,
    status_code=status.HTTP_201_CREATED,
)
async def assign_subscription(
    org_id: UUID,
    body: SubscriptionAssign,
    identity: AuthIdentity = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
) -> SubscriptionOut:
    try:
        org = await svc.get_org(db, org_id)
        out = await svc.assign_subscription(db, redis, org, body, actor_id=_actor(identity))
    except AdminError as e:
        raise _raise(e)
    await db.commit()
    return out
