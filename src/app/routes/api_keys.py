"""API-key management endpoints (Task 2.4, Commit 2).

Endpoints under ``/v1/auth``::

    POST   /v1/auth/api-keys        201 APIKeyCreatedResponse
    GET    /v1/auth/api-keys        200 list[APIKeySummary]
    DELETE /v1/auth/api-keys/{id}   204 / 410

Policy (per ADR-012 + Task 2.4 scope):
  - create + delete require **JWT auth** (api-key credentials denied
    with 403 ``api_key_insufficient_for_operation``). Prevents a
    leaked key from bootstrapping persistent access.
  - create + delete require **MembershipRole.ADMIN** on the caller's
    membership in the target org (403 ``insufficient_role`` otherwise).
  - list accepts JWT OR api-key (useful for CI inventory).
  - Tenant scoping is **app-layer** — api_keys has no RLS (ADR-012).
    Every query explicitly filters ``organization_id = identity.org_id``.
  - Double-revoke returns 410 Gone (idempotent signal).
  - Cross-tenant delete attempts return 404 (not 403) to avoid
    leaking existence of keys in other orgs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

import redis.asyncio as redis_asyncio
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import (
    AuthIdentity,
    check_rate_limits,
    get_auth_identity,
    get_db,
    get_rate_limiter,
    get_real_ip,
    require_jwt,
)
from app.models.identity import APIKey, Membership, MembershipRole
from app.schemas.api_keys import (
    APIKeyCreatedResponse,
    APIKeyCreateRequest,
    APIKeySummary,
)
from app.services.api_keys import generate_api_key
from app.services.audit import AuthAction, audit
from app.redis_client import get_redis
from app.services.plan_enforcement import require_capacity
from app.services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/api-keys", tags=["auth"])


_INSUFFICIENT_ROLE = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="insufficient_role",
)


async def _require_admin(
    db: AsyncSession,
    identity: AuthIdentity,
) -> None:
    """Verify the JWT-authenticated user is ADMIN of their current org.

    Caller must have already validated ``identity.kind == "jwt"`` via
    ``require_jwt`` — this helper assumes ``identity.user`` is set.
    """
    assert identity.user is not None, "require_admin called without jwt user"
    result = await db.execute(
        select(Membership.role).where(
            Membership.user_id == identity.user.id,
            Membership.organization_id == identity.organization_id,
        )
    )
    role = result.scalar_one_or_none()
    if role != MembershipRole.ADMIN:
        raise _INSUFFICIENT_ROLE


# ---------------------------------------------------------------- create


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=APIKeyCreatedResponse,
)
async def create_api_key(
    body: APIKeyCreateRequest,
    request: Request,
    identity: AuthIdentity = Depends(require_jwt),
    db: AsyncSession = Depends(get_db),
    limiter: RateLimiter = Depends(get_rate_limiter),
    redis: redis_asyncio.Redis = Depends(get_redis),
):
    await _require_admin(db, identity)

    # Org-scoped rate limit (not IP-scoped) — a distributed script
    # hitting this from many IPs shouldn't be able to mint unlimited
    # keys. Key shape: `ratelimit:api_key_create:{org_id}:{bucket}`.
    await check_rate_limits(
        limiter,
        [("api_key_create", str(identity.organization_id), 10, 3600)],
    )

    # M12 slice 2: api_keys.max counts active (non-revoked) keys.
    active = (
        await db.execute(
            select(func.count(APIKey.id)).where(
                APIKey.organization_id == identity.organization_id,
                APIKey.revoked_at.is_(None),
            )
        )
    ).scalar_one()
    await require_capacity(db, redis, identity.organization_id, "api_keys.max", int(active))

    plaintext, key_hash, key_prefix = generate_api_key(env="live")
    assert identity.user is not None
    row = APIKey(
        organization_id=identity.organization_id,
        name=body.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
    )
    db.add(row)
    await db.flush()

    await audit(
        db,
        organization_id=identity.organization_id,
        actor_id=identity.user.id,
        action=AuthAction.API_KEY_CREATED,
        resource_type="api_key",
        resource_id=row.id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"api_key_prefix": key_prefix},
    )
    await db.commit()
    await db.refresh(row)

    return APIKeyCreatedResponse(
        id=row.id,
        name=row.name,
        key_prefix=row.key_prefix,
        plaintext_key=plaintext,
        created_at=row.created_at,
    )


# ---------------------------------------------------------------- list


@router.get("", response_model=list[APIKeySummary])
async def list_api_keys(
    identity: AuthIdentity = Depends(get_auth_identity),
    db: AsyncSession = Depends(get_db),
):
    # App-layer tenant scoping — api_keys has no RLS (ADR-012).
    # Every read path MUST include this WHERE clause explicitly.
    result = await db.execute(
        select(APIKey)
        .where(APIKey.organization_id == identity.organization_id)
        .order_by(APIKey.created_at.desc())
    )
    return [APIKeySummary.model_validate(row) for row in result.scalars().all()]


# ---------------------------------------------------------------- delete (revoke)


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: UUID,
    request: Request,
    identity: AuthIdentity = Depends(require_jwt),
    db: AsyncSession = Depends(get_db),
):
    await _require_admin(db, identity)

    # App-layer tenant scoping: a cross-tenant key_id lookup returns
    # None here, which we surface as 404 (NOT 403 or 410) to avoid
    # leaking the existence of keys in other orgs.
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id,
            APIKey.organization_id == identity.organization_id,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="api_key_not_found")

    if row.revoked_at is not None:
        # Idempotent-friendly signal — "this resource is gone, and
        # was previously gone." Distinct from 404 so a client syncing
        # revocation state can distinguish "never existed / wrong
        # org" from "already revoked."
        raise HTTPException(status_code=410, detail="api_key_already_revoked")

    row.revoked_at = datetime.now(timezone.utc)

    assert identity.user is not None
    await audit(
        db,
        organization_id=identity.organization_id,
        actor_id=identity.user.id,
        action=AuthAction.API_KEY_REVOKED,
        resource_type="api_key",
        resource_id=row.id,
        ip_address=get_real_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"api_key_prefix": row.key_prefix},
    )
    await db.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)
