"""Public quick-scan endpoints (M11 pre-work; ADDENDUM-CRITICAL-5 §2).

    POST /v1/public/quick-scans          202 PublicScanCreateResponse
    GET  /v1/public/quick-scans/{slug}   200 PublicScanResultResponse

No authentication. Abuse controls, in order:

1. Pydantic: https-only target, work email, explicit consent (422).
2. IP limit — ``PUBLIC_SCAN_IP_HOURLY_LIMIT`` per hour, Redis fixed
   window (429 ``rate_limited`` with ``Retry-After``).
3. Email limit — ``PUBLIC_SCAN_EMAIL_DAILY_LIMIT`` per 24 h, counted in
   the database so a Redis restart cannot reset it (429
   ``email_limit_reached``).
4. The scan itself is bounded: QUICK tool set, no recon, one target.

Results are addressed by an unguessable slug that is emailed to the
requester; an unknown or expired slug is 404 / status ``expired``.
Every request runs under the system public-scan org's RLS context.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import redis.asyncio as redis_asyncio
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.dependencies import get_db, get_rate_limiter, get_real_ip
from app.redis_client import get_redis
from app.schemas.public_scans import (
    PublicScanCreateRequest,
    PublicScanCreateResponse,
    PublicScanResultResponse,
)
from app.services.email import EmailService, get_email_service
from app.services.public_scans import (
    build_result,
    count_recent_for_email,
    create_public_scan,
    enter_public_tenant,
    get_public_scan_by_slug,
)
from app.services.rate_limiter import RateLimiter

router = APIRouter(prefix="/public/quick-scans", tags=["public"])

_NOT_FOUND = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
_EMAIL_LIMIT = HTTPException(
    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
    detail="email_limit_reached",
    headers={"Retry-After": "86400"},
)

# Rough wall-clock for the QUICK set (nuclei quick templates + sslyze)
# on a single origin. Shown as a hint on the progress screen only.
_ESTIMATED_SECONDS = 90


def _result_url(slug: str) -> str:
    return f"{settings.APP_BASE_URL}/q/{slug}"


@router.post(
    "",
    response_model=PublicScanCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_quick_scan(
    body: PublicScanCreateRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: redis_asyncio.Redis = Depends(get_redis),
    limiter: RateLimiter = Depends(get_rate_limiter),
    email_service: EmailService = Depends(get_email_service),
) -> PublicScanCreateResponse:
    ip = get_real_ip(request)

    # 1. IP window first — cheapest check, and it protects the DB query
    #    behind it from being used as an amplifier.
    rl = await limiter.check("public_scan_ip", ip, settings.PUBLIC_SCAN_IP_HOURLY_LIMIT, 3600)
    if not rl.allowed:
        retry = max(1, rl.reset_at - int(datetime.now(timezone.utc).timestamp()))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="rate_limited",
            headers={"Retry-After": str(retry)},
        )

    org = await enter_public_tenant(db)

    # 2. Email window — one free scan per address per day.
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    if (
        await count_recent_for_email(db, org.id, body.email, since)
        >= settings.PUBLIC_SCAN_EMAIL_DAILY_LIMIT
    ):
        raise _EMAIL_LIMIT

    public = await create_public_scan(
        db,
        redis,
        org=org,
        target_url=body.target_url,
        email=body.email,
        ip_address=ip,
        user_agent=request.headers.get("User-Agent"),
    )

    # 3. Result link by email, after commit. A failed send must not undo
    #    the scan — the response carries the same link.
    await email_service.send(
        to=body.email,
        subject=f"Your ShieldScan quick scan of {public.normalized_domain}",
        body=(
            f"Hi,\n\n"
            f"We're running a read-only quick scan of {public.target_url}. "
            f"Results appear here as they come in:\n\n"
            f"{_result_url(public.slug)}\n\n"
            f"This link is private to you and expires in "
            f"{settings.PUBLIC_SCAN_RESULT_TTL_DAYS} days.\n"
        ),
        template="public_scan_result_link",
    )

    response.headers["Location"] = f"/v1/public/quick-scans/{public.slug}"
    return PublicScanCreateResponse(
        slug=public.slug,
        status="queued",
        target_url=public.target_url,
        result_url=_result_url(public.slug),
        estimated_seconds=_ESTIMATED_SECONDS,
        expires_at=public.expires_at,
    )


@router.get("/{slug}", response_model=PublicScanResultResponse)
async def get_quick_scan(
    slug: str,
    db: AsyncSession = Depends(get_db),
) -> PublicScanResultResponse:
    if len(slug) > 64:
        raise _NOT_FOUND
    await enter_public_tenant(db)
    public = await get_public_scan_by_slug(db, slug)
    if public is None:
        raise _NOT_FOUND
    result = await build_result(db, public)
    if result.status != "expired":
        public.viewed_count += 1
        await db.commit()
    return result
