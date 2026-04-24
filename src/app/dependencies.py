"""FastAPI dependencies for auth-protected endpoints (Sub-task 2.3.4, Commit 2).

Three layers of dependencies:

1. **Infrastructure:** ``get_db``, ``get_redis``, ``get_rate_limiter``.
   Yield per-request handles to the shared backends.

2. **Identity:** ``get_current_user``. Parses ``Authorization: Bearer
   <token>``, decodes the JWT, checks type + revocation status +
   user-still-exists, returns the ``User``. Fails closed on any
   uncertainty (including Redis outages) with HTTP 401.

3. **Rate limiting:** ``rate_limit(scope, limit, window, id_fn=...)``
   factory. Returns a FastAPI dependency that increments a Redis
   fixed-window counter and raises 429 with ``Retry-After`` if over
   the limit. Default ``id_fn`` uses the real client IP (CF header
   / X-Forwarded-For fallback / ``request.client.host`` last).

HTTP code discipline (401 vs 403):
  - **401 Unauthorized:** missing, malformed, expired, revoked, or
    invalid-type token; user-deleted-but-token-alive. The *request*
    failed authentication.
  - **403 Forbidden:** authenticated successfully but the user's
    state forbids the action (e.g. ``email_verified is False`` on
    an endpoint that requires verified email). The *user* is not
    allowed to do this thing.
"""

from __future__ import annotations

import logging
from typing import AsyncIterator, Awaitable, Callable
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import AsyncSessionLocal
from app.models.identity import User
from app.redis_client import get_redis
from app.services.auth import (
    TokenError,
    TokenExpiredError,
    TokenInvalidError,
    decode_token,
)
from app.services.rate_limiter import RateLimiter
from app.services.token_revocation import is_revoked

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------- infrastructure


async def get_db() -> AsyncIterator[AsyncSession]:
    """Per-request SQLAlchemy session. FastAPI closes it on yield-end."""
    async with AsyncSessionLocal() as session:
        yield session


async def get_rate_limiter(
    redis=Depends(get_redis),
) -> RateLimiter:
    return RateLimiter(redis)


# ---------------------------------------------------------------- real IP


def get_real_ip(request: Request) -> str:
    """Extract the real client IP, honoring CF/proxy headers.

    Ordering matters: Cloudflare's ``CF-Connecting-IP`` is the
    canonical signal when we run behind CF; ``X-Forwarded-For`` is a
    general fallback (take the leftmost — that's the true client);
    ``request.client.host`` is the last resort for direct-connect
    local dev.

    Note: in production we MUST ensure these headers are stripped by
    the ingress before reaching the app, otherwise a client can
    impersonate any IP by setting ``CF-Connecting-IP`` directly.
    Enforced at the load balancer layer.
    """
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------- rate limiting


def rate_limit(
    scope: str,
    limit: int,
    window: int,
    id_fn: Callable[[Request], str] | None = None,
) -> Callable[..., Awaitable[None]]:
    """Factory producing a FastAPI dependency that enforces a
    fixed-window rate limit.

    - ``scope``: key namespace (e.g. ``"login_ip"``, ``"register"``).
    - ``limit`` + ``window``: at most ``limit`` requests per ``window``
      seconds.
    - ``id_fn``: extract the identifier from the request. Defaults to
      ``get_real_ip`` (IP-scoped). For email-scoped limits the check
      typically runs in the handler body (post-body-parse), not here.

    On deny, raises ``HTTPException(429)`` with a ``Retry-After``
    header = seconds until the current window ends.
    """
    extractor = id_fn or get_real_ip

    async def _check(
        request: Request,
        limiter: RateLimiter = Depends(get_rate_limiter),
    ) -> None:
        identifier = extractor(request)
        result = await limiter.check(scope, identifier, limit=limit, window_seconds=window)
        if not result.allowed:
            retry_after = max(1, result.reset_at - int(request.scope.get("time") or 0))
            # reset_at is a wall-clock unix second; retry-after must
            # be a positive delta. Fall back to window length if we
            # can't compute it (we never stored `time` in scope).
            if retry_after <= 1:
                retry_after = window
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="rate_limit_exceeded",
                headers={"Retry-After": str(retry_after)},
            )

    return _check


async def check_rate_limits(
    limiter: RateLimiter,
    checks: list[tuple[str, str, int, int]],
) -> None:
    """Multi-scope rate-limit helper for handler-body checks.

    Each entry is ``(scope, identifier, limit, window_seconds)``.
    Returns on success; raises 429 with ``Retry-After`` on first
    denied check. Used for checks that depend on parsed request body
    (e.g. ``login_email`` keyed on the email from ``LoginRequest``).
    """
    for scope, identifier, limit, window in checks:
        result = await limiter.check(scope, identifier, limit=limit, window_seconds=window)
        if not result.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="rate_limit_exceeded",
                headers={"Retry-After": str(window)},
            )


# ---------------------------------------------------------------- current user


_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="unauthorized",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
) -> User:
    """Resolve the caller's ``User`` from the ``Authorization`` header.

    Failure-path ordering (all paths return identical 401 bodies — no
    enumeration of which step failed):

      a. Header missing / not ``Bearer <…>``   -> 401
      b. decode_token raises                   -> 401
         (both TokenExpiredError and TokenInvalidError collapse to
         the same response — clients must not branch on which)
      c. payload["type"] != "access"           -> 401
         (refresh token sent to an access-only endpoint)
      d. is_revoked(jti)                       -> 401
         (Redis outage also 401 — fail closed, never default to False)
      e. user row not found (sub -> User)      -> 401
         (admin-deleted user whose token hasn't expired yet)
      f. return user
    """
    # (a) header
    header = request.headers.get("Authorization")
    if not header or not header.lower().startswith("bearer "):
        raise _UNAUTHORIZED
    token = header.split(" ", 1)[1].strip()
    if not token:
        raise _UNAUTHORIZED

    # (b) decode
    try:
        payload = decode_token(token)
    except (TokenExpiredError, TokenInvalidError, TokenError):
        raise _UNAUTHORIZED

    # (c) type
    if payload.get("type") != "access":
        raise _UNAUTHORIZED

    # (d) revocation — fail closed on any Redis error
    jti = payload.get("jti")
    if not jti:
        raise _UNAUTHORIZED
    try:
        if await is_revoked(redis, jti):
            raise _UNAUTHORIZED
    except HTTPException:
        raise
    except Exception as e:  # Redis down / network error
        logger.error("redis revocation check failed: %s", e)
        raise _UNAUTHORIZED from e

    # (e) user still exists
    sub = payload.get("sub")
    if not sub:
        raise _UNAUTHORIZED
    try:
        user_id = UUID(sub)
    except (ValueError, TypeError):
        raise _UNAUTHORIZED
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise _UNAUTHORIZED

    return user


async def get_verified_user(
    user: User = Depends(get_current_user),
) -> User:
    """Require an authenticated user whose email is verified.

    Use on endpoints that demand a verified account (e.g. creating
    projects, running scans). Returns 403 (not 401) — the user IS
    authenticated; they just aren't authorized until they verify.
    """
    if not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="email_not_verified",
        )
    return user
