"""FastAPI dependencies for auth-protected endpoints.

Three layers of dependencies:

1. **Infrastructure:** ``get_db``, ``get_redis``, ``get_rate_limiter``.
   Yield per-request handles to the shared backends.

2. **Identity:** ``get_current_user`` (JWT-only), ``get_auth_identity``
   (JWT or API key), ``require_jwt`` (JWT-only, returns full identity).
   All three parse ``Authorization: Bearer <credential>`` and dispatch
   based on credential kind (see ``_detect_credential_kind``).

3. **Rate limiting:** ``rate_limit(scope, limit, window, id_fn=...)``
   factory + ``check_rate_limits`` handler-body helper.

HTTP code discipline (401 vs 403):
  - **401 Unauthorized:** missing, malformed, expired, revoked, or
    invalid-type token; user-deleted-but-token-alive. The *request*
    failed authentication.
  - **403 Forbidden:** authenticated but the caller's state or
    credential-kind forbids the action. Two canonical cases:
      * ``email_not_verified`` on endpoints that require verified email.
      * ``api_key_insufficient_for_operation`` on user-session endpoints
        that reject API-key credentials (logout, refresh, api-key
        mutations — see ADR-012 and the Task 2.4 scope).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import AsyncIterator, Awaitable, Callable, Literal
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import AsyncSessionLocal
from app.db.tenant_context import set_tenant_context
from app.models.identity import APIKey, MembershipRole, User
from app.redis_client import get_redis
from app.services.auth import (
    TokenError,
    TokenExpiredError,
    TokenInvalidError,
    decode_token,
)
from app.services.rate_limiter import RateLimiter
from app.services.token_revocation import get_user_revoked_before, is_revoked

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

    # (a.1) credential-kind gate: get_current_user is JWT-only. API-key
    # credentials arriving here (user-session endpoints like /logout,
    # /refresh, api-key mutations) get a distinct 403 so the client
    # can distinguish "your key is valid but wrong shape for this
    # endpoint" from "your key is bad." See Task 2.4 endpoint policy +
    # ADR-012. This is NOT an auth failure; the credential IS
    # authenticated — it's just not authorized for this operation.
    if _detect_credential_kind(token) == "api_key":
        raise _API_KEY_INSUFFICIENT

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


# ---------------------------------------------------------------- API key auth (Task 2.4 Commit 1)


_API_KEY_INSUFFICIENT = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="api_key_insufficient_for_operation",
)


def _detect_credential_kind(raw: str) -> Literal["api_key", "jwt"]:
    """Positive-match for API keys; everything else is JWT.

    API keys have a hard-pinned prefix (``ss_live_`` / ``ss_test_``)
    per Task 2.2. JWTs are the default fall-through — the subsequent
    JWT decode will catch any actual garbage with a 401.

    Intentionally not a regex — ``startswith`` is zero-allocation,
    obvious to readers, and the prefix is a literal contract (Task 2.2
    `generate_api_key` emits exactly this shape).
    """
    if raw.startswith(("ss_live_", "ss_test_")):
        return "api_key"
    return "jwt"


@dataclass(frozen=True)
class AuthIdentity:
    """Unified auth context returned by :func:`get_auth_identity`.

    ``kind`` discriminates the credential source. For ``"jwt"``,
    ``user`` is populated. For ``"api_key"``, ``api_key`` is populated.
    ``organization_id`` is always populated — it's the tenant the
    caller authenticated as.
    """

    kind: Literal["jwt", "api_key"]
    organization_id: UUID
    user: User | None = None
    api_key: APIKey | None = None
    # Membership role for the JWT path. None for API-key path —
    # API keys are admin-equivalent at creation time (Task 2.4),
    # so role-gated endpoints (Task 3.X PATCH /credentials) treat
    # any authenticated API key as authorized without checking role.
    role: MembershipRole | None = None


# last_used_at update is fire-and-forget (latency-sensitive auth path)
# with a 60-second debounce (write-amplification-sensitive under load).
# See DRIFT-LOG 2026-04-21 fire-and-forget entry.
_API_KEY_LAST_USED_DEBOUNCE = 60  # seconds


async def _update_api_key_last_used(key_id: UUID, when: datetime) -> None:
    """Background UPDATE for api_keys.last_used_at. Runs in its own
    session because the request-scoped session may be closed by the
    time this task fires. Failures are logged but not surfaced — the
    caller's request must have already returned by the time we get
    here, so there's nothing to "fail" anyway.

    NOTE — this is the only broad ``except Exception`` in the request path that
    wraps a DB write AND swallows it. That is safe only because ``api_keys`` is
    outside TENANT_TABLES by ADR-012, so the Phase-3b tenant guard never fires
    here. If ``api_keys`` is ever brought under RLS, this becomes a site that
    silently swallows MissingTenantContextError and must be narrowed first.
    """
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(
                update(APIKey).where(APIKey.id == key_id).values(last_used_at=when)
            )
            await session.commit()
    except Exception as e:
        logger.error("api_key last_used_at update failed for %s: %s", key_id, e)


def _maybe_schedule_last_used_update(
    key: APIKey,
    *,
    scheduler: Callable[[Awaitable[None]], object] = asyncio.create_task,
    now: datetime | None = None,
) -> bool:
    """If the key's last_used_at is stale (>60s) or None, schedule a
    fire-and-forget UPDATE. Returns whether a task was scheduled
    (so tests can assert on the debounce).

    ``scheduler`` is injected for testability — the default is
    ``asyncio.create_task`` (fire-and-forget); tests pass a list's
    ``append`` to capture the coroutine without actually running it.
    """
    _now = now if now is not None else datetime.now(timezone.utc)
    if key.last_used_at is None or (
        _now - key.last_used_at
    ).total_seconds() > _API_KEY_LAST_USED_DEBOUNCE:
        scheduler(_update_api_key_last_used(key.id, _now))
        return True
    return False


async def _authenticate_api_key(
    db: AsyncSession,
    plaintext: str,
) -> APIKey | None:
    """Look up an active API key by SHA-256(plaintext). Returns the row
    or ``None`` (wrong hash OR row exists but ``revoked_at`` set).

    NOTE: the ``revoked_at IS NULL`` filter is load-bearing. Omitting
    it would let revoked keys continue to authenticate — the classic
    "forgot the WHERE clause" failure mode that ADR-012's posture
    makes equivalent to "forgot the RLS policy." Regression test
    pins the behavior.

    On success, also sets ``app.current_org_id`` GUC so subsequent
    queries in the request are tenant-scoped correctly.
    """
    key_hash = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    result = await db.execute(
        select(APIKey).where(
            APIKey.key_hash == key_hash,
            APIKey.revoked_at.is_(None),
        )
    )
    key = result.scalar_one_or_none()
    if key is None:
        return None
    await set_tenant_context(db, key.organization_id)
    _maybe_schedule_last_used_update(key)
    return key


async def get_auth_identity(
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
) -> AuthIdentity:
    """Unified auth entrypoint. Accepts JWT or API key in
    ``Authorization: Bearer <credential>``. Returns an ``AuthIdentity``
    discriminated on ``kind``.

    Use this dep for endpoints that accept either credential (e.g.
    ``GET /auth/me``, ``GET /auth/api-keys``). Use ``get_current_user``
    or ``require_jwt`` for user-session-only endpoints.

    All failure paths collapse to a uniform 401 to prevent enumeration
    of which check failed.
    """
    header = request.headers.get("Authorization")
    if not header or not header.lower().startswith("bearer "):
        raise _UNAUTHORIZED
    raw = header.split(" ", 1)[1].strip()
    if not raw:
        raise _UNAUTHORIZED

    kind = _detect_credential_kind(raw)
    if kind == "api_key":
        key = await _authenticate_api_key(db, raw)
        if key is None:
            raise _UNAUTHORIZED
        return AuthIdentity(
            kind="api_key",
            organization_id=key.organization_id,
            api_key=key,
        )

    # JWT path — re-implemented inline rather than calling
    # get_current_user so we don't re-parse the header and so the 403
    # gate in get_current_user doesn't trip.
    try:
        payload = decode_token(raw)
    except (TokenExpiredError, TokenInvalidError, TokenError):
        raise _UNAUTHORIZED
    if payload.get("type") != "access":
        raise _UNAUTHORIZED
    jti = payload.get("jti")
    if not jti:
        raise _UNAUTHORIZED
    try:
        if await is_revoked(redis, jti):
            raise _UNAUTHORIZED
    except HTTPException:
        raise
    except Exception as e:
        logger.error("redis revocation check failed: %s", e)
        raise _UNAUTHORIZED from e
    sub = payload.get("sub")
    if not sub:
        raise _UNAUTHORIZED

    # User-level revocation (Task 2.X, ADR-011 deferred section shipped).
    # Compare the token's `iat` claim against `user_revoked_before:{sub}`
    # so password-change / admin-force-logout invalidate EVERY token
    # issued before that moment, without needing to enumerate jtis.
    #
    # Short-circuit (Option C): get_user_revoked_before returns None for
    # users who have never had a user-level revocation. That's the vast
    # majority of requests — one Redis GET on a missing key, O(1), done.
    iat = payload.get("iat")
    if iat is None:
        # Defensive: every token minted post-commit 4d32fcc carries iat.
        # A missing iat means either a pre-4d32fcc test/dev token (which
        # expires in 15 min anyway) or a token forged by an actor who
        # somehow signed it without the standard factory. Log LOUDLY so
        # production monitoring alerts — this should never fire in prod.
        logger.error(
            "Token missing iat claim for sub=%s; user-level revocation "
            "bypassed. Should not occur post-commit 4d32fcc.",
            sub,
        )
    else:
        try:
            revoked_before = await get_user_revoked_before(redis, sub)
        except Exception as e:
            logger.error("redis user_revoked_before check failed: %s", e)
            raise _UNAUTHORIZED from e
        if revoked_before is not None and iat < revoked_before:
            raise _UNAUTHORIZED  # token invalidated by user-level revocation

    try:
        user_id = UUID(sub)
    except (ValueError, TypeError):
        raise _UNAUTHORIZED
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise _UNAUTHORIZED

    # Resolve the user's primary org for tenant context. A user can
    # belong to multiple orgs; current behavior uses their first
    # membership. Multi-org UX is a later M-task.
    from app.models.identity import Membership

    result = await db.execute(
        select(Membership.organization_id, Membership.role)
        .where(Membership.user_id == user.id)
        .limit(1)
    )
    row = result.first()
    if row is None:
        # A user with zero memberships can't authenticate against any
        # tenant-scoped endpoint. Treat as 401 (same as user-deleted).
        raise _UNAUTHORIZED
    org_id, role = row
    await set_tenant_context(db, org_id)

    return AuthIdentity(kind="jwt", organization_id=org_id, user=user, role=role)


async def require_jwt(
    identity: AuthIdentity = Depends(get_auth_identity),
) -> AuthIdentity:
    """Like ``get_auth_identity`` but rejects API-key credentials with
    403 ``api_key_insufficient_for_operation``. Use on user-session
    operations where an API key is not semantically valid (logout,
    refresh, api-key mutations).
    """
    if identity.kind != "jwt":
        raise _API_KEY_INSUFFICIENT
    return identity


# ---------------------------------------------------------------- tenant scoping (Task 3.1)


_NOT_FOUND = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail="not_found",
)


def require_org_membership(jwt_only: bool = False) -> Callable:
    """Factory: return a FastAPI dep that validates the path's
    ``org_id`` against the caller's authenticated org and SETs the
    GUC for RLS-protected queries.

    Cross-tenant attempts collapse to **404 not_found** (NOT 403)
    so we don't leak existence of orgs/projects in other tenants
    (mirrors ADR-012's app-layer scoping pattern + Task 2.4's
    cross-tenant DELETE policy).

    ``jwt_only=True`` additionally rejects API-key credentials with
    403 ``api_key_insufficient_for_operation``. Use on mutation
    endpoints that require a human in the loop (project DELETE).
    """

    async def _dep(
        org_id: UUID,
        identity: AuthIdentity = Depends(get_auth_identity),
        db: AsyncSession = Depends(get_db),
    ) -> AuthIdentity:
        if jwt_only and identity.kind != "jwt":
            raise _API_KEY_INSUFFICIENT
        if identity.organization_id != org_id:
            raise _NOT_FOUND
        # Re-set GUC explicitly. get_auth_identity already set it for
        # the caller's primary org, but doing it here makes the pattern
        # uniform across endpoints and survives multi-org future work
        # where the path's org_id might not match the JWT's "primary".
        await set_tenant_context(db, org_id)
        return identity

    return _dep
