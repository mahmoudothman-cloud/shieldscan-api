"""Authentication endpoints (Sub-task 2.3.4, Commit 4).

Five endpoints under ``/v1/auth``::

    POST /v1/auth/register   -> TokenResponse 201
    POST /v1/auth/login      -> TokenResponse 200
    POST /v1/auth/refresh    -> TokenResponse 200
    POST /v1/auth/logout     -> 204 (No Content)
    GET  /v1/auth/me         -> UserResponse 200

Design pins (see ADR-011 + DRIFT-LOG 2026-04-21):
  - **No user enumeration** — register duplicate-email, login
    wrong-password / nonexistent / unverified all return the same
    generic body.
  - **Timing-stable login** — when the looked-up user is ``None`` we
    still run ``verify_password(candidate, _DUMMY_HASH)`` so the
    nonexistent-email path isn't noticeably faster than the
    wrong-password path.
  - **Refresh rotation revokes BEFORE it mints** — if the mint fails
    after the revoke, the worst case is the client re-logs-in; if
    we minted before revoking and then lost the revoke, the client
    would briefly hold two valid refresh tokens (security issue).
  - **Reuse detection on /refresh** — presenting an already-revoked
    refresh token is a compromise signal. We audit
    ``auth.token.revoked`` with ``reason="reuse_detected"`` and
    return 401. Full user-level revocation (all tokens for that
    user) is deferred to the password-change endpoint that will
    add the ``user_revoked_before`` machinery.
  - **/logout revokes refresh only, not access** — access token
    expires in 15 minutes naturally. Clients needing immediate
    full invalidation use password-change (later M2 task).
"""

from __future__ import annotations

import hashlib
import logging
from uuid import UUID

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import (
    AuthIdentity,
    check_rate_limits,
    get_auth_identity,
    get_current_user,
    get_db,
    get_rate_limiter,
    get_real_ip,
    rate_limit,
)
from app.models.identity import User
from app.redis_client import get_redis
from app.schemas.api_keys import (
    APIKeySummary,
    AuthIdentityResponse,
    OrganizationSummary,
)
from app.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    ResendVerificationRequest,
    TokenResponse,
    UserResponse,
    VerifyEmailRequest,
)
from app.services.audit import AuthAction, audit
from app.services.auth import (
    TokenError,
    TokenExpiredError,
    TokenInvalidError,
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)
from app.services.email import EmailService, get_email_service
from app.services.email_verification import (
    EMAIL_VERIFY_PREFIX,
    issue_email_verification_token,
)
from app.services.identity import (
    EmailAlreadyRegistered,
    SlugGenerationFailed,
    register_identity,
)
from app.services.rate_limiter import RateLimiter
from app.services.token_revocation import (
    get_user_revoked_before,
    is_revoked,
    revoke,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


# Constant-time timing dummy — used on the login "user not found" path
# so that decode+bcrypt time stays stable regardless of whether the
# user exists. The hash of the string "dummy-for-timing" is irrelevant
# (no password ever matches), we just need bcrypt to do its work.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-for-timing", bcrypt.gensalt(rounds=12)).decode()


# Generic 401 body — identical shape across every auth failure path
# on this router so a client cannot infer WHICH check failed.
_UNAUTH = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="unauthorized",
    headers={"WWW-Authenticate": "Bearer"},
)


def _tokens_for(user: User) -> TokenResponse:
    return TokenResponse(
        access_token=create_access_token(sub=str(user.id)),
        refresh_token=create_refresh_token(sub=str(user.id)),
        user=UserResponse.model_validate(user),
    )


# ---------------------------------------------------------------- register


@router.post(
    "/register",
    status_code=201,
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit("register_ip", limit=3, window=3600))],
)
async def register(
    req: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
    email_service: EmailService = Depends(get_email_service),
):
    ip = get_real_ip(request)
    ua = request.headers.get("User-Agent")
    try:
        user = await register_identity(
            db,
            redis,
            email_service,
            email=req.email,
            password=req.password,
            full_name=req.full_name,
            organization_name=req.organization_name,
            ip_address=ip,
            user_agent=ua,
        )
    except EmailAlreadyRegistered:
        # Generic 400 — DO NOT echo "email already registered" (that
        # would be user enumeration per M2 envelope 6a).
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="registration_failed",
        )
    except SlugGenerationFailed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="registration_failed",
        )
    except ValueError:
        # Password > 72 bytes — shouldn't hit here (schema already
        # validates) but the orchestrator is defensive.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="registration_failed",
        )

    return _tokens_for(user)


# ---------------------------------------------------------------- login


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit("login_ip", limit=5, window=900))],
)
async def login(
    req: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    limiter: RateLimiter = Depends(get_rate_limiter),
):
    ip = get_real_ip(request)
    ua = request.headers.get("User-Agent")

    # Email-scoped rate limit — second layer beyond the IP dep.
    await check_rate_limits(
        limiter,
        [("login_email", req.email, 10, 3600)],
    )

    result = await db.execute(select(User).where(User.email == req.email))
    user = result.scalar_one_or_none()

    # Timing-stable: run verify_password even for nonexistent users.
    # Use a constant dummy hash; discard the result.
    if user is None:
        verify_password(req.password, _DUMMY_HASH)
        failure_reason = "no_such_user"
        actor_id = None
        resource_id = None
        org_id = None
    else:
        password_ok = verify_password(req.password, user.hashed_password)
        if not password_ok:
            failure_reason = "wrong_password"
        elif not user.email_verified:
            failure_reason = "unverified_email"
        else:
            failure_reason = None
        actor_id = user.id
        resource_id = user.id
        # Best-effort: grab an org for audit tenancy. Login attempts
        # pre-memberhsip (unlikely but possible) skip audit.
        org_id = await _first_org_id_for(db, user.id)

    if failure_reason is not None:
        # Audit the failure when we have a tenant context.
        if org_id is not None:
            await db.execute(
                select(User).where(User.id == user.id)  # no-op to prime session
            ) if user else None
            await audit(
                db,
                organization_id=org_id,
                actor_id=actor_id,
                action=AuthAction.LOGIN_FAILURE,
                resource_type="user",
                resource_id=resource_id,
                ip_address=ip,
                user_agent=ua,
                details={"reason": failure_reason},
            )
            await db.commit()
        raise _UNAUTH

    # Success path — audit + tokens.
    await audit(
        db,
        organization_id=org_id,
        actor_id=user.id,
        action=AuthAction.LOGIN_SUCCESS,
        resource_type="user",
        resource_id=user.id,
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return _tokens_for(user)


async def _first_org_id_for(db: AsyncSession, user_id: UUID) -> UUID | None:
    from app.models.identity import Membership

    result = await db.execute(
        select(Membership.organization_id).where(Membership.user_id == user_id).limit(1)
    )
    row = result.scalar_one_or_none()
    if row is not None:
        # Set the GUC so audit's WITH CHECK succeeds.
        from sqlalchemy import text

        await db.execute(text(f"SET app.current_org_id = '{row}'"))
    return row


# ---------------------------------------------------------------- refresh


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    req: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    ip = get_real_ip(request)
    ua = request.headers.get("User-Agent")

    # 1. decode
    try:
        payload = decode_token(req.refresh_token)
    except (TokenExpiredError, TokenInvalidError, TokenError):
        raise _UNAUTH

    # 2. must be a refresh token, not an access
    if payload.get("type") != "refresh":
        raise _UNAUTH

    jti = payload.get("jti")
    sub = payload.get("sub")
    exp = payload.get("exp")
    if not jti or not sub or not exp:
        raise _UNAUTH

    # 3. reuse detection — if already revoked, someone is replaying.
    #    Log compromise signal + reject. Full user-level revocation
    #    on reuse is deferred to the password-change task (ADR-011).
    try:
        already_revoked = await is_revoked(redis, jti)
    except Exception as e:
        logger.error("redis revocation check failed on /refresh: %s", e)
        raise _UNAUTH from e

    if already_revoked:
        # Best-effort compromise audit. Requires a tenant context —
        # look up user for actor/org.
        try:
            user_id = UUID(sub)
        except (ValueError, TypeError):
            raise _UNAUTH
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if user is not None:
            org_id = await _first_org_id_for(db, user.id)
            if org_id is not None:
                await audit(
                    db,
                    organization_id=org_id,
                    actor_id=user.id,
                    action=AuthAction.TOKEN_REVOKED,
                    resource_type="refresh_token",
                    resource_id=None,
                    ip_address=ip,
                    user_agent=ua,
                    details={"reason": "reuse_detected", "token_jti": jti},
                )
                await db.commit()
        raise _UNAUTH

    # 3b. User-level revocation check (Task 2.X gap fix — ADR-011).
    # Without this, a pre-password-change refresh token whose jti
    # isn't in the targeted revocation list would still be accepted
    # here and mint a fresh post-change pair. See DRIFT-LOG 2026-04-23.
    iat = payload.get("iat")
    if iat is None:
        logger.error(
            "Refresh token missing iat claim for sub=%s; user-level "
            "revocation bypassed. Should not occur post-commit 4d32fcc.",
            sub,
        )
    else:
        try:
            revoked_before = await get_user_revoked_before(redis, sub)
        except Exception as e:
            logger.error(
                "redis user_revoked_before check failed on /refresh: %s", e
            )
            raise _UNAUTH from e
        if revoked_before is not None and iat < revoked_before:
            raise _UNAUTH  # token invalidated by password change

    # 4. fetch user (handles admin-deleted-but-token-alive)
    try:
        user_id = UUID(sub)
    except (ValueError, TypeError):
        raise _UNAUTH
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise _UNAUTH

    # 5. REVOKE OLD BEFORE MINT NEW (fail-closed ordering — ADR-011).
    try:
        await revoke(redis, jti, exp_unix=int(exp))
    except Exception as e:
        logger.error("redis revoke failed on /refresh: %s", e)
        raise _UNAUTH from e

    # 6. mint + audit
    org_id = await _first_org_id_for(db, user.id)
    if org_id is not None:
        await audit(
            db,
            organization_id=org_id,
            actor_id=user.id,
            action=AuthAction.TOKEN_REFRESHED,
            resource_type="user",
            resource_id=user.id,
            ip_address=ip,
            user_agent=ua,
        )
        await db.commit()

    return _tokens_for(user)


# ---------------------------------------------------------------- logout


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    req: LogoutRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
    current: User = Depends(get_current_user),
):
    """Revoke the REFRESH token jti only. Access tokens are short-lived
    (15 min) and expire naturally. Clients needing immediate
    full-session invalidation use the (future) password-change
    endpoint.
    """
    ip = get_real_ip(request)
    ua = request.headers.get("User-Agent")

    # Decode body refresh token; on failure, logout is idempotent-ish —
    # we still 204 the client. Revocation only runs if the token was
    # valid+parsable.
    try:
        payload = decode_token(req.refresh_token)
        if payload.get("type") == "refresh" and payload.get("jti") and payload.get("exp"):
            try:
                await revoke(redis, payload["jti"], exp_unix=int(payload["exp"]))
            except Exception as e:
                logger.error("redis revoke failed on /logout: %s", e)
                # Fail loud — the client should retry until logout sticks.
                raise HTTPException(status_code=503, detail="revocation_unavailable")
    except (TokenExpiredError, TokenInvalidError, TokenError):
        pass  # invalid refresh token: nothing to revoke

    org_id = await _first_org_id_for(db, current.id)
    if org_id is not None:
        await audit(
            db,
            organization_id=org_id,
            actor_id=current.id,
            action=AuthAction.LOGOUT,
            resource_type="user",
            resource_id=current.id,
            ip_address=ip,
            user_agent=ua,
        )
        await db.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------- me


@router.get("/me", response_model=AuthIdentityResponse)
async def me(
    identity: AuthIdentity = Depends(get_auth_identity),
    db: AsyncSession = Depends(get_db),
) -> AuthIdentityResponse:
    """Dual-credential identity endpoint. Returns a discriminated-union
    shape — clients branch on ``kind``:
      - ``"jwt"``:    ``user`` populated, ``api_key`` null
      - ``"api_key"``: ``api_key`` populated, ``user`` null

    BREAKING CHANGE vs Task 2.3 shape (flat UserResponse). Intentional
    pre-launch reshape — no external clients yet. See DRIFT-LOG
    2026-04-21 entry on /auth/me contract change (Task 2.4 Commit 2).
    """
    # Load the org for the embedded summary.
    from app.models.identity import Organization

    org_result = await db.execute(
        select(Organization).where(Organization.id == identity.organization_id)
    )
    org = org_result.scalar_one()

    return AuthIdentityResponse(
        kind=identity.kind,
        organization=OrganizationSummary.model_validate(org),
        user=(
            UserResponse.model_validate(identity.user)
            if identity.user is not None
            else None
        ),
        api_key=(
            APIKeySummary.model_validate(identity.api_key)
            if identity.api_key is not None
            else None
        ),
    )


# ---------------------------------------------------------------- verify-email (Task 2.5)


_INVALID_TOKEN = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="invalid_or_expired_token",
)

_RESEND_OK = {"detail": "verification_email_sent_if_account_exists"}


@router.post("/verify-email")
async def verify_email(
    body: VerifyEmailRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
) -> dict:
    """Consume an email-verification token.

    **Unauthenticated** — the token IS the credential. All failure
    modes (nonexistent, expired-via-TTL, user-deleted, previously-used)
    collapse to an identical 400 body per no-enumeration policy. See
    DRIFT-LOG 2026-04-21 email-verification policy notes.

    Single-use enforcement: ``GETDEL`` is atomic — the key is removed
    as part of the read, preventing a race where two concurrent
    replays both see the token and both succeed.
    """
    token_hash = hashlib.sha256(body.token.encode("utf-8")).hexdigest()
    key = f"{EMAIL_VERIFY_PREFIX}:{token_hash}"

    # GETDEL: atomic read-and-delete. If the key is missing (expired,
    # nonexistent, already consumed), returns None.
    try:
        user_id_raw = await redis.getdel(key)
    except Exception as e:
        logger.error("redis getdel failed on /verify-email: %s", e)
        raise _INVALID_TOKEN from e

    if user_id_raw is None:
        raise _INVALID_TOKEN

    try:
        user_id = UUID(user_id_raw)
    except (ValueError, TypeError):
        # Stored value was malformed — shouldn't happen, but don't
        # confirm anything to the caller.
        raise _INVALID_TOKEN

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        # User deleted after token issuance. Token is already gone
        # (GETDEL consumed it); nothing more to do.
        raise _INVALID_TOKEN

    # Idempotent: if already verified, skip the UPDATE + audit — we
    # don't log no-op events (per Task 2.5 design decision #6).
    if not user.email_verified:
        user.email_verified = True
        org_id = await _first_org_id_for(db, user.id)
        if org_id is not None:
            await audit(
                db,
                organization_id=org_id,
                actor_id=user.id,
                action=AuthAction.EMAIL_VERIFIED,
                resource_type="user",
                resource_id=user.id,
                ip_address=get_real_ip(request),
                user_agent=request.headers.get("User-Agent"),
                details={"method": "email"},
            )
        await db.commit()

    return {"email_verified": True}


# ---------------------------------------------------------------- resend-verification (Task 2.5)


@router.post("/resend-verification")
async def resend_verification(
    body: ResendVerificationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
    email_service: EmailService = Depends(get_email_service),
    limiter: RateLimiter = Depends(get_rate_limiter),
) -> dict:
    """Re-issue a verification email.

    **Unauthenticated** — the caller can't log in until verified, so
    gating resend on login would create a lockout. Every outcome
    (account doesn't exist, already verified, rate-limited,
    successfully resent) returns the same 200 body per no-enumeration
    policy.

    Rate limit runs FIRST, independent of whether the account exists
    (see DRIFT-LOG entry: otherwise the limiter's trip signal is an
    existence oracle).
    """
    # Normalized email — already lowercased/stripped by the schema
    # validator via normalize_email().
    email = body.email

    # Rate limit BEFORE any DB lookup — runs for nonexistent emails
    # too, so 429 behavior doesn't differ by existence. On denial we
    # silently drop and return the generic 200 (no 429 leakage).
    result = await limiter.check(
        "resend_verification_email", email, limit=3, window_seconds=3600
    )
    if not result.allowed:
        return _RESEND_OK

    # Best-effort resend. Every branch below returns the same body.
    user_row = await db.execute(select(User).where(User.email == email))
    user = user_row.scalar_one_or_none()

    if user is not None and not user.email_verified:
        # Issue a fresh token (old one still exists in Redis if the
        # user had requested before; both remain valid until TTL —
        # user may click either link). This is intentional: old links
        # in older emails shouldn't break.
        token_plaintext = await issue_email_verification_token(redis, user.id)
        await email_service.send(
            to=user.email,
            subject="Verify your ShieldScan email",
            body=(
                f"Hi {user.full_name},\n\n"
                f"Click to verify your email: "
                f"https://app.shieldscan.io/verify-email?token={token_plaintext}\n\n"
                f"Link expires in 24 hours."
            ),
            template="verify_email",
        )

        org_id = await _first_org_id_for(db, user.id)
        if org_id is not None:
            await audit(
                db,
                organization_id=org_id,
                actor_id=user.id,
                action=AuthAction.EMAIL_VERIFICATION_SENT,
                resource_type="user",
                resource_id=user.id,
                ip_address=get_real_ip(request),
                user_agent=request.headers.get("User-Agent"),
                details={"method": "email"},
            )
            await db.commit()

    return _RESEND_OK
