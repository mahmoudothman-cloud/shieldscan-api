"""Tests for user-level revocation (Task 2.X Commit 1).

Manually sets ``user_revoked_before:{user_id}`` via Redis and verifies
the auth path trips. The ``POST /auth/password/change`` endpoint that
consumes this mechanism lands in Commit 2; this commit ships the
infrastructure + the /auth/refresh gap fix.
"""

from __future__ import annotations

import logging
import time
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.dependencies import AuthIdentity, get_auth_identity, get_current_user
from app.models.identity import Membership, MembershipRole, Organization, User
from app.services.auth import (
    create_access_token,
    create_refresh_token,
    hash_password,
)
from app.services.token_revocation import (
    USER_REVOKED_BEFORE_PREFIX,
    get_user_revoked_before,
    set_user_revoked_before,
)
from tests.conftest import use_org


def _make_request(
    *,
    headers: dict[str, str] | None = None,
    client: tuple[str, int] | None = ("127.0.0.1", 40000),
) -> Request:
    raw_headers = [
        (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": raw_headers,
        "client": client,
        "server": ("test", 80),
        "scheme": "http",
    }
    return Request(scope)


async def _make_user(db_session) -> User:
    org = Organization(name="Org U", slug=f"orgu-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"u-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("Password-123"),
        full_name="U User",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(
            user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN
        )
    )
    await db_session.commit()
    return user


# ---------------------------------------------------------------- helper primitive


@pytest.mark.asyncio
async def test_get_user_revoked_before_returns_none_when_unset(fake_redis):
    assert await get_user_revoked_before(fake_redis, uuid4()) is None


@pytest.mark.asyncio
async def test_get_user_revoked_before_roundtrip(fake_redis):
    user_id = uuid4()
    ts = int(time.time())
    await set_user_revoked_before(fake_redis, user_id, ts, ttl_seconds=3600)
    got = await get_user_revoked_before(fake_redis, user_id)
    assert got == ts
    # Key shape matches the contract.
    keys = [k async for k in fake_redis.scan_iter(
        match=f"{USER_REVOKED_BEFORE_PREFIX}:{user_id}"
    )]
    assert len(keys) == 1


# ---------------------------------------------------------------- get_auth_identity JWT path


@pytest.mark.asyncio
async def test_jwt_auth_passes_when_no_user_revocation(
    db_session, fake_redis
):
    """Control case: user never had a revocation applied."""
    user = await _make_user(db_session)
    token = create_access_token(sub=str(user.id))
    req = _make_request(headers={"Authorization": f"Bearer {token}"})
    identity = await get_auth_identity(req, db_session, fake_redis)
    assert identity.kind == "jwt"
    assert identity.user.id == user.id


@pytest.mark.asyncio
async def test_jwt_auth_rejects_token_predating_user_revocation(
    db_session, fake_redis
):
    """Core user-level revocation: a token with iat < revoked_before
    is rejected with 401."""
    user = await _make_user(db_session)
    # Mint a token, then simulate a password change AFTER it.
    token = create_access_token(sub=str(user.id))
    future_ts = int(time.time()) + 300  # 5 min in the future
    await set_user_revoked_before(
        fake_redis, user.id, future_ts, ttl_seconds=86400
    )

    req = _make_request(headers={"Authorization": f"Bearer {token}"})
    with pytest.raises(HTTPException) as ei:
        await get_auth_identity(req, db_session, fake_redis)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_jwt_auth_accepts_token_issued_after_revocation(
    db_session, fake_redis
):
    """Tokens minted AFTER the revocation timestamp pass normally —
    otherwise password change would lock users out of their new
    tokens too."""
    user = await _make_user(db_session)
    past_ts = int(time.time()) - 300  # 5 min in the past
    await set_user_revoked_before(
        fake_redis, user.id, past_ts, ttl_seconds=86400
    )
    # Mint token NOW — its iat is > past_ts.
    token = create_access_token(sub=str(user.id))

    req = _make_request(headers={"Authorization": f"Bearer {token}"})
    identity = await get_auth_identity(req, db_session, fake_redis)
    assert identity.kind == "jwt"


@pytest.mark.asyncio
async def test_jwt_auth_logs_error_when_iat_missing_but_passes(
    db_session, fake_redis, caplog
):
    """Defensive guard: a token without `iat` should bypass the
    check (tokens pre-commit 4d32fcc are the only realistic case
    and they expire in 15min anyway) BUT log at ERROR so production
    monitoring alerts if this ever fires.
    """
    user = await _make_user(db_session)
    # Manually construct a token without iat by re-signing the payload
    # with no iat claim.
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4 as _uuid

    from jose import jwt as jose_jwt

    from app.config import settings

    payload = {
        "sub": str(user.id),
        # NO iat intentionally
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "type": "access",
        "jti": str(_uuid()),
    }
    token = jose_jwt.encode(
        payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )

    req = _make_request(headers={"Authorization": f"Bearer {token}"})
    with caplog.at_level(logging.ERROR, logger="app.dependencies"):
        identity = await get_auth_identity(req, db_session, fake_redis)
    assert identity.kind == "jwt"
    assert any(
        "iat" in rec.getMessage() and str(user.id) in rec.getMessage()
        for rec in caplog.records
    ), f"expected loud iat-missing log, got: {[r.getMessage() for r in caplog.records]}"


@pytest.mark.asyncio
async def test_jwt_auth_fails_closed_on_redis_error(db_session):
    """Redis failure during user-level check MUST 401 — never default
    to 'not revoked' (same fail-closed posture as jti revocation)."""
    user = await _make_user(db_session)
    token = create_access_token(sub=str(user.id))

    class _BrokenRedis:
        async def exists(self, *_a, **_k):
            return 0  # jti revocation check passes

        async def get(self, *_a, **_k):
            raise ConnectionError("simulated redis outage")

    req = _make_request(headers={"Authorization": f"Bearer {token}"})
    with pytest.raises(HTTPException) as ei:
        await get_auth_identity(req, db_session, _BrokenRedis())
    assert ei.value.status_code == 401


# ---------------------------------------------------------------- /auth/refresh gap fix


@pytest.mark.asyncio
async def test_refresh_rejects_token_predating_user_revocation(
    client, db_session, fake_redis
):
    """The §E gap fix: pre-password-change refresh token must be
    rejected at /auth/refresh too, not just at get_auth_identity.
    Without the new check, a pre-change refresh would mint fresh
    post-change tokens — effectively undoing the password change.
    """
    user = await _make_user(db_session)
    refresh = create_refresh_token(sub=str(user.id))
    # Now simulate a password change AFTER this refresh was issued.
    future_ts = int(time.time()) + 300
    await set_user_revoked_before(
        fake_redis, user.id, future_ts, ttl_seconds=86400
    )

    r = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh}
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_refresh_accepts_token_issued_after_revocation(
    client, db_session, fake_redis
):
    """Positive regression: a refresh token issued AFTER the password
    change works normally. The check compares iat vs revoked_before;
    newer iats pass."""
    user = await _make_user(db_session)
    past_ts = int(time.time()) - 300
    await set_user_revoked_before(
        fake_redis, user.id, past_ts, ttl_seconds=86400
    )
    # Mint AFTER the revocation.
    refresh = create_refresh_token(sub=str(user.id))

    r = await client.post(
        "/v1/auth/refresh", json={"refresh_token": refresh}
    )
    assert r.status_code == 200
