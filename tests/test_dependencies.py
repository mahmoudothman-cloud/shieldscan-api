"""Tests for app.dependencies — Sub-task 2.3.4, Commit 2."""

from __future__ import annotations

import logging
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from app.dependencies import (
    check_rate_limits,
    get_current_user,
    get_real_ip,
    get_verified_user,
    rate_limit,
)
from app.models.identity import Organization, User
from app.services.auth import (
    create_access_token,
    create_refresh_token,
)
from app.services.rate_limiter import RateLimiter
from app.services.token_revocation import revoke
from tests.conftest import use_org


# ---------------------------------------------------------------- Request helpers


def _make_request(
    *,
    headers: dict[str, str] | None = None,
    client: tuple[str, int] | None = ("192.0.2.1", 40000),
) -> Request:
    """Build a minimal Starlette Request for unit-testing deps."""
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


# ---------------------------------------------------------------- get_real_ip


def test_get_real_ip_falls_back_to_client_host():
    req = _make_request(client=("203.0.113.42", 12345))
    assert get_real_ip(req) == "203.0.113.42"


def test_get_real_ip_prefers_cf_connecting_ip():
    req = _make_request(
        headers={"CF-Connecting-IP": "198.51.100.7"},
        client=("203.0.113.42", 12345),
    )
    assert get_real_ip(req) == "198.51.100.7"


def test_get_real_ip_uses_xff_leftmost_when_no_cf():
    """X-Forwarded-For may be a comma-chain; the leftmost entry is the
    original client."""
    req = _make_request(
        headers={"X-Forwarded-For": "198.51.100.7, 10.0.0.1, 10.0.0.2"},
        client=("10.0.0.2", 12345),
    )
    assert get_real_ip(req) == "198.51.100.7"


def test_get_real_ip_returns_unknown_when_no_client_and_no_headers():
    req = _make_request(client=None)
    assert get_real_ip(req) == "unknown"


# ---------------------------------------------------------------- get_current_user


async def _persist_user(db_session, email="active@test.com") -> User:
    org = Organization(name="Org", slug=f"org-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=email,
        hashed_password="x",
        full_name="Active User",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest.mark.asyncio
async def test_get_current_user_rejects_missing_authorization_header(
    db_session, fake_redis
):
    req = _make_request()
    with pytest.raises(HTTPException) as ei:
        await get_current_user(req, db_session, fake_redis)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_rejects_non_bearer_scheme(
    db_session, fake_redis
):
    req = _make_request(headers={"Authorization": "Basic abc123"})
    with pytest.raises(HTTPException) as ei:
        await get_current_user(req, db_session, fake_redis)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_rejects_empty_bearer_token(
    db_session, fake_redis
):
    req = _make_request(headers={"Authorization": "Bearer "})
    with pytest.raises(HTTPException) as ei:
        await get_current_user(req, db_session, fake_redis)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_rejects_malformed_token(
    db_session, fake_redis
):
    req = _make_request(headers={"Authorization": "Bearer not.a.jwt"})
    with pytest.raises(HTTPException) as ei:
        await get_current_user(req, db_session, fake_redis)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_rejects_refresh_token_on_access_endpoint(
    db_session, fake_redis
):
    """A valid refresh token must NOT authenticate access endpoints —
    the type claim protects against a confused deputy."""
    user = await _persist_user(db_session)
    refresh = create_refresh_token(sub=str(user.id))
    req = _make_request(headers={"Authorization": f"Bearer {refresh}"})
    with pytest.raises(HTTPException) as ei:
        await get_current_user(req, db_session, fake_redis)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_rejects_revoked_jti(
    db_session, fake_redis
):
    import time

    user = await _persist_user(db_session)
    token = create_access_token(sub=str(user.id))
    from jose import jwt as jose_jwt

    payload = jose_jwt.get_unverified_claims(token)
    await revoke(fake_redis, payload["jti"], exp_unix=int(time.time()) + 900)

    req = _make_request(headers={"Authorization": f"Bearer {token}"})
    with pytest.raises(HTTPException) as ei:
        await get_current_user(req, db_session, fake_redis)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_rejects_when_user_deleted(
    db_session, fake_redis
):
    """Sub claim resolves to no user row — returns 401. Covers the
    admin-deleted-user case where a token is still cryptographically
    valid but the user is gone.
    """
    ghost_id = uuid4()
    token = create_access_token(sub=str(ghost_id))
    req = _make_request(headers={"Authorization": f"Bearer {token}"})
    with pytest.raises(HTTPException) as ei:
        await get_current_user(req, db_session, fake_redis)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_returns_user_on_happy_path(
    db_session, fake_redis
):
    user = await _persist_user(db_session)
    token = create_access_token(sub=str(user.id))
    req = _make_request(headers={"Authorization": f"Bearer {token}"})
    got = await get_current_user(req, db_session, fake_redis)
    assert got.id == user.id
    assert got.email == user.email


class _BrokenRedis:
    """Stand-in for a Redis client that raises on every operation.

    fakeredis doesn't model Redis-down (a closed fakeredis client
    silently reopens), so we inject this instead. Only the methods
    ``get_current_user`` actually touches are defined.
    """

    async def exists(self, *_args, **_kwargs):  # pragma: no cover - raises
        raise ConnectionError("simulated redis outage")


@pytest.mark.asyncio
async def test_get_current_user_fails_closed_on_redis_error(
    db_session, caplog
):
    """If the revocation-list check raises (Redis down), the dep MUST
    return 401 — never silently default to 'not revoked'."""
    user = await _persist_user(db_session)
    token = create_access_token(sub=str(user.id))

    req = _make_request(headers={"Authorization": f"Bearer {token}"})
    with caplog.at_level(logging.ERROR, logger="app.dependencies"):
        with pytest.raises(HTTPException) as ei:
            await get_current_user(req, db_session, _BrokenRedis())
    assert ei.value.status_code == 401
    # Ops signal: log at ERROR mentions the redis failure so outages
    # aren't invisibly masked as auth failures.
    assert any("redis" in r.getMessage().lower() for r in caplog.records)


# ---------------------------------------------------------------- get_verified_user


@pytest.mark.asyncio
async def test_get_verified_user_passes_through_when_verified():
    user = User(
        email="v@x.y",
        hashed_password="x",
        full_name="V",
        email_verified=True,
    )
    got = await get_verified_user(user=user)
    assert got is user


@pytest.mark.asyncio
async def test_get_verified_user_rejects_unverified_with_403():
    """403 (not 401): the user IS authenticated, just not authorized."""
    user = User(
        email="v@x.y",
        hashed_password="x",
        full_name="V",
        email_verified=False,
    )
    with pytest.raises(HTTPException) as ei:
        await get_verified_user(user=user)
    assert ei.value.status_code == 403
    assert ei.value.detail == "email_not_verified"


# ---------------------------------------------------------------- rate_limit + check_rate_limits


def _build_rate_limited_app(fake_redis) -> FastAPI:
    """Minimal FastAPI app exercising the rate_limit factory + helper."""
    from app.dependencies import get_rate_limiter
    from app.redis_client import get_redis

    app = FastAPI()

    async def _override_redis():
        yield fake_redis

    app.dependency_overrides[get_redis] = _override_redis

    @app.get(
        "/limited",
        dependencies=[Depends(rate_limit("test_ip", limit=2, window=60))],
    )
    async def limited():
        return {"ok": True}

    @app.post("/multi")
    async def multi(
        limiter: RateLimiter = Depends(get_rate_limiter),
    ):
        await check_rate_limits(
            limiter,
            [("scope_a", "id1", 2, 60)],
        )
        return {"ok": True}

    return app


@pytest_asyncio.fixture
async def rl_client(fake_redis):
    app = _build_rate_limited_app(fake_redis)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_rate_limit_dep_allows_under_limit(rl_client):
    assert (await rl_client.get("/limited")).status_code == 200
    assert (await rl_client.get("/limited")).status_code == 200


@pytest.mark.asyncio
async def test_rate_limit_dep_returns_429_with_retry_after_over_limit(rl_client):
    for _ in range(2):
        await rl_client.get("/limited")
    r = await rl_client.get("/limited")
    assert r.status_code == 429
    assert r.json()["detail"] == "rate_limit_exceeded"
    assert "Retry-After" in r.headers
    # Retry-After must be a positive integer.
    assert int(r.headers["Retry-After"]) > 0


@pytest.mark.asyncio
async def test_check_rate_limits_helper_passes_under_limit(rl_client):
    assert (await rl_client.post("/multi")).status_code == 200
    assert (await rl_client.post("/multi")).status_code == 200


@pytest.mark.asyncio
async def test_check_rate_limits_helper_raises_429(rl_client):
    for _ in range(2):
        await rl_client.post("/multi")
    r = await rl_client.post("/multi")
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "60"


# ---------------------------------------------------------------- client harness smoke


@pytest.mark.asyncio
async def test_client_fixture_reaches_health_endpoint(client):
    """End-to-end smoke: the `client` fixture wires dep overrides and
    talks to app.main:app successfully. Real auth endpoints land in
    Commit 4; for now we just prove the harness works."""
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
