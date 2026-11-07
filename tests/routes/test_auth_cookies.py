"""Browser session cookie for the dashboard (CONSTITUTION §14.2).

1. login sets ``shieldscan_refresh`` — httpOnly, path /v1/auth, SameSite=Lax,
   Secure outside development — carrying the refresh token from the body
2. /refresh with no body and only the cookie rotates tokens and re-sets
   the cookie; the old jti is revoked
3. /refresh with neither body nor cookie → 401
4. body token wins over the cookie when both are present
5. logout with cookie only revokes it and clears the cookie
"""

from __future__ import annotations

import pytest
from jose import jwt as jose_jwt

from app.config import settings
from app.routes.auth import REFRESH_COOKIE
from app.services.auth import create_access_token, create_refresh_token
from app.services.token_revocation import REVOKED_JTI_PREFIX


def _cookie_header(r) -> str:
    return next(h for h in r.headers.get_list("set-cookie") if h.startswith(REFRESH_COOKIE))


@pytest.mark.asyncio
async def test_login_sets_httponly_refresh_cookie(client, existing_user):
    user, password = existing_user
    user.email_verified = True
    r = await client.post("/v1/auth/login", json={"email": user.email, "password": password})
    assert r.status_code == 200, r.text
    raw = _cookie_header(r)
    assert "HttpOnly" in raw
    assert "Path=/v1/auth" in raw
    assert "samesite=lax" in raw.lower()
    assert f"Max-Age={settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 86400}" in raw
    # development: no Secure flag so http://localhost works
    assert ("Secure" in raw) == (settings.ENVIRONMENT != "development")
    # Cookie value is the same refresh token the body carries.
    assert r.cookies[REFRESH_COOKIE] == r.json()["refresh_token"]


@pytest.mark.asyncio
async def test_refresh_from_cookie_only(client, existing_user, fake_redis):
    user, _ = existing_user
    refresh = create_refresh_token(sub=str(user.id))
    client.cookies.set(REFRESH_COOKIE, refresh, path="/v1/auth")
    r = await client.post("/v1/auth/refresh")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"] and body["refresh_token"] != refresh
    # Cookie rotated to the new refresh token.
    assert r.cookies[REFRESH_COOKIE] == body["refresh_token"]
    old_jti = jose_jwt.get_unverified_claims(refresh)["jti"]
    assert await fake_redis.exists(f"{REVOKED_JTI_PREFIX}:{old_jti}")
    client.cookies.clear()


@pytest.mark.asyncio
async def test_refresh_without_any_token_is_401(client):
    client.cookies.clear()
    r = await client.post("/v1/auth/refresh")
    assert r.status_code == 401
    r = await client.post("/v1/auth/refresh", json={})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_refresh_body_wins_over_cookie(client, existing_user, fake_redis):
    user, _ = existing_user
    body_token = create_refresh_token(sub=str(user.id))
    cookie_token = create_refresh_token(sub=str(user.id))
    client.cookies.set(REFRESH_COOKIE, cookie_token, path="/v1/auth")
    r = await client.post("/v1/auth/refresh", json={"refresh_token": body_token})
    assert r.status_code == 200
    body_jti = jose_jwt.get_unverified_claims(body_token)["jti"]
    cookie_jti = jose_jwt.get_unverified_claims(cookie_token)["jti"]
    assert await fake_redis.exists(f"{REVOKED_JTI_PREFIX}:{body_jti}")
    assert not await fake_redis.exists(f"{REVOKED_JTI_PREFIX}:{cookie_jti}")
    client.cookies.clear()


@pytest.mark.asyncio
async def test_logout_from_cookie_revokes_and_clears(client, existing_user, fake_redis):
    user, _ = existing_user
    refresh = create_refresh_token(sub=str(user.id))
    access = create_access_token(sub=str(user.id))
    client.cookies.set(REFRESH_COOKIE, refresh, path="/v1/auth")
    r = await client.post("/v1/auth/logout", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 204, r.text
    jti = jose_jwt.get_unverified_claims(refresh)["jti"]
    assert await fake_redis.exists(f"{REVOKED_JTI_PREFIX}:{jti}")
    raw = _cookie_header(r)
    assert 'shieldscan_refresh=""' in raw or "shieldscan_refresh=;" in raw
    assert "Max-Age=0" in raw or "expires=" in raw.lower()
    client.cookies.clear()
