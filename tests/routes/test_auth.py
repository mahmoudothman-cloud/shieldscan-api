"""End-to-end tests for /v1/auth/* endpoints — Sub-task 2.3.4, Commit 4.

Uses the `client` fixture (httpx.AsyncClient over ASGITransport) with
dep overrides for get_db / get_redis / get_email_service installed in
conftest.py. State is shared with the `db_session`, `fake_redis`, and
`email_service_stub` fixtures so we can assert on both sides of a
request (DB rows, outbox, Redis keys).
"""

from __future__ import annotations

import time
from uuid import uuid4

import pytest
from jose import jwt as jose_jwt
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.identity import Membership, Organization, User
from app.services.auth import (
    create_access_token,
    create_refresh_token,
)
from app.services.token_revocation import REVOKED_JTI_PREFIX, revoke


def _register_payload(
    *,
    email="new@test.com",
    password="Secure-Pass-123",
    name="New User",
    org="New Co",
):
    return {
        "email": email,
        "password": password,
        "full_name": name,
        "organization_name": org,
    }


def _with_ip(ip: str) -> dict[str, str]:
    """Force get_real_ip to return `ip` by setting CF-Connecting-IP."""
    return {"CF-Connecting-IP": ip}


# =============================================================== register


@pytest.mark.asyncio
async def test_register_happy_path(client, db_session, email_service_stub):
    r = await client.post(
        "/v1/auth/register",
        json=_register_payload(email="alice@t.co", org="Alice Co"),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 900
    assert body["user"]["email"] == "alice@t.co"
    assert body["user"]["email_verified"] is False
    assert "password" not in body["user"]
    assert "hashed_password" not in body["user"]

    # Side-effects: user, org, membership, email, audit row.
    users = (await db_session.execute(select(User))).scalars().all()
    assert len(users) == 1 and users[0].email == "alice@t.co"
    orgs = (await db_session.execute(select(Organization))).scalars().all()
    assert len(orgs) == 1 and orgs[0].slug == "alice-co"
    ms = (await db_session.execute(select(Membership))).scalars().all()
    assert len(ms) == 1
    assert len(email_service_stub.outbox) == 1
    assert email_service_stub.outbox[0].to == "alice@t.co"

    audits = (await db_session.execute(select(AuditLog))).scalars().all()
    actions = {a.action for a in audits}
    assert "user.registered" in actions
    assert "auth.email.verification_sent" in actions


@pytest.mark.asyncio
async def test_register_duplicate_email_returns_generic_400(client):
    await client.post("/v1/auth/register", json=_register_payload(email="dup@t.co"))
    r = await client.post(
        "/v1/auth/register",
        json=_register_payload(email="dup@t.co", org="Other Co"),
        headers=_with_ip("203.0.113.99"),  # different IP so not rate-limited
    )
    assert r.status_code == 400
    # Generic body — must NOT say "email already registered".
    assert r.json()["detail"] == "registration_failed"


@pytest.mark.asyncio
async def test_register_rate_limited_after_three_from_same_ip(client):
    ip = "198.51.100.42"
    for i in range(3):
        r = await client.post(
            "/v1/auth/register",
            json=_register_payload(email=f"u{i}@t.co", org=f"Co {i}"),
            headers=_with_ip(ip),
        )
        assert r.status_code == 201, f"attempt {i} failed: {r.text}"
    r = await client.post(
        "/v1/auth/register",
        json=_register_payload(email="u4@t.co", org="Co 4"),
        headers=_with_ip(ip),
    )
    assert r.status_code == 429
    assert r.json()["detail"] == "rate_limit_exceeded"
    assert "Retry-After" in r.headers


@pytest.mark.asyncio
async def test_register_rejects_sqli_email(client, db_session):
    """Pydantic EmailStr rejects malformed emails at the 422 boundary;
    no SQL ever reaches the DB. Regression guard — if someone swaps
    EmailStr for `str`, this test breaks."""
    r = await client.post(
        "/v1/auth/register",
        json=_register_payload(email="x'; DROP TABLE users;--@y.com"),
    )
    assert r.status_code == 422
    # users table still exists (no DDL ran).
    users = (await db_session.execute(select(User))).scalars().all()
    assert users == []


@pytest.mark.asyncio
async def test_register_rejects_password_over_72_bytes(client):
    r = await client.post(
        "/v1/auth/register",
        json=_register_payload(password="A" + "a" * 71 + "1"),
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_register_rejects_weak_password(client):
    # No digit.
    r = await client.post(
        "/v1/auth/register",
        json=_register_payload(password="onlyletters"),
    )
    assert r.status_code == 422


# =============================================================== login


@pytest.mark.asyncio
async def test_login_happy_path(client, existing_user):
    user, password = existing_user
    # existing_user is not email_verified; manually verify for happy-path login.
    # (Login requires email_verified=True to succeed — we assert this separately.)
    user.email_verified = True
    r = await client.post(
        "/v1/auth/login",
        json={"email": user.email, "password": password},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "access_token" in body
    assert body["user"]["email"] == user.email


@pytest.mark.asyncio
async def test_login_wrong_password_returns_generic_401(client, existing_user):
    user, _ = existing_user
    user.email_verified = True
    r = await client.post(
        "/v1/auth/login",
        json={"email": user.email, "password": "WrongPass1"},
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "unauthorized"


@pytest.mark.asyncio
async def test_login_nonexistent_email_returns_identical_401(client):
    r = await client.post(
        "/v1/auth/login",
        json={"email": "nobody@nowhere.tld", "password": "Anything1"},
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "unauthorized"


@pytest.mark.asyncio
async def test_login_unverified_email_returns_identical_401(client, existing_user):
    user, password = existing_user  # email_verified is False out of fixture
    r = await client.post(
        "/v1/auth/login",
        json={"email": user.email, "password": password},
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "unauthorized"


@pytest.mark.asyncio
async def test_login_runs_verify_password_on_nonexistent_user(client, monkeypatch):
    """Timing-stable login regression guard: verify_password MUST be
    invoked even when the user row doesn't exist, otherwise an
    attacker can distinguish 'no such user' from 'wrong password' by
    response time."""
    import app.routes.auth as auth_routes

    call_counter = {"n": 0}
    orig = auth_routes.verify_password

    def counting(plain, hashed):
        call_counter["n"] += 1
        return orig(plain, hashed)

    monkeypatch.setattr(auth_routes, "verify_password", counting)

    r = await client.post(
        "/v1/auth/login",
        json={"email": "ghost@nowhere.tld", "password": "Anything1"},
    )
    assert r.status_code == 401
    assert call_counter["n"] == 1, "verify_password must run for nonexistent users"


@pytest.mark.asyncio
async def test_login_rate_limited_by_ip_after_5_attempts(client, existing_user):
    user, _ = existing_user
    ip = "198.51.100.77"
    for _ in range(5):
        await client.post(
            "/v1/auth/login",
            json={"email": user.email, "password": "WrongPass1"},
            headers=_with_ip(ip),
        )
    r = await client.post(
        "/v1/auth/login",
        json={"email": user.email, "password": "WrongPass1"},
        headers=_with_ip(ip),
    )
    assert r.status_code == 429


@pytest.mark.asyncio
async def test_login_rate_limited_by_email_across_ips(client, existing_user):
    user, _ = existing_user
    # 10 login attempts for same email from rotating IPs — 11th must 429.
    for i in range(10):
        await client.post(
            "/v1/auth/login",
            json={"email": user.email, "password": "WrongPass1"},
            headers=_with_ip(f"198.51.100.{i}"),
        )
    r = await client.post(
        "/v1/auth/login",
        json={"email": user.email, "password": "WrongPass1"},
        headers=_with_ip("198.51.100.200"),
    )
    assert r.status_code == 429


@pytest.mark.asyncio
async def test_login_failure_writes_audit_row(client, existing_user, db_session):
    user, _ = existing_user
    user.email_verified = True
    await client.post(
        "/v1/auth/login",
        json={"email": user.email, "password": "WrongPass1"},
    )
    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.login.failure")
        )
    ).scalars().all()
    assert len(audits) >= 1
    assert audits[-1].details == {"reason": "wrong_password"}


# =============================================================== refresh


@pytest.mark.asyncio
async def test_refresh_happy_path_rotates_tokens(client, existing_user, fake_redis):
    user, _ = existing_user
    refresh = create_refresh_token(sub=str(user.id))
    r = await client.post("/v1/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "access_token" in body and "refresh_token" in body
    # Old refresh jti is now in the revocation list.
    old_jti = jose_jwt.get_unverified_claims(refresh)["jti"]
    assert await fake_redis.exists(f"{REVOKED_JTI_PREFIX}:{old_jti}")


@pytest.mark.asyncio
async def test_refresh_reuse_detection_returns_401_and_audits(
    client, existing_user, fake_redis, db_session
):
    user, _ = existing_user
    refresh = create_refresh_token(sub=str(user.id))
    # First use — success.
    await client.post("/v1/auth/refresh", json={"refresh_token": refresh})
    # Second use of the SAME token — must detect reuse.
    r = await client.post("/v1/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 401
    # Audit carries the compromise signal.
    audits = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.token.revoked")
        )
    ).scalars().all()
    assert any(
        (a.details or {}).get("reason") == "reuse_detected" for a in audits
    ), f"expected reuse_detected audit, got {[a.details for a in audits]}"


@pytest.mark.asyncio
async def test_refresh_rejects_access_token(client, existing_user):
    """Type-claim check: an access token sent to /refresh must fail
    the `type == "refresh"` gate."""
    user, _ = existing_user
    access = create_access_token(sub=str(user.id))
    r = await client.post("/v1/auth/refresh", json={"refresh_token": access})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_refresh_rejects_malformed_token(client):
    r = await client.post("/v1/auth/refresh", json={"refresh_token": "not.a.jwt"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_refresh_rejects_token_for_deleted_user(client):
    """Cryptographically valid refresh token whose sub no longer
    resolves to a user row → 401."""
    ghost_refresh = create_refresh_token(sub=str(uuid4()))
    r = await client.post("/v1/auth/refresh", json={"refresh_token": ghost_refresh})
    assert r.status_code == 401


# =============================================================== logout


@pytest.mark.asyncio
async def test_logout_revokes_refresh_and_returns_204(
    client, existing_user, auth_headers, fake_redis
):
    user, _ = existing_user
    refresh = create_refresh_token(sub=str(user.id))
    r = await client.post(
        "/v1/auth/logout",
        json={"refresh_token": refresh},
        headers=auth_headers,
    )
    assert r.status_code == 204
    # Refresh jti is in the revocation list.
    refresh_jti = jose_jwt.get_unverified_claims(refresh)["jti"]
    assert await fake_redis.exists(f"{REVOKED_JTI_PREFIX}:{refresh_jti}")


@pytest.mark.asyncio
async def test_logout_requires_access_token(client, existing_user):
    """No auth header — get_current_user returns 401."""
    user, _ = existing_user
    refresh = create_refresh_token(sub=str(user.id))
    r = await client.post(
        "/v1/auth/logout",
        json={"refresh_token": refresh},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout_does_not_revoke_access_token(
    client, existing_user, auth_headers, fake_redis
):
    """Per policy: /logout revokes refresh only. Access tokens expire
    naturally in 15min. Regression guard — if someone adds access-
    revocation to /logout they need to think about it explicitly."""
    user, _ = existing_user
    refresh = create_refresh_token(sub=str(user.id))
    await client.post(
        "/v1/auth/logout",
        json={"refresh_token": refresh},
        headers=auth_headers,
    )
    # The access jti from auth_headers should NOT be in the revocation list.
    access_token = auth_headers["Authorization"].split(" ", 1)[1]
    access_jti = jose_jwt.get_unverified_claims(access_token)["jti"]
    assert not await fake_redis.exists(f"{REVOKED_JTI_PREFIX}:{access_jti}")


# =============================================================== me


@pytest.mark.asyncio
async def test_me_returns_identity_for_jwt(client, existing_user, auth_headers):
    """Task 2.4: /auth/me now returns AuthIdentityResponse (discriminated
    union). For a JWT caller, kind='jwt', user populated, api_key null."""
    user, _ = existing_user
    r = await client.get("/v1/auth/me", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "jwt"
    assert body["user"]["email"] == user.email
    assert body["api_key"] is None
    assert "organization" in body
    assert body["organization"]["slug"] == "existing-co"
    # No credentials leak.
    assert "hashed_password" not in r.text
    assert "password" not in body["user"]


@pytest.mark.asyncio
async def test_me_requires_bearer_token(client):
    r = await client.get("/v1/auth/me")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_me_rejects_revoked_access_token(
    client, existing_user, auth_headers, fake_redis
):
    access = auth_headers["Authorization"].split(" ", 1)[1]
    jti = jose_jwt.get_unverified_claims(access)["jti"]
    await revoke(fake_redis, jti, exp_unix=int(time.time()) + 900)
    r = await client.get("/v1/auth/me", headers=auth_headers)
    assert r.status_code == 401


# =============================================================== readiness


@pytest.mark.asyncio
async def test_ready_returns_200_when_deps_healthy(client, monkeypatch):
    # Pin both dep-checks healthy so the test proves the readiness-aggregation
    # -returns-200 logic deterministically (its actual point), rather than
    # gating on real postgres/redis round-trips finishing inside the 0.5s
    # _PROBE_TIMEOUT — which flakes under full-suite CPU load. Mirrors the
    # sibling test_ready_returns_503_when_redis_unreachable monkeypatch shape.
    import app.main as main_module

    async def _ok_postgres_check():
        return "ok"

    async def _ok_redis_check(_redis):
        return "ok"

    monkeypatch.setattr(main_module, "_check_postgres", _ok_postgres_check)
    monkeypatch.setattr(main_module, "_check_redis", _ok_redis_check)
    r = await client.get("/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    assert body["checks"] == {"postgres": "ok", "redis": "ok"}


@pytest.mark.asyncio
async def test_ready_returns_503_when_redis_unreachable(client, monkeypatch):
    """Break the redis ping — /ready must 503 with a per-dep code."""
    import app.main as main_module

    async def _broken_redis_check(_redis):
        return "error:ConnectionError"

    monkeypatch.setattr(main_module, "_check_redis", _broken_redis_check)
    r = await client.get("/ready")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["redis"].startswith("error:")


# =============================================================== lifespan


@pytest.mark.asyncio
async def test_lifespan_aborts_on_redis_unreachable(monkeypatch):
    """RUNBOOK §11.6: auth path fails closed. Startup MUST abort if
    Redis is unreachable — we do not want the app to accept requests
    with auth broken.
    """
    import app.main as main_module

    class _BadPing:
        async def ping(self):
            raise ConnectionError("simulated redis outage")

    async def _fake_init():
        return _BadPing()

    async def _noop_close():
        return None

    monkeypatch.setattr(main_module, "init_redis", _fake_init)
    monkeypatch.setattr(main_module, "close_redis", _noop_close)

    with pytest.raises(ConnectionError):
        async with main_module.lifespan(main_module.app):
            pass  # should never reach here
