"""Tests for API-key auth path — Task 2.4, Commit 1.

Covers:
  - _detect_credential_kind (4 cases)
  - _authenticate_api_key happy path / revoked key / nonexistent
  - _maybe_schedule_last_used_update: fires on fresh keys (None),
    fires on stale keys (>60s old), DOES NOT fire within debounce
  - get_current_user rejects API-key-shape credentials with 403
    (api_key_insufficient_for_operation) — distinct from 401
  - require_jwt rejects API keys with 403, passes for JWT
  - Fire-and-forget: scheduler is invoked synchronously from the
    auth path, not awaited
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.dependencies import (
    AuthIdentity,
    _API_KEY_LAST_USED_DEBOUNCE,
    _authenticate_api_key,
    _detect_credential_kind,
    _maybe_schedule_last_used_update,
    get_auth_identity,
    get_current_user,
    require_jwt,
)
from app.models.identity import APIKey, Membership, MembershipRole, Organization, User
from app.services.auth import create_access_token
from tests.conftest import use_org


def _make_request(headers: dict[str, str] | None = None) -> Request:
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
        "client": ("127.0.0.1", 40000),
        "server": ("test", 80),
        "scheme": "http",
    }
    return Request(scope)


async def _make_org_user_and_key(db_session, *, revoked: bool = False):
    org = Organization(name="Org K", slug=f"orgk-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"k-{uuid4().hex[:6]}@t.co",
        hashed_password="x",
        full_name="K User",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN)
    )
    plaintext = f"ss_live_test_{uuid4().hex[:24]}"
    key = APIKey(
        organization_id=org.id,
        name="Test Key",
        key_prefix=plaintext[:12],
        key_hash=hashlib.sha256(plaintext.encode()).hexdigest(),
        revoked_at=datetime.now(timezone.utc) if revoked else None,
    )
    db_session.add(key)
    await db_session.commit()
    return org, user, key, plaintext


# ---------------------------------------------------------------- _detect_credential_kind


def test_detect_credential_kind_api_key_live():
    assert _detect_credential_kind("ss_live_abc123xyz") == "api_key"


def test_detect_credential_kind_api_key_test():
    assert _detect_credential_kind("ss_test_abc123xyz") == "api_key"


def test_detect_credential_kind_jwt():
    jwt_like = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig"
    assert _detect_credential_kind(jwt_like) == "jwt"


def test_detect_credential_kind_garbage_falls_through_to_jwt():
    """Positive-match design: anything NOT starting with ss_live_/ss_test_
    goes to the JWT path. A bad JWT then fails loudly at decode time."""
    assert _detect_credential_kind("garbage_that_is_not_an_api_key") == "jwt"
    assert _detect_credential_kind("") == "jwt"


# ---------------------------------------------------------------- _authenticate_api_key


@pytest.mark.asyncio
async def test_authenticate_api_key_happy_path(db_session):
    _, _, key, plaintext = await _make_org_user_and_key(db_session)
    got = await _authenticate_api_key(db_session, plaintext)
    assert got is not None
    assert got.id == key.id
    assert got.organization_id == key.organization_id


@pytest.mark.asyncio
async def test_authenticate_api_key_rejects_revoked(db_session):
    """Load-bearing: a revoked key must NOT authenticate. If the
    revoked_at IS NULL filter is ever dropped, this test fires."""
    _, _, _, plaintext = await _make_org_user_and_key(db_session, revoked=True)
    got = await _authenticate_api_key(db_session, plaintext)
    assert got is None


@pytest.mark.asyncio
async def test_authenticate_api_key_rejects_nonexistent(db_session):
    got = await _authenticate_api_key(db_session, "ss_live_no_such_key_anywhere_xyz")
    assert got is None


# ---------------------------------------------------------------- last_used_at debounce + fire-and-forget


@pytest.mark.asyncio
async def test_last_used_update_fires_for_fresh_key(db_session):
    """First use of a key (last_used_at IS NULL) must schedule the
    update."""
    _, _, key, _ = await _make_org_user_and_key(db_session)
    assert key.last_used_at is None

    scheduled: list = []
    fired = _maybe_schedule_last_used_update(key, scheduler=scheduled.append)
    assert fired is True
    assert len(scheduled) == 1

    # Clean up the unawaited coroutine to avoid pytest warnings.
    scheduled[0].close()


@pytest.mark.asyncio
async def test_last_used_update_debounces_within_60s(db_session):
    """last_used_at set 10 seconds ago — next request must NOT
    schedule another update. Prevents write-amplification under
    high API-key traffic."""
    _, _, key, _ = await _make_org_user_and_key(db_session)
    key.last_used_at = datetime.now(timezone.utc) - timedelta(seconds=10)

    scheduled: list = []
    fired = _maybe_schedule_last_used_update(key, scheduler=scheduled.append)
    assert fired is False
    assert scheduled == []


@pytest.mark.asyncio
async def test_last_used_update_fires_after_debounce_window(db_session):
    """last_used_at set 61 seconds ago — back over the debounce
    threshold, next request schedules the update."""
    _, _, key, _ = await _make_org_user_and_key(db_session)
    key.last_used_at = datetime.now(timezone.utc) - timedelta(
        seconds=_API_KEY_LAST_USED_DEBOUNCE + 1
    )

    scheduled: list = []
    fired = _maybe_schedule_last_used_update(key, scheduler=scheduled.append)
    assert fired is True
    assert len(scheduled) == 1
    scheduled[0].close()


@pytest.mark.asyncio
async def test_last_used_update_is_fire_and_forget_not_awaited(db_session, monkeypatch):
    """Prove the auth path does NOT await the last_used_at update —
    the coroutine is handed to ``asyncio.create_task`` which returns
    immediately. Measured via a capturing scheduler: _authenticate_api_key
    must return while the captured coroutine is still unawaited.
    """
    import app.dependencies as deps

    captured: list = []

    def _capturing_scheduler(coro):
        # Record the coro without awaiting it — proves fire-and-forget.
        captured.append(coro)
        return None  # asyncio.create_task would return a Task; we don't need it

    # Patch the default scheduler used by _maybe_schedule_last_used_update.
    orig = deps._maybe_schedule_last_used_update

    def patched(key, *, scheduler=_capturing_scheduler, now=None):
        return orig(key, scheduler=scheduler, now=now)

    monkeypatch.setattr(deps, "_maybe_schedule_last_used_update", patched)

    _, _, key, plaintext = await _make_org_user_and_key(db_session)
    got = await _authenticate_api_key(db_session, plaintext)
    assert got is not None
    # The coro was captured but NEVER awaited — auth path returned
    # without waiting on the DB UPDATE.
    assert len(captured) == 1
    # The coroutine must still be un-awaited (not yet run). Closing it
    # is the cleanup; if it had been awaited, asyncio would complain
    # about this.
    assert asyncio.iscoroutine(captured[0])
    captured[0].close()


# ---------------------------------------------------------------- get_current_user rejects API keys


@pytest.mark.asyncio
async def test_get_current_user_rejects_api_key_with_403(db_session, fake_redis):
    """get_current_user is JWT-only. An API-key-shaped credential
    must NOT be authenticated here — it's 403 (authenticated-but-not-
    authorized-for-this-operation), distinct from 401 (bad creds)."""
    req = _make_request(headers={"Authorization": "Bearer ss_live_abc123xyz"})
    with pytest.raises(HTTPException) as ei:
        await get_current_user(req, db_session, fake_redis)
    assert ei.value.status_code == 403
    assert ei.value.detail == "api_key_insufficient_for_operation"


# ---------------------------------------------------------------- get_auth_identity (both kinds)


@pytest.mark.asyncio
async def test_get_auth_identity_accepts_api_key(db_session, fake_redis):
    _, _, key, plaintext = await _make_org_user_and_key(db_session)
    req = _make_request(headers={"Authorization": f"Bearer {plaintext}"})
    identity = await get_auth_identity(req, db_session, fake_redis)
    assert identity.kind == "api_key"
    assert identity.organization_id == key.organization_id
    assert identity.api_key is not None
    assert identity.api_key.id == key.id
    assert identity.user is None


@pytest.mark.asyncio
async def test_get_auth_identity_accepts_jwt(db_session, fake_redis):
    _, user, _, _ = await _make_org_user_and_key(db_session)
    token = create_access_token(sub=str(user.id))
    req = _make_request(headers={"Authorization": f"Bearer {token}"})
    identity = await get_auth_identity(req, db_session, fake_redis)
    assert identity.kind == "jwt"
    assert identity.user is not None
    assert identity.user.id == user.id
    assert identity.api_key is None


# ---------------------------------------------------------------- require_jwt


@pytest.mark.asyncio
async def test_require_jwt_passes_for_jwt_identity():
    """Build an AuthIdentity directly — unit test the predicate
    without a full request round-trip."""
    user = User(email="x@t.co", hashed_password="x", full_name="X", email_verified=True)
    identity = AuthIdentity(kind="jwt", organization_id=uuid4(), user=user)
    got = await require_jwt(identity=identity)
    assert got is identity


@pytest.mark.asyncio
async def test_require_jwt_rejects_api_key_with_403():
    identity = AuthIdentity(
        kind="api_key",
        organization_id=uuid4(),
        api_key=None,  # value irrelevant; kind drives the check
    )
    with pytest.raises(HTTPException) as ei:
        await require_jwt(identity=identity)
    assert ei.value.status_code == 403
    assert ei.value.detail == "api_key_insufficient_for_operation"
