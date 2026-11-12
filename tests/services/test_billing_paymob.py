"""Paymob provider + subscription state machine (M12 slice 4), against a
fake Paymob served through httpx.MockTransport. No network."""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select

from app.config import settings
from app.models.billing import BillingInterval, Invoice, SubscriptionStatus
from app.models.identity import Membership, MembershipRole, Organization, User
from app.services.auth import create_access_token, hash_password
from app.services.billing.paymob import HMAC_FIELDS, PaymobProvider, compute_hmac
from app.services.billing.subscriptions import (
    apply_event,
    cancel_subscription,
    record_event,
    start_checkout,
    sweep_org,
    vat_part,
)
from app.services.plans import current_subscription, resolve_limits
from tests.conftest import use_org

SECRET = "hmac-test-secret"


class FakePaymob:
    """Just enough of Paymob to drive the provider: auth, plans, intention,
    subscription read/suspend/resume/cancel. Records every call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.plans: dict[int, dict[str, Any]] = {}
        self.subs: dict[int, dict[str, Any]] = {}
        self.next_id = 100

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        self.calls.append((request.method, path, body))
        if path == "/api/auth/tokens":
            return httpx.Response(201, json={"token": "AUTH"})
        if path == "/api/acceptance/subscription-plans" and request.method == "POST":
            assert request.headers["Authorization"] == "Bearer AUTH"
            pid = self.next_id
            self.next_id += 1
            self.plans[pid] = body
            return httpx.Response(201, json={"id": pid, **body})
        if path == "/v1/intention/":
            assert request.headers["Authorization"] == "Token sk_test"
            return httpx.Response(201, json={"client_secret": "cs_123", "intention_order_id": 555})
        if path.startswith("/api/acceptance/subscriptions/"):
            sid = int(path.split("/")[4])
            action = path.split("/")[5] if len(path.split("/")) > 5 else None
            sub = self.subs.setdefault(
                sid, {"id": sid, "state": "active", "next_billing": None, "amount_cents": 99900}
            )
            if action in ("suspend", "resume", "cancel"):
                sub["state"] = {"suspend": "suspended", "resume": "active", "cancel": "canceled"}[
                    action
                ]
                return httpx.Response(200, json=sub)
            return httpx.Response(200, json=sub)
        return httpx.Response(404, json={"detail": "nope"})


def _provider(fake: FakePaymob) -> PaymobProvider:
    return PaymobProvider(
        base_url="https://fake.paymob",
        api_key="ak",
        secret_key="sk_test",
        public_key="pk_test",
        hmac_secret=SECRET,
        card_integration_id=11,
        moto_integration_id=22,
        transport=httpx.MockTransport(fake.handler),
    )


def _txn(
    *,
    txn_id: int,
    success: bool,
    reference: str | None = None,
    subscription_id: int | None = None,
    amount: int = 99900,
    refunded: bool = False,
    created_at: str = "2026-11-13T10:00:00+02:00",
) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "id": txn_id,
        "amount_cents": amount,
        "created_at": created_at,
        "currency": "EGP",
        "error_occured": False,
        "has_parent_transaction": False,
        "integration_id": 11,
        "is_3d_secure": True,
        "is_auth": False,
        "is_capture": False,
        "is_refunded": refunded,
        "is_standalone_payment": True,
        "is_voided": False,
        "order": {"id": 555, "merchant_order_id": reference},
        "owner": 1,
        "pending": False,
        "source_data": {"pan": "2346", "sub_type": "MasterCard", "type": "card"},
        "success": success,
        "data": {"message": "Approved" if success else "Declined: insufficient funds"},
    }
    if subscription_id is not None:
        obj["subscription_id"] = subscription_id
    return {"type": "TRANSACTION", "obj": obj}


def _signed(body: dict[str, Any]) -> dict[str, str]:
    return {"hmac": compute_hmac(body["obj"], SECRET)}


# ------------------------------------------------------------------ unit


def test_hmac_covers_the_documented_fields_in_order():
    assert (
        len(HMAC_FIELDS) == 20 and HMAC_FIELDS[0] == "amount_cents" and HMAC_FIELDS[-1] == "success"
    )
    body = _txn(txn_id=1, success=True)
    p = _provider(FakePaymob())
    assert p.verify_webhook(body, _signed(body))
    assert not p.verify_webhook(body, {"hmac": "00" * 64})
    tampered = _txn(txn_id=1, success=True, amount=1)
    assert not p.verify_webhook(tampered, _signed(body))


def test_parse_webhook_kinds():
    p = _provider(FakePaymob())
    ok = p.parse_webhook(_txn(txn_id=7, success=True, reference="abc", subscription_id=9))
    assert (
        ok.kind == "payment_succeeded"
        and ok.reference == "abc"
        and ok.provider_subscription_id == "9"
    )
    assert ok.event_id == "7" and ok.amount_cents == 99900 and ok.occurred_at is not None
    bad = p.parse_webhook(_txn(txn_id=8, success=False))
    assert bad.kind == "payment_failed" and "Declined" in (bad.failure_reason or "")
    assert p.parse_webhook(_txn(txn_id=9, success=True, refunded=True)).kind == "refunded"
    assert p.parse_webhook({"type": "TOKEN", "obj": {"id": 1}}).kind == "unknown"


def test_vat_is_inside_the_gross_price():
    settings.BILLING_VAT_RATE_PERCENT = 14
    assert vat_part(99900) == 12268  # 999 EGP gross = 876.32 net + 122.68 VAT (14/114)


# ------------------------------------------------------------------ state machine


@pytest_asyncio.fixture
async def org_user(db_session):
    org = Organization(name="Pay Org", slug=f"pay-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    user = User(
        email=f"p-{uuid4().hex[:6]}@t.co",
        hashed_password=hash_password("PayPass-1"),
        full_name="Pay User",
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(Membership(user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN))
    await db_session.commit()
    return org, user


@pytest.mark.asyncio
async def test_checkout_activation_renewal_failure_and_suspension(db_session, fake_redis, org_user):
    org, user = org_user
    fake = FakePaymob()
    provider = _provider(fake)
    settings.PAYMOB_WEBHOOK_URL = "https://app.test/v1/billing/webhooks/paymob"
    settings.BILLING_GRACE_DAYS = 7

    pending, co = await start_checkout(
        db_session,
        fake_redis,
        provider,
        org=org,
        user=user,
        plan_code="starter",
        interval=BillingInterval.MONTH,
        return_url="https://app.test/settings/billing?return=1",
        notification_url="https://app.test/v1/billing/webhooks/paymob",
    )
    await db_session.commit()
    assert pending.status == SubscriptionStatus.PENDING
    assert co.url.startswith(
        "https://fake.paymob/unifiedcheckout/?publicKey=pk_test&clientSecret=cs_123"
    )
    # Paymob plan created once with the monthly frequency and our webhook, intention carried our reference.
    plan_calls = [c for c in fake.calls if c[1] == "/api/acceptance/subscription-plans"]
    assert len(plan_calls) == 1 and plan_calls[0][2]["frequency"] == 30
    assert plan_calls[0][2]["webhook_url"] == settings.PAYMOB_WEBHOOK_URL
    intention = next(c for c in fake.calls if c[1] == "/v1/intention/")[2]
    assert (
        intention["special_reference"] == str(pending.id)
        and intention["subscription_plan_id"] == 100
    )
    # Still Free until the first payment.
    assert (await resolve_limits(db_session, org.id)).plan_code == "free"

    # First payment succeeds → ACTIVE on Starter v1, period = one month, invoice with VAT.
    ev = provider.parse_webhook(
        _txn(txn_id=1001, success=True, reference=str(pending.id), subscription_id=77)
    )
    row = await record_event(db_session, ev)
    assert row is not None
    assert await apply_event(db_session, fake_redis, ev, row) == "activated"
    await db_session.commit()
    sub = await current_subscription(db_session, org.id)
    assert sub is not None and sub.id == pending.id and sub.status == SubscriptionStatus.ACTIVE
    assert sub.provider_subscription_id == "77"
    assert sub.current_period_start == date(2026, 11, 13) and sub.current_period_end == date(
        2026, 12, 13
    )
    eff = await resolve_limits(db_session, org.id)
    assert eff.plan_code == "starter" and eff.period_start == "2026-11-13"
    inv = (await db_session.execute(select(Invoice))).scalars().all()
    assert len(inv) == 1 and inv[0].status.value == "paid" and inv[0].vat_cents == vat_part(99900)

    # Redelivery is a no-op.
    assert await record_event(db_session, ev) is None

    # Renewal (matched by subscription id, no reference) rolls the period from its end.
    ev2 = provider.parse_webhook(
        _txn(txn_id=1002, success=True, subscription_id=77, created_at="2026-12-13T09:00:00+02:00")
    )
    row2 = await record_event(db_session, ev2)
    assert row2 is not None and await apply_event(db_session, fake_redis, ev2, row2) == "renewed"
    await db_session.commit()
    sub = await current_subscription(db_session, org.id)
    assert sub is not None and sub.current_period_end == date(2027, 1, 13)

    # Failed renewal → PAST_DUE, still entitled.
    ev3 = provider.parse_webhook(
        _txn(txn_id=1003, success=False, subscription_id=77, created_at="2027-01-13T09:00:00+02:00")
    )
    row3 = await record_event(db_session, ev3)
    assert row3 is not None and await apply_event(db_session, fake_redis, ev3, row3) == "past_due"
    await db_session.commit()
    sub = await current_subscription(db_session, org.id)
    assert sub is not None and sub.status == SubscriptionStatus.PAST_DUE
    assert (await resolve_limits(db_session, org.id)).plan_code == "starter"

    # Nightly sweep inside grace: nothing. Past grace: suspended at Paymob and here; limits fall to Free.
    out = await sweep_org(db_session, fake_redis, provider, org.id, today=date(2027, 1, 15))
    assert out["action"] == "none"
    sub.past_due_since = datetime.now(timezone.utc) - timedelta(days=8)
    await db_session.commit()
    out = await sweep_org(db_session, fake_redis, provider, org.id, today=date(2027, 1, 25))
    assert out["action"] == "suspended"
    await db_session.commit()
    assert fake.subs[77]["state"] == "suspended"
    assert (await resolve_limits(db_session, org.id)).plan_code == "free"

    # A later successful payment (retry) reactivates.
    ev4 = provider.parse_webhook(
        _txn(txn_id=1004, success=True, subscription_id=77, created_at="2027-01-26T09:00:00+02:00")
    )
    row4 = await record_event(db_session, ev4)
    assert row4 is not None and await apply_event(db_session, fake_redis, ev4, row4) == "renewed"
    await db_session.commit()
    sub = await current_subscription(db_session, org.id)
    assert (
        sub is not None and sub.status == SubscriptionStatus.ACTIVE and sub.past_due_since is None
    )


@pytest.mark.asyncio
async def test_unmatched_event_is_recorded_not_applied(db_session, fake_redis, org_user):
    provider = _provider(FakePaymob())
    ev = provider.parse_webhook(
        _txn(txn_id=2001, success=True, reference=str(uuid4()), subscription_id=1)
    )
    row = await record_event(db_session, ev)
    assert row is not None
    assert await apply_event(db_session, fake_redis, ev, row) == "ignored_unmatched"
    assert row.outcome == "ignored_unmatched" and row.processed_at is not None


@pytest.mark.asyncio
async def test_cancel_at_period_end_then_sweep_cancels_at_processor(
    db_session, fake_redis, org_user
):
    org, user = org_user
    fake = FakePaymob()
    provider = _provider(fake)
    pending, _ = await start_checkout(
        db_session,
        fake_redis,
        provider,
        org=org,
        user=user,
        plan_code="growth",
        interval=BillingInterval.YEAR,
        return_url="https://app.test/r",
        notification_url="https://app.test/n",
    )
    ev = provider.parse_webhook(
        _txn(txn_id=3001, success=True, reference=str(pending.id), subscription_id=88)
    )
    row = await record_event(db_session, ev)
    assert row is not None
    await apply_event(db_session, fake_redis, ev, row)
    await db_session.commit()
    sub = await cancel_subscription(
        db_session, fake_redis, provider, org_id=org.id, at_period_end=True
    )
    await db_session.commit()
    assert sub.cancel_at_period_end is True and sub.status == SubscriptionStatus.ACTIVE
    assert sub.current_period_end == date(2027, 11, 13)
    # Before the period ends: still Growth. At period end: canceled here and at Paymob, back to Free.
    out = await sweep_org(db_session, fake_redis, provider, org.id, today=date(2027, 6, 1))
    assert out["action"] == "none"
    out = await sweep_org(db_session, fake_redis, provider, org.id, today=date(2027, 11, 13))
    await db_session.commit()
    assert out["action"] == "canceled_at_period_end" and fake.subs[88]["state"] == "canceled"
    assert (await resolve_limits(db_session, org.id)).plan_code == "free"


# ------------------------------------------------------------------ routes


@pytest.mark.asyncio
async def test_webhook_route_rejects_bad_signature_and_applies_good_one(
    client, db_session, org_user, monkeypatch
):
    org, user = org_user
    fake = FakePaymob()
    provider = _provider(fake)
    monkeypatch.setattr("app.routes.billing.get_provider", lambda: provider)
    monkeypatch.setattr(settings, "BILLING_PROVIDER", "paymob")
    monkeypatch.setattr(settings, "PAYMOB_SECRET_KEY", "sk_test")
    headers = {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}

    r = await client.post(
        f"/v1/orgs/{org.id}/billing/checkout",
        json={"plan_code": "starter", "billing_interval": "month"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    sub_id = r.json()["subscription_id"]
    assert "unifiedcheckout" in r.json()["checkout_url"]
    r = await client.get(f"/v1/orgs/{org.id}/billing/subscription", headers=headers)
    assert r.json()["plan_code"] == "free" and r.json()["pending_checkout"] is True
    assert r.json()["online_checkout"] is True

    body = _txn(txn_id=4001, success=True, reference=sub_id, subscription_id=99)
    r = await client.post("/v1/billing/webhooks/paymob", json=body, params={"hmac": "deadbeef"})
    assert r.status_code == 401
    r = await client.post("/v1/billing/webhooks/paymob", json=body, params=_signed(body))
    assert r.status_code == 200 and r.text == "activated"
    r = await client.post("/v1/billing/webhooks/paymob", json=body, params=_signed(body))
    assert r.status_code == 200 and r.text == "duplicate"

    r = await client.get(f"/v1/orgs/{org.id}/billing/subscription", headers=headers)
    v = r.json()
    assert v["plan_code"] == "starter" and v["status"] == "active" and v["provider"] == "paymob"
    assert (
        v["pending_checkout"] is False
        and len(v["invoices"]) == 1
        and v["invoices"][0]["status"] == "paid"
    )

    r = await client.post(f"/v1/orgs/{org.id}/billing/cancel", headers=headers)
    assert r.status_code == 200 and r.json()["cancel_at_period_end"] is True


@pytest.mark.asyncio
async def test_checkout_unavailable_on_manual_provider(client, org_user):
    org, user = org_user
    headers = {"Authorization": f"Bearer {create_access_token(sub=str(user.id))}"}
    r = await client.post(
        f"/v1/orgs/{org.id}/billing/checkout", json={"plan_code": "starter"}, headers=headers
    )
    assert r.status_code == 503
    r = await client.post("/v1/billing/webhooks/paymob", json={"type": "TRANSACTION", "obj": {}})
    assert r.status_code == 404
