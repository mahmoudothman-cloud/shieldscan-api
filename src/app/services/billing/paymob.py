"""Paymob Accept (Egypt) — Subscriptions module + Unified Checkout.

Built from Paymob's published Postman collections (Subscription Module
API, Intention APIs) and the HMAC rule on developers.paymob.com, read
2026-11-11. Two auth styles on the same host:

* ``/api/acceptance/*`` (plans, subscriptions): ``Authorization: Bearer
  <auth token>`` where the token comes from ``POST /api/auth/tokens``
  with the account API key (cached ~55 min here);
* ``/v1/intention/`` (checkout): ``Authorization: Token <secret key>``.

Transaction callback HMAC (SHA-512, hex, over the concatenation of 20
fields in this fixed order, with the dashboard HMAC secret; the digest
arrives as the ``hmac`` query parameter)::

    amount_cents created_at currency error_occured has_parent_transaction
    id integration_id is_3d_secure is_auth is_capture is_refunded
    is_standalone_payment is_voided order.id owner pending
    source_data.pan source_data.sub_type source_data.type success

ASSUMPTIONS TO VERIFY IN TEST MODE (see DRIFT-LOG 2026-11-13): the
transaction callback for a subscription payment carries
``obj.subscription_id`` (renewals) and ``obj.order.merchant_order_id``
= our ``special_reference`` (first payment); ``GET
/api/acceptance/subscriptions/{id}`` returns ``state`` and
``next_billing``. Both are isolated in ``parse_webhook`` /
``fetch_subscription`` so a field rename is a one-line change.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from datetime import date, datetime
from typing import Any
from uuid import UUID

import httpx

from app.config import settings
from app.models.billing import BillingInterval, BillingProviderName
from app.services.billing import (
    BillingEvent,
    Checkout,
    ProviderPlanRef,
    ProviderSubscription,
)

logger = logging.getLogger(__name__)

_FREQUENCY: dict[BillingInterval, int] = {BillingInterval.MONTH: 30, BillingInterval.YEAR: 360}

HMAC_FIELDS: tuple[str, ...] = (
    "amount_cents",
    "created_at",
    "currency",
    "error_occured",
    "has_parent_transaction",
    "id",
    "integration_id",
    "is_3d_secure",
    "is_auth",
    "is_capture",
    "is_refunded",
    "is_standalone_payment",
    "is_voided",
    "order.id",
    "owner",
    "pending",
    "source_data.pan",
    "source_data.sub_type",
    "source_data.type",
    "success",
)


def _get(obj: dict[str, Any], dotted: str) -> Any:
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _py_bool(v: Any) -> str:
    # Paymob concatenates Python-style booleans ("true"/"false" lowercase).
    if isinstance(v, bool):
        return "true" if v else "false"
    return "" if v is None else str(v)


def compute_hmac(obj: dict[str, Any], secret: str) -> str:
    message = "".join(_py_bool(_get(obj, f)) for f in HMAC_FIELDS)
    return hmac.new(secret.encode(), message.encode(), hashlib.sha512).hexdigest()


class PaymobError(Exception):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"paymob {status}: {body[:200]}")
        self.status = status
        self.body = body


class PaymobProvider:
    name = BillingProviderName.PAYMOB

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        secret_key: str,
        public_key: str,
        hmac_secret: str,
        card_integration_id: int,
        moto_integration_id: int,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.secret_key = secret_key
        self.public_key = public_key
        self.hmac_secret = hmac_secret
        self.card_integration_id = card_integration_id
        self.moto_integration_id = moto_integration_id
        self._transport = transport
        self._auth_token: str | None = None
        self._auth_expires = 0.0

    @classmethod
    def from_settings(cls) -> PaymobProvider:
        return cls(
            base_url=settings.PAYMOB_BASE_URL,
            api_key=settings.PAYMOB_API_KEY,
            secret_key=settings.PAYMOB_SECRET_KEY,
            public_key=settings.PAYMOB_PUBLIC_KEY,
            hmac_secret=settings.PAYMOB_HMAC_SECRET,
            card_integration_id=settings.PAYMOB_CARD_INTEGRATION_ID,
            moto_integration_id=settings.PAYMOB_MOTO_INTEGRATION_ID,
        )

    # ------------------------------------------------------------ http

    def _client(self) -> httpx.AsyncClient:
        kw: dict[str, Any] = {"base_url": self.base_url, "timeout": 20.0}
        if self._transport is not None:
            kw["transport"] = self._transport
        return httpx.AsyncClient(**kw)

    async def _auth(self) -> str:
        if self._auth_token and time.monotonic() < self._auth_expires:
            return self._auth_token
        async with self._client() as c:
            r = await c.post("/api/auth/tokens", json={"api_key": self.api_key})
        if r.status_code >= 400:
            raise PaymobError(r.status_code, r.text)
        token = str(r.json()["token"])
        self._auth_token = token
        self._auth_expires = time.monotonic() + 55 * 60
        return token

    async def _acceptance(self, method: str, path: str, json: dict[str, Any] | None = None) -> Any:
        token = await self._auth()
        async with self._client() as c:
            r = await c.request(
                method, path, json=json, headers={"Authorization": f"Bearer {token}"}
            )
        if r.status_code >= 400:
            raise PaymobError(r.status_code, r.text)
        return r.json() if r.content else {}

    # ------------------------------------------------------------ plans

    async def create_plan(
        self,
        *,
        code: str,
        name: str,
        interval: BillingInterval,
        amount_cents: int,
        webhook_url: str,
    ) -> ProviderPlanRef:
        body = {
            "frequency": _FREQUENCY[interval],
            "name": f"ShieldScan {name} ({interval.value})",
            "reminder_days": 3,
            "retrial_days": 3,
            "plan_type": "rent",
            "number_of_deductions": None,
            "amount_cents": amount_cents,
            "use_transaction_amount": False,
            "is_active": True,
            "integration": self.moto_integration_id,
            "webhook_url": webhook_url,
        }
        data = await self._acceptance("POST", "/api/acceptance/subscription-plans", body)
        return ProviderPlanRef(provider_plan_id=str(data["id"]))

    async def update_plan_amount(self, provider_plan_id: str, amount_cents: int) -> None:
        await self._acceptance(
            "PUT",
            f"/api/acceptance/subscription-plans/{provider_plan_id}",
            {"amount_cents": amount_cents, "integration": self.moto_integration_id},
        )

    # ------------------------------------------------------------ checkout

    async def start_checkout(
        self,
        *,
        provider_plan_id: str,
        amount_cents: int,
        reference: UUID,
        customer_email: str,
        customer_name: str,
        return_url: str,
        notification_url: str,
    ) -> Checkout:
        first, _, last = customer_name.partition(" ")
        body = {
            "amount": amount_cents,
            "currency": "EGP",
            "payment_methods": [self.card_integration_id],
            "subscription_plan_id": int(provider_plan_id),
            "items": [
                {
                    "name": "ShieldScan subscription",
                    "amount": amount_cents,
                    "description": "First period",
                    "quantity": 1,
                }
            ],
            "billing_data": {
                "first_name": first or "Customer",
                "last_name": last or "-",
                "email": customer_email,
                "phone_number": "+20000000000",  # Paymob requires a value; we do not collect phones
                "apartment": "-",
                "street": "-",
                "building": "-",
                "city": "-",
                "country": "EG",
                "floor": "-",
                "state": "-",
            },
            "special_reference": str(reference),
            "notification_url": notification_url,
            "redirection_url": return_url,
        }
        async with self._client() as c:
            r = await c.post(
                "/v1/intention/", json=body, headers={"Authorization": f"Token {self.secret_key}"}
            )
        if r.status_code >= 400:
            raise PaymobError(r.status_code, r.text)
        data = r.json()
        client_secret = str(data["client_secret"])
        order_id = data.get("intention_order_id") or _get(data, "intention_detail.order_id")
        return Checkout(
            url=f"{self.base_url}/unifiedcheckout/?publicKey={self.public_key}&clientSecret={client_secret}",
            client_secret=client_secret,
            provider_order_id=str(order_id) if order_id is not None else None,
        )

    # ------------------------------------------------------------ subscriptions

    async def fetch_subscription(self, provider_subscription_id: str) -> ProviderSubscription:
        data = await self._acceptance(
            "GET", f"/api/acceptance/subscriptions/{provider_subscription_id}"
        )
        state = str(data.get("state") or data.get("status") or "unknown").lower()
        nb = data.get("next_billing")
        next_billing = date.fromisoformat(str(nb)[:10]) if nb else None
        amt = data.get("amount_cents")
        return ProviderSubscription(
            provider_subscription_id=str(data.get("id", provider_subscription_id)),
            state=state,
            next_billing=next_billing,
            amount_cents=int(amt) if amt is not None else None,
            raw=data,
        )

    async def suspend(self, provider_subscription_id: str) -> None:
        await self._acceptance(
            "POST", f"/api/acceptance/subscriptions/{provider_subscription_id}/suspend"
        )

    async def resume(self, provider_subscription_id: str) -> None:
        await self._acceptance(
            "POST", f"/api/acceptance/subscriptions/{provider_subscription_id}/resume"
        )

    async def cancel(self, provider_subscription_id: str) -> None:
        await self._acceptance(
            "POST", f"/api/acceptance/subscriptions/{provider_subscription_id}/cancel"
        )

    # ------------------------------------------------------------ webhooks

    def verify_webhook(self, body: dict[str, Any], query: dict[str, str]) -> bool:
        if not self.hmac_secret:
            return False
        given = query.get("hmac") or str(body.get("hmac") or "")
        obj = body.get("obj")
        if not isinstance(obj, dict) or not given:
            return False
        return hmac.compare_digest(compute_hmac(obj, self.hmac_secret), given.lower())

    def parse_webhook(self, body: dict[str, Any]) -> BillingEvent:
        raw_obj = body.get("obj")
        obj: dict[str, Any] = raw_obj if isinstance(raw_obj, dict) else {}
        kind = "unknown"
        if body.get("type") == "TRANSACTION":
            if obj.get("is_refunded"):
                kind = "refunded"
            elif obj.get("success") is True and not obj.get("pending"):
                kind = "payment_succeeded"
            elif obj.get("success") is False:
                kind = "payment_failed"
        created = obj.get("created_at")
        occurred: datetime | None = None
        if created:
            try:
                occurred = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
            except ValueError:
                occurred = None
        sub_id = obj.get("subscription_id") or obj.get("subscription")
        ref = _get(obj, "order.merchant_order_id")
        data_msg = _get(obj, "data.message")
        return BillingEvent(
            provider=self.name,
            event_id=str(obj.get("id") or body.get("id") or ""),
            kind=kind,
            occurred_at=occurred,
            amount_cents=int(obj["amount_cents"]) if obj.get("amount_cents") is not None else None,
            currency=obj.get("currency"),
            reference=str(ref) if ref else None,
            provider_subscription_id=str(sub_id) if sub_id else None,
            provider_transaction_id=str(obj.get("id")) if obj.get("id") is not None else None,
            failure_reason=str(data_msg) if data_msg and kind == "payment_failed" else None,
            raw=body,
        )
