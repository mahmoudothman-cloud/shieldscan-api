"""Billing processors (M12 slice 4; Plans & Billing Review v1.1 §5).

One interface, two implementations today — ``PaymobProvider`` (Egypt,
EGP, Paymob Accept Subscriptions module) and ``ManualProvider`` (no
online checkout: the platform admin assigns subscriptions; bank-transfer
customers, design partners, the Free row). Paddle (USD) is a third
implementation later, behind the same interface.

The provider never touches ``org_subscriptions`` itself: it talks to the
processor and returns plain data; ``services.billing.subscriptions``
owns the state machine and the database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Protocol
from uuid import UUID

from app.config import settings
from app.models.billing import BillingInterval, BillingProviderName


@dataclass
class ProviderPlanRef:
    provider_plan_id: str


@dataclass
class Checkout:
    url: str
    client_secret: str | None = None
    provider_order_id: str | None = None


@dataclass
class ProviderSubscription:
    provider_subscription_id: str
    state: str  # active | suspended | canceled | ended | unknown
    next_billing: date | None
    amount_cents: int | None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class BillingEvent:
    """A processor webhook, normalised. ``kind`` is one of
    payment_succeeded | payment_failed | refunded | unknown."""

    provider: BillingProviderName
    event_id: str
    kind: str
    occurred_at: datetime | None
    amount_cents: int | None
    currency: str | None
    reference: str | None  # our org_subscriptions.id as passed in special_reference, if present
    provider_subscription_id: str | None
    provider_transaction_id: str | None
    failure_reason: str | None
    raw: dict[str, Any]


class BillingProvider(Protocol):
    name: BillingProviderName

    async def create_plan(
        self,
        *,
        code: str,
        name: str,
        interval: BillingInterval,
        amount_cents: int,
        webhook_url: str,
    ) -> ProviderPlanRef: ...

    async def update_plan_amount(self, provider_plan_id: str, amount_cents: int) -> None: ...

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
    ) -> Checkout: ...

    async def fetch_subscription(self, provider_subscription_id: str) -> ProviderSubscription: ...

    async def suspend(self, provider_subscription_id: str) -> None: ...

    async def resume(self, provider_subscription_id: str) -> None: ...

    async def cancel(self, provider_subscription_id: str) -> None: ...

    def verify_webhook(self, body: dict[str, Any], query: dict[str, str]) -> bool: ...

    def parse_webhook(self, body: dict[str, Any]) -> BillingEvent: ...


def get_provider() -> BillingProvider:
    """The configured processor. Imported lazily so the manual path has no
    httpx dependency at import time."""
    if settings.BILLING_PROVIDER == "paymob":
        from app.services.billing.paymob import PaymobProvider

        return PaymobProvider.from_settings()
    from app.services.billing.manual import ManualProvider

    return ManualProvider()


def online_checkout_available() -> bool:
    return settings.BILLING_PROVIDER == "paymob" and bool(settings.PAYMOB_SECRET_KEY)
