"""No-processor provider: nothing is charged online. ``start_checkout``
refuses; everything else is a no-op so the state machine can run the
same code paths (reconcile, cancel) without branching on provider."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.models.billing import BillingInterval, BillingProviderName
from app.services.billing import (
    BillingEvent,
    Checkout,
    ProviderPlanRef,
    ProviderSubscription,
)


class CheckoutUnavailable(Exception):
    pass


class ManualProvider:
    name = BillingProviderName.MANUAL

    async def create_plan(
        self,
        *,
        code: str,
        name: str,
        interval: BillingInterval,
        amount_cents: int,
        webhook_url: str,
    ) -> ProviderPlanRef:
        return ProviderPlanRef(provider_plan_id=f"manual:{code}:{interval.value}")

    async def update_plan_amount(self, provider_plan_id: str, amount_cents: int) -> None:
        return None

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
        raise CheckoutUnavailable("online checkout is not configured")

    async def fetch_subscription(self, provider_subscription_id: str) -> ProviderSubscription:
        return ProviderSubscription(
            provider_subscription_id=provider_subscription_id,
            state="unknown",
            next_billing=None,
            amount_cents=None,
        )

    async def suspend(self, provider_subscription_id: str) -> None:
        return None

    async def resume(self, provider_subscription_id: str) -> None:
        return None

    async def cancel(self, provider_subscription_id: str) -> None:
        return None

    def verify_webhook(self, body: dict[str, Any], query: dict[str, str]) -> bool:
        return False

    def parse_webhook(self, body: dict[str, Any]) -> BillingEvent:
        raise ValueError("manual provider has no webhooks")
