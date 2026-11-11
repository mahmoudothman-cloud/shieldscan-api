"""Plan catalog and billing-summary schemas (M12 slice 1)."""

from __future__ import annotations

from datetime import date
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class PlanPrice(BaseModel):
    """One live version of a plan for one billing interval. Prices are
    gross (14% VAT inside), in minor units."""

    model_config = ConfigDict(from_attributes=True)

    version_id: UUID
    billing_interval: str
    price_egp_cents: int
    price_usd_cents: int
    limits: dict[str, int]
    features: dict[str, Any]


class PlanPublic(BaseModel):
    code: str
    name: str
    description: str | None
    rank: int | None
    prices: list[PlanPrice]


class PlanCatalogResponse(BaseModel):
    """``GET /plans`` — what the pricing page and the upgrade dialog render.
    Public plans only, live versions only, ordered by rank."""

    plans: list[PlanPublic]
    vat_included: bool = True
    vat_rate_percent: int = 14


class BillingSummaryResponse(BaseModel):
    """``GET /orgs/{org_id}/billing/summary`` — the org's effective limits,
    the period they apply to, and usage so far in that period."""

    plan_code: str
    plan_name: str
    billing_interval: str
    subscription_status: str
    period_start: date
    period_end: date | None
    limits: dict[str, int]
    features: dict[str, Any]
    usage: dict[str, int]
    overrides: list[str]
