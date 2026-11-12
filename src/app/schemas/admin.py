"""Platform-admin schemas (M12 slice 3)."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.services.plans import FEATURE_KEYS, LIMIT_KEYS, UNLIMITED


class PlanVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    plan_id: UUID
    version: int
    billing_interval: str
    price_egp_cents: int
    price_usd_cents: int
    limits: dict[str, int]
    features: dict[str, Any]
    paymob_plan_id: str | None
    paddle_price_id: str | None
    effective_from: datetime
    retired_at: datetime | None
    change_note: str | None
    created_by: UUID | None
    created_at: datetime


class PlanAdminOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    code: str
    name: str
    description: str | None
    rank: int | None
    is_public: bool
    archived_at: datetime | None
    live_versions: list[PlanVersionOut]
    version_count: int
    subscriber_count: int


class PlanAdminList(BaseModel):
    plans: list[PlanAdminOut]
    limit_keys: list[str] = list(LIMIT_KEYS)
    feature_keys: list[str] = list(FEATURE_KEYS)


class PlanCreate(BaseModel):
    code: str = Field(min_length=2, max_length=40, pattern=r"^[a-z][a-z0-9_]*$")
    name: str = Field(min_length=1, max_length=80)
    description: str | None = None
    rank: int | None = None
    is_public: bool = True


class PlanPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = None
    rank: int | None = None
    is_public: bool | None = None
    archived: bool | None = None


def _check_limits(limits: dict[str, int]) -> dict[str, int]:
    unknown = set(limits) - set(LIMIT_KEYS)
    if unknown:
        raise ValueError(f"unknown limit keys: {sorted(unknown)}")
    missing = set(LIMIT_KEYS) - set(limits)
    if missing:
        raise ValueError(f"missing limit keys: {sorted(missing)}")
    for k, v in limits.items():
        if isinstance(v, bool) or not isinstance(v, int) or v < UNLIMITED:
            raise ValueError(f"{k}: must be an integer >= -1 (-1 = unlimited)")
    return limits


def _check_features(features: dict[str, Any]) -> dict[str, Any]:
    unknown = set(features) - set(FEATURE_KEYS)
    if unknown:
        raise ValueError(f"unknown feature keys: {sorted(unknown)}")
    missing = set(FEATURE_KEYS) - set(features)
    if missing:
        raise ValueError(f"missing feature keys: {sorted(missing)}")
    for k, v in features.items():
        if k == "compliance.frameworks":
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise ValueError("compliance.frameworks: must be a list of framework slugs")
        elif not isinstance(v, bool):
            raise ValueError(f"{k}: must be true or false")
    return features


class PlanVersionCreate(BaseModel):
    """Publish a new version for (plan, interval): the current live one is
    retired; subscriptions on it keep it (grandfathering)."""

    billing_interval: str = Field(pattern=r"^(month|year)$")
    price_egp_cents: int = Field(ge=0)
    price_usd_cents: int = Field(ge=0)
    limits: dict[str, int]
    features: dict[str, Any]
    change_note: str | None = Field(default=None, max_length=500)

    @field_validator("limits")
    @classmethod
    def _limits(cls, v: dict[str, int]) -> dict[str, int]:
        return _check_limits(v)

    @field_validator("features")
    @classmethod
    def _features(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _check_features(v)


class VersionDiff(BaseModel):
    """What changed between the retired version and the new one."""

    field: str
    before: Any
    after: Any


class PlanVersionPublished(BaseModel):
    version: PlanVersionOut
    retired: PlanVersionOut | None
    diff: list[VersionDiff]


class OrgSummaryOut(BaseModel):
    id: UUID
    name: str
    slug: str
    created_at: datetime
    members: int
    plan_code: str
    subscription_status: str
    provider: str | None


class OrgAdminList(BaseModel):
    orgs: list[OrgSummaryOut]
    total: int


class OverrideOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key: str
    value: Any
    reason: str | None
    expires_at: datetime | None
    set_by: UUID | None
    updated_at: datetime


class SubscriptionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    plan_version_id: UUID
    status: str
    provider: str
    provider_subscription_id: str | None
    current_period_start: date
    current_period_end: date | None
    cancel_at_period_end: bool
    note: str | None
    created_at: datetime


class OrgAdminDetail(BaseModel):
    org: OrgSummaryOut
    subscription: SubscriptionOut | None
    overrides: list[OverrideOut]
    effective_limits: dict[str, int]
    effective_features: dict[str, Any]
    usage: dict[str, int]
    period_start: date
    period_end: date | None


class OverrideSet(BaseModel):
    value: Any
    reason: str | None = Field(default=None, max_length=500)
    expires_at: datetime | None = None


class SubscriptionAssign(BaseModel):
    """Manual subscription (design partner, enterprise invoice, support
    bump). Cancels the current one and starts a MANUAL ACTIVE row."""

    plan_code: str
    billing_interval: str = Field(default="month", pattern=r"^(month|year)$")
    period_end: date | None = None
    note: str | None = Field(default=None, max_length=500)
