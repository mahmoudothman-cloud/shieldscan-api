"""Plan catalog and subscriptions (M12 slice 1; Plans & Billing Review v1.1 §4).

Plans, prices and limits live in the database and are edited by a platform
admin, never in code. Code reads an org's *effective limits* through
``app.services.plans.get_effective_limits`` and never names a tier.

Global reference tables (no tenant column, no RLS — like
``compliance_frameworks``):

* ``plans`` — one row per plan family (free, starter, growth, business,
  enterprise). ``rank`` orders upgrades; ``is_public`` hides design-partner
  plans from the pricing page.
* ``plan_versions`` — a priced snapshot of a plan: gross EGP and USD prices
  (14% VAT inside), billing interval, ``limits`` and ``features`` JSONB,
  processor ids. Editing a plan creates a new version and retires the old
  one; subscriptions keep the version they bought (grandfathering). At most
  one live version per (plan, interval).

Tenant tables (RLS, Gotcha 3):

* ``org_subscriptions`` — exactly one active row per org (partial unique
  index). Free is a real row with ``provider=manual``; an org with no row
  resolves to the live Free version so a missed insert is never a 500.
* ``org_limit_overrides`` — per-org bumps for design partners, enterprise
  contracts, goodwill; applied on top of the version's limits/features.
* ``usage_counters`` — the monthly meter: one row per org × key × period,
  incremented in the same transaction that creates the metered thing.

Limit and feature vocabulary (one set of keys shared by versions, overrides
and counters): see ``app.services.plans.LIMIT_KEYS`` / ``FEATURE_KEYS``.
``-1`` in a limit means unlimited.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum as PyEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TenantMixin, TimestampMixin


class BillingInterval(str, PyEnum):
    MONTH = "month"
    YEAR = "year"


class SubscriptionStatus(str, PyEnum):
    PENDING = "pending"  # checkout started, first payment not confirmed
    TRIALING = "trialing"  # reserved; v1.0 has no trial
    ACTIVE = "active"
    PAST_DUE = "past_due"  # renewal failed, inside grace
    SUSPENDED = "suspended"  # grace exhausted; limits fall to Free
    CANCELED = "canceled"


class BillingProviderName(str, PyEnum):
    MANUAL = "manual"  # Free, design partners, bank-transfer invoices
    PAYMOB = "paymob"
    PADDLE = "paddle"


class Plan(Base, TimestampMixin):
    __tablename__ = "plans"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    code: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Upgrade order. NULL for things that are not a tier (add-on packs, v1.1).
    rank: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    versions: Mapped[list[PlanVersion]] = relationship(
        back_populates="plan", order_by="PlanVersion.version"
    )


class PlanVersion(Base, TimestampMixin):
    __tablename__ = "plan_versions"
    __table_args__ = (
        UniqueConstraint(
            "plan_id", "billing_interval", "version", name="uq_plan_versions_plan_interval_version"
        ),
        # One live version per (plan, interval).
        Index(
            "uq_plan_versions_live",
            "plan_id",
            "billing_interval",
            unique=True,
            postgresql_where="retired_at IS NULL",
        ),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    plan_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("plans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    billing_interval: Mapped[BillingInterval] = mapped_column(
        Enum(
            BillingInterval, name="billing_interval", values_callable=lambda e: [m.value for m in e]
        ),
        nullable=False,
        default=BillingInterval.MONTH,
    )
    # Gross prices (14% VAT inside). Both set explicitly; USD is not an FX
    # conversion of EGP.
    price_egp_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    price_usd_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    limits: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    features: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    paymob_plan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    paddle_price_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    effective_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    change_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    plan: Mapped[Plan] = relationship(back_populates="versions")


class OrgSubscription(Base, TimestampMixin, TenantMixin):
    __tablename__ = "org_subscriptions"
    __table_args__ = (
        # Exactly one non-terminal subscription per org.
        Index(
            "uq_org_subscriptions_one_live",
            "organization_id",
            unique=True,
            postgresql_where="status <> 'canceled'",
        ),
        Index("ix_org_subscriptions_provider_sub", "provider", "provider_subscription_id"),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    plan_version_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("plan_versions.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[SubscriptionStatus] = mapped_column(
        Enum(
            SubscriptionStatus,
            name="subscription_status",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
        default=SubscriptionStatus.ACTIVE,
    )
    provider: Mapped[BillingProviderName] = mapped_column(
        Enum(
            BillingProviderName,
            name="billing_provider",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
        default=BillingProviderName.MANUAL,
    )
    provider_customer_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    provider_subscription_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    current_period_start: Mapped[date] = mapped_column(Date, nullable=False)
    current_period_end: Mapped[date | None] = mapped_column(Date, nullable=True)
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    past_due_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    canceled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    plan_version: Mapped[PlanVersion] = relationship()


class OrgLimitOverride(Base, TimestampMixin, TenantMixin):
    __tablename__ = "org_limit_overrides"
    __table_args__ = (
        UniqueConstraint("organization_id", "key", name="uq_org_limit_overrides_org_key"),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    # JSON scalar or list: an int for limits, bool/list for features.
    value: Mapped[object] = mapped_column(JSONB, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    set_by: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class UsageCounter(Base, TimestampMixin, TenantMixin):
    __tablename__ = "usage_counters"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "key", "period_start", name="uq_usage_counters_org_key_period"
        ),
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    period_start: Mapped[date] = mapped_column(Date, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
