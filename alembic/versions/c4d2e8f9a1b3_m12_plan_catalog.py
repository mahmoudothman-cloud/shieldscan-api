"""plan catalog, subscriptions, overrides, usage counters (M12 slice 1)

Revision ID: c4d2e8f9a1b3
Revises: b7c3e9d1a2f4
Create Date: 2026-11-11 19:00:00.000000

Plans & Billing Review v1.1 §4. Seeds the §3 ladder as version 1 of
each plan (monthly for all, annual for the paid ones) and gives every
existing organization an ACTIVE Free subscription BEFORE row-level
security is switched on for the tenant tables (FORCE RLS would block
the seed otherwise). New orgs get their Free row at registration.
"""
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from app.services.plans import default_ladder_rows

# revision identifiers, used by Alembic.
revision: str = "c4d2e8f9a1b3"
down_revision: Union[str, Sequence[str], None] = "b7c3e9d1a2f4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TENANT = ("org_subscriptions", "org_limit_overrides", "usage_counters")


def _rls(table: str) -> None:
    # Mirrors app.db.policies.rls_upgrade_sql() exactly.
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
    op.execute(
        f"CREATE POLICY tenant_isolation ON {table} "
        "USING (organization_id = current_setting('app.current_org_id')::uuid) "
        "WITH CHECK (organization_id = current_setting('app.current_org_id')::uuid);"
    )


def upgrade() -> None:
    billing_interval = postgresql.ENUM("month", "year", name="billing_interval", create_type=False)
    subscription_status = postgresql.ENUM(
        "pending", "trialing", "active", "past_due", "suspended", "canceled",
        name="subscription_status", create_type=False,
    )
    billing_provider = postgresql.ENUM("manual", "paymob", "paddle", name="billing_provider", create_type=False)
    bind = op.get_bind()
    billing_interval.create(bind, checkfirst=True)
    subscription_status.create(bind, checkfirst=True)
    billing_provider.create(bind, checkfirst=True)

    op.create_table(
        "plans",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("code", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("rank", sa.Integer(), nullable=True),
        sa.Column("is_public", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code"),
    )

    op.create_table(
        "plan_versions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("plan_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("billing_interval", billing_interval, nullable=False),
        sa.Column("price_egp_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("price_usd_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("limits", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column("features", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column("paymob_plan_id", sa.String(length=64), nullable=True),
        sa.Column("paddle_price_id", sa.String(length=64), nullable=True),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("change_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["plan_id"], ["plans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "plan_id", "billing_interval", "version", name="uq_plan_versions_plan_interval_version"
        ),
    )
    op.create_index(op.f("ix_plan_versions_plan_id"), "plan_versions", ["plan_id"], unique=False)
    op.create_index(
        "uq_plan_versions_live",
        "plan_versions",
        ["plan_id", "billing_interval"],
        unique=True,
        postgresql_where=sa.text("retired_at IS NULL"),
    )

    op.create_table(
        "org_subscriptions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("plan_version_id", sa.UUID(), nullable=False),
        sa.Column("status", subscription_status, nullable=False),
        sa.Column("provider", billing_provider, nullable=False),
        sa.Column("provider_customer_id", sa.String(length=128), nullable=True),
        sa.Column("provider_subscription_id", sa.String(length=128), nullable=True),
        sa.Column("current_period_start", sa.Date(), nullable=False),
        sa.Column("current_period_end", sa.Date(), nullable=True),
        sa.Column("cancel_at_period_end", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("trial_ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("past_due_since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("canceled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["plan_version_id"], ["plan_versions.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_org_subscriptions_organization_id"), "org_subscriptions", ["organization_id"], unique=False
    )
    op.create_index(
        "uq_org_subscriptions_one_live",
        "org_subscriptions",
        ["organization_id"],
        unique=True,
        postgresql_where=sa.text("status <> 'canceled'"),
    )
    op.create_index(
        "ix_org_subscriptions_provider_sub",
        "org_subscriptions",
        ["provider", "provider_subscription_id"],
        unique=False,
    )

    op.create_table(
        "org_limit_overrides",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("set_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["set_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "key", name="uq_org_limit_overrides_org_key"),
    )
    op.create_index(
        op.f("ix_org_limit_overrides_organization_id"), "org_limit_overrides", ["organization_id"], unique=False
    )

    op.create_table(
        "usage_counters",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "key", "period_start", name="uq_usage_counters_org_key_period"),
    )
    op.create_index(
        op.f("ix_usage_counters_organization_id"), "usage_counters", ["organization_id"], unique=False
    )

    # ---- seed the ladder
    now = datetime.now(timezone.utc)
    plans, versions = default_ladder_rows(now)
    for v in versions:  # ORM enum member -> the DB label the plain ENUM column expects
        v["billing_interval"] = v["billing_interval"].value
    plans_t = sa.table(
        "plans",
        sa.column("id", sa.UUID()),
        sa.column("code", sa.String()),
        sa.column("name", sa.String()),
        sa.column("description", sa.Text()),
        sa.column("rank", sa.Integer()),
        sa.column("is_public", sa.Boolean()),
        sa.column("archived_at", sa.DateTime(timezone=True)),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    versions_t = sa.table(
        "plan_versions",
        sa.column("id", sa.UUID()),
        sa.column("plan_id", sa.UUID()),
        sa.column("version", sa.Integer()),
        sa.column("billing_interval", billing_interval),
        sa.column("price_egp_cents", sa.Integer()),
        sa.column("price_usd_cents", sa.Integer()),
        sa.column("limits", postgresql.JSONB()),
        sa.column("features", postgresql.JSONB()),
        sa.column("paymob_plan_id", sa.String()),
        sa.column("paddle_price_id", sa.String()),
        sa.column("effective_from", sa.DateTime(timezone=True)),
        sa.column("retired_at", sa.DateTime(timezone=True)),
        sa.column("change_note", sa.Text()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(plans_t, plans)
    op.bulk_insert(versions_t, versions)

    # ---- every existing org on Free (before RLS is enabled on the table)
    free_version_id = next(
        v["id"] for v in versions if v["plan_id"] == next(p["id"] for p in plans if p["code"] == "free")
    )
    period_start = now.date().replace(day=1)
    op.execute(
        sa.text(
            "INSERT INTO org_subscriptions "
            "(id, organization_id, plan_version_id, status, provider, current_period_start, "
            " cancel_at_period_end, created_at, updated_at) "
            "SELECT gen_random_uuid(), o.id, :fv, 'active', 'manual', :ps, false, :now, :now "
            "FROM organizations o"
        ).bindparams(fv=free_version_id, ps=period_start, now=now)
    )

    for table in _TENANT:
        _rls(table)


def downgrade() -> None:
    op.drop_index(op.f("ix_usage_counters_organization_id"), table_name="usage_counters")
    op.drop_table("usage_counters")
    op.drop_index(op.f("ix_org_limit_overrides_organization_id"), table_name="org_limit_overrides")
    op.drop_table("org_limit_overrides")
    op.drop_index("ix_org_subscriptions_provider_sub", table_name="org_subscriptions")
    op.drop_index("uq_org_subscriptions_one_live", table_name="org_subscriptions")
    op.drop_index(op.f("ix_org_subscriptions_organization_id"), table_name="org_subscriptions")
    op.drop_table("org_subscriptions")
    op.drop_index("uq_plan_versions_live", table_name="plan_versions")
    op.drop_index(op.f("ix_plan_versions_plan_id"), table_name="plan_versions")
    op.drop_table("plan_versions")
    op.drop_table("plans")
    op.execute("DROP TYPE IF EXISTS billing_provider;")
    op.execute("DROP TYPE IF EXISTS subscription_status;")
    op.execute("DROP TYPE IF EXISTS billing_interval;")
