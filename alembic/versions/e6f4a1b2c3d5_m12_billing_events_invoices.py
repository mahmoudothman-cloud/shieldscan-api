"""billing_events + invoices (M12 slice 4)

Revision ID: e6f4a1b2c3d5
Revises: d5e3f0a1b2c4
Create Date: 2026-11-13 00:30:00.000000

``billing_events`` is the webhook idempotency ledger (global).
``invoices`` is one row per processor charge attempt (tenant, RLS).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "e6f4a1b2c3d5"
down_revision: Union[str, Sequence[str], None] = "d5e3f0a1b2c4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # A PENDING (unpaid checkout) row may sit beside the org's live row.
    op.drop_index("uq_org_subscriptions_one_live", table_name="org_subscriptions")
    op.create_index(
        "uq_org_subscriptions_one_live",
        "org_subscriptions",
        ["organization_id"],
        unique=True,
        postgresql_where=sa.text("status NOT IN ('canceled', 'pending')"),
    )
    billing_provider = postgresql.ENUM("manual", "paymob", "paddle", name="billing_provider", create_type=False)
    invoice_status = postgresql.ENUM("paid", "failed", "refunded", name="invoice_status", create_type=False)
    invoice_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "billing_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("provider", billing_provider, nullable=False),
        sa.Column("event_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=True),
        sa.Column("subscription_id", sa.UUID(), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column("outcome", sa.String(length=64), nullable=False, server_default="received"),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider", "event_id", name="uq_billing_events_provider_event"),
    )
    op.create_index(op.f("ix_billing_events_organization_id"), "billing_events", ["organization_id"], unique=False)

    op.create_table(
        "invoices",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("subscription_id", sa.UUID(), nullable=False),
        sa.Column("provider", billing_provider, nullable=False),
        sa.Column("provider_transaction_id", sa.String(length=128), nullable=False),
        sa.Column("status", invoice_status, nullable=False),
        sa.Column("amount_cents", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False, server_default="EGP"),
        sa.Column("vat_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("period_start", sa.Date(), nullable=True),
        sa.Column("period_end", sa.Date(), nullable=True),
        sa.Column("paid_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["subscription_id"], ["org_subscriptions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider", "provider_transaction_id", name="uq_invoices_provider_txn"),
    )
    op.create_index(op.f("ix_invoices_organization_id"), "invoices", ["organization_id"], unique=False)
    op.execute("ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE invoices FORCE ROW LEVEL SECURITY;")
    op.execute(
        "CREATE POLICY tenant_isolation ON invoices "
        "USING (organization_id = current_setting('app.current_org_id')::uuid) "
        "WITH CHECK (organization_id = current_setting('app.current_org_id')::uuid);"
    )


def downgrade() -> None:
    op.drop_index("uq_org_subscriptions_one_live", table_name="org_subscriptions")
    op.create_index(
        "uq_org_subscriptions_one_live",
        "org_subscriptions",
        ["organization_id"],
        unique=True,
        postgresql_where=sa.text("status <> 'canceled'"),
    )
    op.drop_index(op.f("ix_invoices_organization_id"), table_name="invoices")
    op.drop_table("invoices")
    op.drop_index(op.f("ix_billing_events_organization_id"), table_name="billing_events")
    op.drop_table("billing_events")
    op.execute("DROP TYPE IF EXISTS invoice_status;")
