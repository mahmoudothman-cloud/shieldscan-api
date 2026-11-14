"""on-prem agents: agents table, projects.agent_id, scan_jobs.agent_id/leased_at, plan v2 with agents.max (M14)

Revision ID: a8b6c3d4e5f7
Revises: f7a5b2c3d4e6
Create Date: 2026-11-14 06:00:00.000000

On-Prem Agent Design v1.0 §4. The ``agents.max`` limit is added to the
catalog by publishing version 2 of growth (1), business (5) and
enterprise (-1) — a copy of the live monthly and annual versions with the
new key — and retiring version 1. Subscribers keep their v1 (resolver
reads a missing key as 0); the admin re-assigns who should get agents.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "a8b6c3d4e5f7"
down_revision: Union[str, Sequence[str], None] = "f7a5b2c3d4e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

AGENTS_MAX = {"growth": 1, "business": 5, "enterprise": -1}


def upgrade() -> None:
    agent_status = postgresql.ENUM(
        "pending", "active", "revoked", name="agent_status", create_type=False
    )
    agent_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "agents",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", agent_status, nullable=False, server_default="pending"),
        sa.Column("enrolment_token_hash", sa.String(length=64), nullable=True),
        sa.Column("enrolment_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("key_prefix", sa.String(length=16), nullable=True),
        sa.Column("key_hash", sa.String(length=64), nullable=True),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.String(length=40), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("platform", sa.String(length=40), nullable=True),
        sa.Column(
            "tools", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_hash"),
    )
    op.create_index(op.f("ix_agents_organization_id"), "agents", ["organization_id"], unique=False)
    # No RLS: credential-indexed table (ADR-012 amendment, see db/policies.py).

    op.add_column("projects", sa.Column("agent_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_projects_agent_id_agents",
        "projects",
        "agents",
        ["agent_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(op.f("ix_projects_agent_id"), "projects", ["agent_id"], unique=False)
    op.add_column("scan_jobs", sa.Column("agent_id", sa.UUID(), nullable=True))
    op.add_column("scan_jobs", sa.Column("leased_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index(op.f("ix_scan_jobs_agent_id"), "scan_jobs", ["agent_id"], unique=False)

    # ---- plan v2 with agents.max
    conn = op.get_bind()
    now = datetime.now(timezone.utc)
    rows = (
        conn.execute(
            sa.text(
                "SELECT v.id, v.plan_id, p.code, v.version, v.billing_interval::text, v.price_egp_cents, "
                "v.price_usd_cents, v.limits, v.features FROM plan_versions v "
                "JOIN plans p ON p.id = v.plan_id WHERE v.retired_at IS NULL AND p.code IN ('growth','business','enterprise')"
            )
        )
        .mappings()
        .all()
    )
    for r in rows:
        limits = dict(r["limits"])
        limits["agents.max"] = AGENTS_MAX[r["code"]]
        conn.execute(
            sa.text(
                "UPDATE plan_versions SET retired_at = CAST(:now AS TIMESTAMPTZ) WHERE id = CAST(:id AS UUID)"
            ),
            {"now": now, "id": r["id"]},
        )
        conn.execute(
            sa.text(
                "INSERT INTO plan_versions (id, plan_id, version, billing_interval, price_egp_cents, price_usd_cents, "
                "limits, features, effective_from, change_note, created_at, updated_at) VALUES "
                "(CAST(:id AS UUID), CAST(:plan AS UUID), :version, CAST(:interval AS billing_interval), :egp, :usd, "
                "CAST(:limits AS JSONB), CAST(:features AS JSONB), CAST(:now AS TIMESTAMPTZ), :note, "
                "CAST(:now AS TIMESTAMPTZ), CAST(:now AS TIMESTAMPTZ))"
            ),
            {
                "id": uuid.uuid4(),
                "plan": r["plan_id"],
                "version": int(r["version"]) + 1,
                "interval": r["billing_interval"],
                "egp": r["price_egp_cents"],
                "usd": r["price_usd_cents"],
                "limits": json.dumps(limits),
                "features": json.dumps(dict(r["features"])),
                "now": now,
                "note": "M14: agents.max added (On-Prem Agent Design v1.0 A6)",
            },
        )


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_jobs_agent_id"), table_name="scan_jobs")
    op.drop_column("scan_jobs", "leased_at")
    op.drop_column("scan_jobs", "agent_id")
    op.drop_index(op.f("ix_projects_agent_id"), table_name="projects")
    op.drop_constraint("fk_projects_agent_id_agents", "projects", type_="foreignkey")
    op.drop_column("projects", "agent_id")
    op.drop_index(op.f("ix_agents_organization_id"), table_name="agents")
    op.drop_table("agents")
    op.execute("DROP TYPE IF EXISTS agent_status;")
    # plan v2 rows are left in place (retiring them would need the v1 rows un-retired; do by hand if ever needed)
