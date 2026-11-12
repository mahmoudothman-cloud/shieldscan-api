"""platform admin flag + plan_versions.created_by (M12 slice 3)

Revision ID: d5e3f0a1b2c4
Revises: c4d2e8f9a1b3
Create Date: 2026-11-12 22:40:00.000000

``users.is_platform_admin`` gates ``/v1/admin/*``. It is never set by
the API: this migration seeds it for the founder's account by email
(``PLATFORM_ADMIN_EMAIL`` env var at migration time, default the demo
login's owner is NOT used — an explicit email only), and later admins
are added by psql. ``plan_versions.created_by`` records who published a
version; the version row is the audit trail for catalog edits.
"""

import os
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "d5e3f0a1b2c4"
down_revision: Union[str, Sequence[str], None] = "c4d2e8f9a1b3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("is_platform_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("plan_versions", sa.Column("created_by", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_plan_versions_created_by_users",
        "plan_versions",
        "users",
        ["created_by"],
        ["id"],
        ondelete="SET NULL",
    )
    email = os.environ.get("PLATFORM_ADMIN_EMAIL", "").strip().lower()
    if email:
        op.execute(
            sa.text(
                "UPDATE users SET is_platform_admin = true WHERE lower(email) = :email"
            ).bindparams(email=email)
        )


def downgrade() -> None:
    op.drop_constraint("fk_plan_versions_created_by_users", "plan_versions", type_="foreignkey")
    op.drop_column("plan_versions", "created_by")
    op.drop_column("users", "is_platform_admin")
