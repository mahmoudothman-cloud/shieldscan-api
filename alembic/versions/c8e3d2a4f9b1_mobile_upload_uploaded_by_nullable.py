"""mobile_uploads.uploaded_by → nullable for API-key uploads (Task 3.3)

Revision ID: c8e3d2a4f9b1
Revises: b7f2a9c1e8d4
Create Date: 2026-04-26

Rationale: M1 schema declared ``mobile_uploads.uploaded_by`` as
``NOT NULL`` referencing ``users.id``. With Task 3.3 enabling API-key
authentication for the upload endpoint, there is no associated user
for an API-key upload — keys belong to an org, not a user.

This mirrors the precedent established for ``audit_logs.actor_id`` in
Task 2.3.2: actions taken via API key have no user actor, so the
``actor_id`` column was nullable from day one. ``uploaded_by`` should
have followed the same pattern but didn't — this migration corrects
that.

API-layer behavior (see services/audit.py + routes/mobile.py):
  * JWT upload: ``uploaded_by = identity.user.id``,
    audit row ``actor_id = identity.user.id``.
  * API-key upload: ``uploaded_by = NULL``,
    audit row ``actor_id = NULL``,
    ``audit.details.api_key_prefix`` populated.

Downgrade safety: the downgrade restores ``NOT NULL``. If any rows
have ``uploaded_by IS NULL`` at downgrade time (i.e. an API-key
upload landed under this revision), the ALTER will fail with a
clear PG error: ``column "uploaded_by" contains null values``.
This is intentional — silent data loss would be the worse failure
mode. Operator must either (a) delete those rows or (b) backfill
them to a synthetic system user before re-running the downgrade.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "c8e3d2a4f9b1"
down_revision: Union[str, Sequence[str], None] = "b7f2a9c1e8d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "mobile_uploads",
        "uploaded_by",
        nullable=True,
    )


def downgrade() -> None:
    # Will fail loudly if any NULL rows exist — see module docstring.
    op.alter_column(
        "mobile_uploads",
        "uploaded_by",
        nullable=False,
    )
