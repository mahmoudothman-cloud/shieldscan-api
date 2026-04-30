"""project_credentials.project_id UNIQUE constraint (Task 3.X)

Revision ID: d4f6b1e9a527
Revises: c8e3d2a4f9b1
Create Date: 2026-04-30

Rationale: Task 3.X's PATCH semantics replace the credential
in-place — exactly one credential per project. M1 schema didn't
declare the UNIQUE(project_id) invariant, so the schema permitted
multiple credential rows for one project (orphan rows on a
SELECT-then-INSERT race). This migration lifts the invariant to
the DB layer so the application can use UPSERT
(``INSERT ... ON CONFLICT (project_id) DO UPDATE``) atomically.

Downgrade safety: restoring the constraint as a UNIQUE INDEX is
trivial; dropping it is harmless. No data migration: pre-launch,
zero production rows. If a dev DB happens to have duplicate
``project_id`` values when this upgrade runs, the migration fails
loudly with a unique-violation — operator dedupes manually.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "d4f6b1e9a527"
down_revision: Union[str, Sequence[str], None] = "c8e3d2a4f9b1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_project_credentials_project_id",
        "project_credentials",
        ["project_id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_project_credentials_project_id",
        "project_credentials",
        type_="unique",
    )
