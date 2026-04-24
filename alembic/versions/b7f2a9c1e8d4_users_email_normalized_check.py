"""users.email normalized CHECK constraint (Task 2.5 Commit 1a)

Revision ID: b7f2a9c1e8d4
Revises: 9a4e2c1b7d3f
Create Date: 2026-04-21

Adds a DB-layer CHECK constraint enforcing ``email = lower(email)`` on
the ``users`` table. This is the third layer of defense-in-depth for
email case-normalization:

  1. Pydantic ``@field_validator`` on EmailStr fields (HTTP boundary)
  2. ``register_identity`` defensive normalization (non-HTTP callers)
  3. This CHECK constraint (catches anything that bypasses both)

Bug closed: Pydantic EmailStr only lowercases the domain, leaving the
local part case-sensitive. Without normalization, `Alice@example.com`
and `alice@example.com` are distinct users per the UNIQUE index, and
a user registering as one case but logging in with another gets a
401 lock-out. See DRIFT-LOG 2026-04-21 entry.

No data migration: pre-launch, zero production users. If any dev-db
rows violate the CHECK at upgrade time, the migration will fail
noisily — operator runs `UPDATE users SET email = lower(email)`
manually before retrying.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "b7f2a9c1e8d4"
down_revision: Union[str, Sequence[str], None] = "9a4e2c1b7d3f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_check_constraint(
        "users_email_normalized",
        "users",
        "email = lower(email)",
    )


def downgrade() -> None:
    op.drop_constraint("users_email_normalized", "users", type_="check")
