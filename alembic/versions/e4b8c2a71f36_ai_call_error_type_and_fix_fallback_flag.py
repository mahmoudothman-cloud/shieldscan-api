"""ai_api_calls.error_type + vulnerabilities.ai_fix_is_fallback

Revision ID: e4b8c2a71f36
Revises: c3e7a15d8b92
Create Date: 2026-08-15

Two columns that make AI-pipeline degradation observable. Both are additive and
nullable/defaulted, so existing rows are unaffected and the change is inert
until the code that writes them is running.

Motivation: an Anthropic credit exhaustion on 2026-08-14 caused every fix
generation and executive summary to fall back to the deterministic template for
34 hours across 9 scans. Nothing surfaced it.

ai_api_calls.error_type
  The failure path logs tokens_in=0, tokens_out=0, cost_usd=0. That is
  indistinguishable from a cheap call, so cost metrics showed a 100%-degraded
  pipeline as free — the spend graph looked healthy precisely BECAUSE nothing
  was working. NULL means the call succeeded; non-NULL carries the provider's
  error type (e.g. invalid_request_error) or the exception class name.

vulnerabilities.ai_fix_is_fallback
  Auditing which fixes were real previously meant matching
  ai_fix_text LIKE '%temporarily unavailable%'. That silently breaks if the
  template wording ever changes, and it cannot distinguish a budget-exhaustion
  fallback from an API-failure one. Scan.ai_pipeline_degraded covers the scan
  level; this is the per-vulnerability equivalent.

BACKFILL: existing rows are left alone deliberately. ai_fix_is_fallback
defaults to false, so the 134 historical placeholder fixes will read as
non-fallback. Backfilling by text match would bake the fragile predicate this
column exists to replace into the migration itself, and the historical answer
is already recorded: see shieldscan-api/DRIFT-LOG.md, entry
"2026-08-15 — Drift #67", which lists the affected scans and per-scan counts.
Rows written from now on are accurate.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e4b8c2a71f36"
down_revision: Union[str, Sequence[str], None] = "c3e7a15d8b92"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "ai_api_calls",
        sa.Column("error_type", sa.String(length=100), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "ai_fix_is_fallback",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("vulnerabilities", "ai_fix_is_fallback")
    op.drop_column("ai_api_calls", "error_type")
