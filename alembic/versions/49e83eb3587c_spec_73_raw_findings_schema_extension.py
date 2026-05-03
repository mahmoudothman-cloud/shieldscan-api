"""spec_73_raw_findings_schema_extension

Revision ID: 49e83eb3587c
Revises: d4f6b1e9a527
Create Date: 2026-05-03 11:40:17.064268

SPEC §7.3 schema extension (M6-close-followup, ADR-024).

Adds 4 new optional fields to raw_findings:
  - references     ARRAY(String)  — URL/advisory citations
  - tags           ARRAY(String)  — fine-grained tags (distinct
                                    from engine_category)
  - cvss_vector    String(255)    — canonical CVSS:3.1/... string
  - additional_cwes ARRAY(String) — multi-CWE beyond primary cwe_id

All fields nullable; backward-compatible with existing rows.
Reversible via downgrade().

Per ADR-024 "Python ingest scope" subsection: schema columns land
in columns-ready posture. Pydantic schema + CompletionsConsumer
ingest extension deferred to future findings-ingest task.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY


# revision identifiers, used by Alembic.
revision: str = '49e83eb3587c'
down_revision: Union[str, Sequence[str], None] = 'd4f6b1e9a527'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('raw_findings', sa.Column('references', ARRAY(sa.String()), nullable=True))
    op.add_column('raw_findings', sa.Column('tags', ARRAY(sa.String()), nullable=True))
    op.add_column('raw_findings', sa.Column('cvss_vector', sa.String(length=255), nullable=True))
    op.add_column('raw_findings', sa.Column('additional_cwes', ARRAY(sa.String()), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('raw_findings', 'additional_cwes')
    op.drop_column('raw_findings', 'cvss_vector')
    op.drop_column('raw_findings', 'tags')
    op.drop_column('raw_findings', 'references')
