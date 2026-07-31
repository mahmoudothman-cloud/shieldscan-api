"""m10c compliance tables + seed

Revision ID: a7c3e9f04b21
Revises: f1a2b3c4d5e6
Create Date: 2026-07-28 00:00:00.000000

M10.C (Task 10.5): three GLOBAL reference tables (no RLS, no TenantMixin per
SPEC line 345) + the first data/seed migration in the repo. The seed is an
inline literal here (migration-stability: migrations must not import evolving
app code); services/compliance/frameworks.py holds the runtime copy of the
same data. UUIDs are generated at upgrade time and threaded through the FKs
within this one upgrade() run.
"""
import uuid
from datetime import datetime, timezone
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a7c3e9f04b21"
down_revision: Union[str, Sequence[str], None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# --- inline seed literal (kept in sync with services/compliance/frameworks.py) ---
_FRAMEWORKS = [
    ("soc2", "SOC 2", "2017"),
    ("iso27001", "ISO/IEC 27001", "2013"),
]
_CONTROLS = {
    "soc2": [
        ("CC6.1", "Logical and Physical Access Controls", "Restrict logical access to information assets."),
        ("CC6.6", "Boundary Protection", "Protect against threats from sources outside system boundaries."),
        ("CC6.7", "Data Transmission and Disposal", "Protect data during transmission and at rest."),
        ("CC7.1", "Vulnerability Detection", "Detect and monitor configuration changes and vulnerabilities."),
        ("CC7.2", "Security Event Monitoring", "Monitor system components for anomalies and security events."),
        ("CC8.1", "Change Management", "Authorize, design, and implement changes to infrastructure and software."),
    ],
    "iso27001": [
        ("A.9.4.1", "Information Access Restriction", "Restrict access to information and application functions."),
        ("A.10.1.1", "Policy on the Use of Cryptographic Controls", "Develop and implement a policy on cryptographic controls."),
        ("A.12.6.1", "Management of Technical Vulnerabilities", "Obtain timely information about technical vulnerabilities and take action."),
        ("A.13.1.1", "Network Controls", "Manage and control networks to protect information in systems."),
        ("A.14.2.1", "Secure Development Policy", "Establish rules for the secure development of software and systems."),
        ("A.14.2.5", "Secure System Engineering Principles", "Establish and apply secure system engineering principles."),
    ],
}
_CWE_MAPPINGS = {
    "CWE-89": [("soc2", "CC6.1"), ("iso27001", "A.14.2.5")],
    "CWE-79": [("soc2", "CC6.1"), ("iso27001", "A.14.2.5")],
    "CWE-78": [("soc2", "CC6.1"), ("iso27001", "A.14.2.5")],
    "CWE-22": [("soc2", "CC6.1"), ("iso27001", "A.9.4.1")],
    "CWE-287": [("soc2", "CC6.1"), ("iso27001", "A.9.4.1")],
    "CWE-798": [("soc2", "CC6.1"), ("iso27001", "A.9.4.1")],
    "CWE-311": [("soc2", "CC6.7"), ("iso27001", "A.10.1.1")],
    "CWE-312": [("soc2", "CC6.7"), ("iso27001", "A.10.1.1")],
    "CWE-319": [("soc2", "CC6.7"), ("iso27001", "A.13.1.1")],
    "CWE-352": [("soc2", "CC6.1"), ("iso27001", "A.14.2.5")],
    "CWE-434": [("soc2", "CC6.6"), ("iso27001", "A.14.2.1")],
    "CWE-1104": [("soc2", "CC7.1"), ("iso27001", "A.12.6.1")],
}


def upgrade() -> None:
    op.create_table(
        "compliance_frameworks",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("slug", sa.String(length=50), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_table(
        "compliance_controls",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("framework_id", sa.UUID(), nullable=False),
        sa.Column("control_id", sa.String(length=50), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["framework_id"], ["compliance_frameworks.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_compliance_controls_framework_id"),
        "compliance_controls",
        ["framework_id"],
    )
    op.create_table(
        "cwe_control_mappings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("cwe_id", sa.String(length=20), nullable=False),
        sa.Column("control_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["control_id"], ["compliance_controls.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_cwe_control_mappings_cwe_id"), "cwe_control_mappings", ["cwe_id"]
    )
    op.create_index(
        op.f("ix_cwe_control_mappings_control_id"),
        "cwe_control_mappings",
        ["control_id"],
    )

    # --- seed (first data migration in the repo) ---
    now = datetime.now(timezone.utc)
    fw_tbl = sa.table(
        "compliance_frameworks",
        sa.column("id"), sa.column("slug"), sa.column("name"),
        sa.column("version"), sa.column("created_at"), sa.column("updated_at"),
    )
    ctl_tbl = sa.table(
        "compliance_controls",
        sa.column("id"), sa.column("framework_id"), sa.column("control_id"),
        sa.column("title"), sa.column("description"),
        sa.column("created_at"), sa.column("updated_at"),
    )
    map_tbl = sa.table(
        "cwe_control_mappings",
        sa.column("id"), sa.column("cwe_id"), sa.column("control_id"),
        sa.column("created_at"), sa.column("updated_at"),
    )

    fw_id: dict[str, uuid.UUID] = {}
    fw_rows = []
    for slug, name, version in _FRAMEWORKS:
        fid = uuid.uuid4()
        fw_id[slug] = fid
        fw_rows.append(
            {"id": fid, "slug": slug, "name": name, "version": version,
             "created_at": now, "updated_at": now}
        )
    op.bulk_insert(fw_tbl, fw_rows)

    ctl_id: dict[tuple[str, str], uuid.UUID] = {}
    ctl_rows = []
    for slug, controls in _CONTROLS.items():
        for control_id, title, description in controls:
            cid = uuid.uuid4()
            ctl_id[(slug, control_id)] = cid
            ctl_rows.append(
                {"id": cid, "framework_id": fw_id[slug], "control_id": control_id,
                 "title": title, "description": description,
                 "created_at": now, "updated_at": now}
            )
    op.bulk_insert(ctl_tbl, ctl_rows)

    map_rows = []
    for cwe_id, targets in _CWE_MAPPINGS.items():
        for slug, control_id in targets:
            map_rows.append(
                {"id": uuid.uuid4(), "cwe_id": cwe_id,
                 "control_id": ctl_id[(slug, control_id)],
                 "created_at": now, "updated_at": now}
            )
    op.bulk_insert(map_tbl, map_rows)


def downgrade() -> None:
    # drop in reverse FK order — removes the seed with the tables.
    op.drop_index(
        op.f("ix_cwe_control_mappings_control_id"), table_name="cwe_control_mappings"
    )
    op.drop_index(
        op.f("ix_cwe_control_mappings_cwe_id"), table_name="cwe_control_mappings"
    )
    op.drop_table("cwe_control_mappings")
    op.drop_index(
        op.f("ix_compliance_controls_framework_id"), table_name="compliance_controls"
    )
    op.drop_table("compliance_controls")
    op.drop_table("compliance_frameworks")
