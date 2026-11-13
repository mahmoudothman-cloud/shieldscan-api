"""m14 Egypt PDPL + PCI DSS catalogs; widened CWE map (M14)

Revision ID: f7a5b2c3d4e6
Revises: e6f4a1b2c3d5
Create Date: 2026-11-13 02:30:00.000000

Inline literal, generated from services/compliance/frameworks.py (kept in
sync by authoring the same content — migration-stability discipline, as
a7c3e9f04b21). Adds two frameworks with their controls, and every
(cwe, framework, control) mapping that does not already exist — the
map was widened for the four frameworks to the CWE ids the engines
actually emit. Idempotent: re-running inserts nothing.
"""

import uuid
from datetime import datetime, timezone
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f7a5b2c3d4e6"
down_revision: Union[str, Sequence[str], None] = "e6f4a1b2c3d5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NEW_FRAMEWORKS = [
    ("egypt_pdpl", "Egypt Personal Data Protection Law (No. 151/2020)", "2020"),
    ("pci_dss", "PCI DSS", "4.0.1"),
]

NEW_CONTROLS = {
    "egypt_pdpl": [
        (
            "Art.2",
            "Data subject rights",
            "Access, correction, restriction, objection, withdrawal of consent and breach "
            "notification rights of the data subject.",
        ),
        (
            "Art.3",
            "Lawful, limited and accurate processing",
            "Personal data is collected for legitimate, specific purposes, kept accurate and "
            "retained no longer than needed.",
        ),
        (
            "Art.4(6)",
            "Controller: technical and organisational security measures",
            "The controller takes the technical and organisational measures necessary to "
            "protect personal data, its confidentiality, and to prevent breach, tampering or "
            "unlawful access.",
        ),
        (
            "Art.5(7)",
            "Processor: protection of processing operations",
            "The processor protects the processing operations and the devices and media used "
            "for them.",
        ),
        (
            "Art.7",
            "Breach notification within 72 hours",
            "The Centre is notified of a personal-data breach within 72 hours; affected data "
            "subjects within three working days of that.",
        ),
        (
            "Art.8",
            "Data protection officer",
            "A qualified, registered data protection officer is appointed and responsible for "
            "compliance.",
        ),
        (
            "Art.12",
            "Sensitive personal data",
            "Sensitive data is processed only under a Centre licence and with explicit "
            "written consent.",
        ),
        (
            "Art.13",
            "Security policies for sensitive data",
            "The DPO and staff apply the security policies required for sensitive personal data.",
        ),
        (
            "Art.14",
            "Cross-border transfer",
            "Personal data is transferred abroad only to adequately protected jurisdictions "
            "or under a Centre licence.",
        ),
    ],
    "pci_dss": [
        (
            "1.3",
            "Restrict network access to and from the CDE",
            "Inbound and outbound traffic to the cardholder data environment is restricted to "
            "what is necessary.",
        ),
        (
            "2.2",
            "Secure configuration of system components",
            "System components are configured and managed securely; vendor defaults and "
            "unnecessary services are removed.",
        ),
        (
            "3.5",
            "Stored PAN is rendered unreadable",
            "Primary account numbers are secured wherever stored (hashing, truncation, "
            "tokenisation or strong cryptography).",
        ),
        (
            "4.2",
            "Strong cryptography on open, public networks",
            "PAN is protected with strong cryptography during transmission; only trusted keys "
            "and certificates, no insecure protocol versions.",
        ),
        (
            "6.2",
            "Bespoke and custom software is developed securely",
            "Software is developed to prevent common attacks (injection, XSS, CSRF, insecure "
            "deserialisation, access-control and data-exposure flaws).",
        ),
        (
            "6.3",
            "Security vulnerabilities are identified and addressed",
            "Vulnerabilities in system components and software are identified, ranked and "
            "remediated; security patches are applied in time.",
        ),
        (
            "6.4",
            "Public-facing web applications are protected",
            "Public-facing web applications are continually protected against attacks (automated "
            "technical solution or reviews).",
        ),
        (
            "7.2",
            "Access to system components and data is appropriately defined",
            "Access is restricted by need to know and least privilege, including "
            "application-level access control.",
        ),
        (
            "8.3",
            "Strong authentication for users and administrators",
            "Authentication factors are strong, protected in transit and storage, and defaults "
            "are never used.",
        ),
        (
            "10.2",
            "Audit logs capture security events",
            "Audit logs record access to cardholder data and security-relevant events without "
            "exposing sensitive data.",
        ),
        (
            "11.3",
            "External and internal vulnerabilities are regularly identified",
            "Vulnerability scans are run at least quarterly and after significant change; "
            "high-risk findings are resolved.",
        ),
    ],
}

# (cwe_id, framework_slug, control_id) — the full map; existing rows are skipped.
MAPPINGS = [
    ("CWE-89", "soc2", "CC6.1"),
    ("CWE-89", "iso27001", "A.14.2.5"),
    ("CWE-89", "egypt_pdpl", "Art.4(6)"),
    ("CWE-89", "pci_dss", "6.2"),
    ("CWE-89", "pci_dss", "6.4"),
    ("CWE-79", "soc2", "CC6.1"),
    ("CWE-79", "iso27001", "A.14.2.5"),
    ("CWE-79", "egypt_pdpl", "Art.4(6)"),
    ("CWE-79", "pci_dss", "6.2"),
    ("CWE-79", "pci_dss", "6.4"),
    ("CWE-78", "soc2", "CC6.1"),
    ("CWE-78", "iso27001", "A.14.2.5"),
    ("CWE-78", "egypt_pdpl", "Art.4(6)"),
    ("CWE-78", "pci_dss", "6.2"),
    ("CWE-78", "pci_dss", "6.4"),
    ("CWE-94", "soc2", "CC6.1"),
    ("CWE-94", "iso27001", "A.14.2.5"),
    ("CWE-94", "egypt_pdpl", "Art.4(6)"),
    ("CWE-94", "pci_dss", "6.2"),
    ("CWE-94", "pci_dss", "6.4"),
    ("CWE-611", "soc2", "CC6.1"),
    ("CWE-611", "iso27001", "A.14.2.5"),
    ("CWE-611", "egypt_pdpl", "Art.4(6)"),
    ("CWE-611", "pci_dss", "6.2"),
    ("CWE-611", "pci_dss", "6.4"),
    ("CWE-918", "soc2", "CC6.1"),
    ("CWE-918", "iso27001", "A.14.2.5"),
    ("CWE-918", "egypt_pdpl", "Art.4(6)"),
    ("CWE-918", "pci_dss", "6.2"),
    ("CWE-918", "pci_dss", "6.4"),
    ("CWE-352", "soc2", "CC6.1"),
    ("CWE-352", "iso27001", "A.14.2.5"),
    ("CWE-352", "egypt_pdpl", "Art.4(6)"),
    ("CWE-352", "pci_dss", "6.2"),
    ("CWE-352", "pci_dss", "6.4"),
    ("CWE-601", "soc2", "CC6.1"),
    ("CWE-601", "iso27001", "A.14.2.5"),
    ("CWE-601", "egypt_pdpl", "Art.4(6)"),
    ("CWE-601", "pci_dss", "6.2"),
    ("CWE-601", "pci_dss", "6.4"),
    ("CWE-20", "soc2", "CC6.1"),
    ("CWE-20", "iso27001", "A.14.2.5"),
    ("CWE-20", "egypt_pdpl", "Art.4(6)"),
    ("CWE-20", "pci_dss", "6.2"),
    ("CWE-20", "pci_dss", "6.4"),
    ("CWE-1021", "soc2", "CC6.1"),
    ("CWE-1021", "iso27001", "A.14.2.5"),
    ("CWE-1021", "egypt_pdpl", "Art.4(6)"),
    ("CWE-1021", "pci_dss", "6.2"),
    ("CWE-1021", "pci_dss", "6.4"),
    ("CWE-22", "soc2", "CC6.1"),
    ("CWE-22", "iso27001", "A.9.4.1"),
    ("CWE-22", "egypt_pdpl", "Art.4(6)"),
    ("CWE-22", "pci_dss", "7.2"),
    ("CWE-22", "pci_dss", "6.2"),
    ("CWE-264", "soc2", "CC6.1"),
    ("CWE-264", "iso27001", "A.9.4.1"),
    ("CWE-264", "egypt_pdpl", "Art.4(6)"),
    ("CWE-264", "pci_dss", "7.2"),
    ("CWE-264", "pci_dss", "6.2"),
    ("CWE-284", "soc2", "CC6.1"),
    ("CWE-284", "iso27001", "A.9.4.1"),
    ("CWE-284", "egypt_pdpl", "Art.4(6)"),
    ("CWE-284", "pci_dss", "7.2"),
    ("CWE-284", "pci_dss", "6.2"),
    ("CWE-285", "soc2", "CC6.1"),
    ("CWE-285", "iso27001", "A.9.4.1"),
    ("CWE-285", "egypt_pdpl", "Art.4(6)"),
    ("CWE-285", "pci_dss", "7.2"),
    ("CWE-285", "pci_dss", "6.2"),
    ("CWE-639", "soc2", "CC6.1"),
    ("CWE-639", "iso27001", "A.9.4.1"),
    ("CWE-639", "egypt_pdpl", "Art.4(6)"),
    ("CWE-639", "pci_dss", "7.2"),
    ("CWE-639", "pci_dss", "6.2"),
    ("CWE-434", "soc2", "CC6.6"),
    ("CWE-434", "iso27001", "A.14.2.1"),
    ("CWE-434", "egypt_pdpl", "Art.4(6)"),
    ("CWE-434", "pci_dss", "6.2"),
    ("CWE-434", "pci_dss", "6.4"),
    ("CWE-287", "soc2", "CC6.1"),
    ("CWE-287", "iso27001", "A.9.4.1"),
    ("CWE-287", "egypt_pdpl", "Art.4(6)"),
    ("CWE-287", "pci_dss", "8.3"),
    ("CWE-306", "soc2", "CC6.1"),
    ("CWE-306", "iso27001", "A.9.4.1"),
    ("CWE-306", "egypt_pdpl", "Art.4(6)"),
    ("CWE-306", "pci_dss", "8.3"),
    ("CWE-798", "soc2", "CC6.1"),
    ("CWE-798", "iso27001", "A.9.4.1"),
    ("CWE-798", "egypt_pdpl", "Art.4(6)"),
    ("CWE-798", "pci_dss", "8.3"),
    ("CWE-521", "soc2", "CC6.1"),
    ("CWE-521", "iso27001", "A.9.4.1"),
    ("CWE-521", "egypt_pdpl", "Art.4(6)"),
    ("CWE-521", "pci_dss", "8.3"),
    ("CWE-1004", "soc2", "CC6.1"),
    ("CWE-1004", "iso27001", "A.9.4.1"),
    ("CWE-1004", "egypt_pdpl", "Art.4(6)"),
    ("CWE-1004", "pci_dss", "8.3"),
    ("CWE-614", "soc2", "CC6.1"),
    ("CWE-614", "iso27001", "A.9.4.1"),
    ("CWE-614", "egypt_pdpl", "Art.4(6)"),
    ("CWE-614", "pci_dss", "8.3"),
    ("CWE-311", "soc2", "CC6.7"),
    ("CWE-311", "iso27001", "A.10.1.1"),
    ("CWE-311", "egypt_pdpl", "Art.4(6)"),
    ("CWE-311", "egypt_pdpl", "Art.13"),
    ("CWE-311", "pci_dss", "3.5"),
    ("CWE-312", "soc2", "CC6.7"),
    ("CWE-312", "iso27001", "A.10.1.1"),
    ("CWE-312", "egypt_pdpl", "Art.4(6)"),
    ("CWE-312", "egypt_pdpl", "Art.13"),
    ("CWE-312", "pci_dss", "3.5"),
    ("CWE-359", "soc2", "CC6.7"),
    ("CWE-359", "iso27001", "A.10.1.1"),
    ("CWE-359", "egypt_pdpl", "Art.4(6)"),
    ("CWE-359", "egypt_pdpl", "Art.13"),
    ("CWE-359", "pci_dss", "3.5"),
    ("CWE-327", "soc2", "CC6.7"),
    ("CWE-327", "iso27001", "A.10.1.1"),
    ("CWE-327", "egypt_pdpl", "Art.4(6)"),
    ("CWE-327", "egypt_pdpl", "Art.13"),
    ("CWE-327", "pci_dss", "3.5"),
    ("CWE-310", "soc2", "CC6.7"),
    ("CWE-310", "iso27001", "A.13.1.1"),
    ("CWE-310", "egypt_pdpl", "Art.4(6)"),
    ("CWE-310", "egypt_pdpl", "Art.5(7)"),
    ("CWE-310", "pci_dss", "4.2"),
    ("CWE-319", "soc2", "CC6.7"),
    ("CWE-319", "iso27001", "A.13.1.1"),
    ("CWE-319", "egypt_pdpl", "Art.4(6)"),
    ("CWE-319", "egypt_pdpl", "Art.5(7)"),
    ("CWE-319", "pci_dss", "4.2"),
    ("CWE-326", "soc2", "CC6.7"),
    ("CWE-326", "iso27001", "A.13.1.1"),
    ("CWE-326", "egypt_pdpl", "Art.4(6)"),
    ("CWE-326", "egypt_pdpl", "Art.5(7)"),
    ("CWE-326", "pci_dss", "4.2"),
    ("CWE-295", "soc2", "CC6.7"),
    ("CWE-295", "iso27001", "A.13.1.1"),
    ("CWE-295", "egypt_pdpl", "Art.4(6)"),
    ("CWE-295", "egypt_pdpl", "Art.5(7)"),
    ("CWE-295", "pci_dss", "4.2"),
    ("CWE-345", "soc2", "CC6.7"),
    ("CWE-345", "iso27001", "A.13.1.1"),
    ("CWE-345", "egypt_pdpl", "Art.4(6)"),
    ("CWE-345", "egypt_pdpl", "Art.5(7)"),
    ("CWE-345", "pci_dss", "4.2"),
    ("CWE-346", "soc2", "CC6.7"),
    ("CWE-346", "iso27001", "A.13.1.1"),
    ("CWE-346", "egypt_pdpl", "Art.4(6)"),
    ("CWE-346", "egypt_pdpl", "Art.5(7)"),
    ("CWE-346", "pci_dss", "4.2"),
    ("CWE-353", "soc2", "CC6.7"),
    ("CWE-353", "iso27001", "A.13.1.1"),
    ("CWE-353", "egypt_pdpl", "Art.4(6)"),
    ("CWE-353", "egypt_pdpl", "Art.5(7)"),
    ("CWE-353", "pci_dss", "4.2"),
    ("CWE-200", "soc2", "CC6.7"),
    ("CWE-200", "iso27001", "A.9.4.1"),
    ("CWE-200", "egypt_pdpl", "Art.4(6)"),
    ("CWE-200", "egypt_pdpl", "Art.3"),
    ("CWE-200", "pci_dss", "6.2"),
    ("CWE-209", "soc2", "CC6.7"),
    ("CWE-209", "iso27001", "A.9.4.1"),
    ("CWE-209", "egypt_pdpl", "Art.4(6)"),
    ("CWE-209", "egypt_pdpl", "Art.3"),
    ("CWE-209", "pci_dss", "6.2"),
    ("CWE-497", "soc2", "CC6.7"),
    ("CWE-497", "iso27001", "A.9.4.1"),
    ("CWE-497", "egypt_pdpl", "Art.4(6)"),
    ("CWE-497", "egypt_pdpl", "Art.3"),
    ("CWE-497", "pci_dss", "6.2"),
    ("CWE-532", "soc2", "CC6.7"),
    ("CWE-532", "iso27001", "A.9.4.1"),
    ("CWE-532", "egypt_pdpl", "Art.4(6)"),
    ("CWE-532", "egypt_pdpl", "Art.3"),
    ("CWE-532", "pci_dss", "6.2"),
    ("CWE-532", "pci_dss", "10.2"),
    ("CWE-548", "soc2", "CC6.7"),
    ("CWE-548", "iso27001", "A.9.4.1"),
    ("CWE-548", "egypt_pdpl", "Art.4(6)"),
    ("CWE-548", "egypt_pdpl", "Art.3"),
    ("CWE-548", "pci_dss", "6.2"),
    ("CWE-16", "soc2", "CC6.6"),
    ("CWE-16", "iso27001", "A.14.2.1"),
    ("CWE-16", "egypt_pdpl", "Art.4(6)"),
    ("CWE-16", "pci_dss", "2.2"),
    ("CWE-525", "soc2", "CC6.6"),
    ("CWE-525", "iso27001", "A.14.2.1"),
    ("CWE-525", "egypt_pdpl", "Art.4(6)"),
    ("CWE-525", "pci_dss", "2.2"),
    ("CWE-693", "soc2", "CC6.6"),
    ("CWE-693", "iso27001", "A.14.2.1"),
    ("CWE-693", "egypt_pdpl", "Art.4(6)"),
    ("CWE-693", "pci_dss", "2.2"),
    ("CWE-1395", "soc2", "CC6.6"),
    ("CWE-1395", "iso27001", "A.14.2.1"),
    ("CWE-1395", "egypt_pdpl", "Art.4(6)"),
    ("CWE-1395", "pci_dss", "2.2"),
    ("CWE-1104", "soc2", "CC7.1"),
    ("CWE-1104", "iso27001", "A.12.6.1"),
    ("CWE-1104", "egypt_pdpl", "Art.4(6)"),
    ("CWE-1104", "pci_dss", "6.3"),
    ("CWE-1104", "pci_dss", "11.3"),
    ("CWE-937", "soc2", "CC7.1"),
    ("CWE-937", "iso27001", "A.12.6.1"),
    ("CWE-937", "egypt_pdpl", "Art.4(6)"),
    ("CWE-937", "pci_dss", "6.3"),
    ("CWE-937", "pci_dss", "11.3"),
    ("CWE-778", "soc2", "CC7.2"),
    ("CWE-778", "iso27001", "A.9.4.1"),
    ("CWE-778", "egypt_pdpl", "Art.4(6)"),
    ("CWE-778", "pci_dss", "10.2"),
]


def upgrade() -> None:
    conn = op.get_bind()
    now = datetime.now(timezone.utc)
    for slug, name, version in NEW_FRAMEWORKS:
        exists = conn.execute(
            sa.text("SELECT id FROM compliance_frameworks WHERE slug = :slug"), {"slug": slug}
        ).scalar()
        if exists is None:
            conn.execute(
                sa.text(
                    "INSERT INTO compliance_frameworks (id, slug, name, version, created_at, updated_at) "
                    "VALUES (:id, :slug, :name, :version, :now, :now)"
                ),
                {"id": uuid.uuid4(), "slug": slug, "name": name, "version": version, "now": now},
            )
    for slug, controls in NEW_CONTROLS.items():
        fw_id = conn.execute(
            sa.text("SELECT id FROM compliance_frameworks WHERE slug = :slug"), {"slug": slug}
        ).scalar()
        for control_id, title, description in controls:
            exists = conn.execute(
                sa.text(
                    "SELECT id FROM compliance_controls WHERE framework_id = :fw AND control_id = :cid"
                ),
                {"fw": fw_id, "cid": control_id},
            ).scalar()
            if exists is None:
                conn.execute(
                    sa.text(
                        "INSERT INTO compliance_controls "
                        "(id, framework_id, control_id, title, description, created_at, updated_at) "
                        "VALUES (:id, :fw, :cid, :title, :desc, :now, :now)"
                    ),
                    {
                        "id": uuid.uuid4(),
                        "fw": fw_id,
                        "cid": control_id,
                        "title": title,
                        "desc": description,
                        "now": now,
                    },
                )
    for cwe_id, slug, control_id in MAPPINGS:
        conn.execute(
            sa.text(
                "INSERT INTO cwe_control_mappings (id, cwe_id, control_id, created_at, updated_at) "
                "SELECT :id, :cwe, c.id, :now, :now FROM compliance_controls c "
                "JOIN compliance_frameworks f ON f.id = c.framework_id "
                "WHERE f.slug = :slug AND c.control_id = :cid "
                "AND NOT EXISTS (SELECT 1 FROM cwe_control_mappings m WHERE m.cwe_id = :cwe AND m.control_id = c.id)"
            ),
            {"id": uuid.uuid4(), "cwe": cwe_id, "slug": slug, "cid": control_id, "now": now},
        )


def downgrade() -> None:
    conn = op.get_bind()
    # Remove the two frameworks (controls and mappings cascade) and the
    # widened mappings on the original two; the a7c3e9f04b21 seed stays.
    conn.execute(
        sa.text("DELETE FROM compliance_frameworks WHERE slug IN ('egypt_pdpl', 'pci_dss')")
    )
    for cwe_id, slug, control_id in MAPPINGS:
        if slug in ("soc2", "iso27001") and cwe_id not in (
            "CWE-89",
            "CWE-79",
            "CWE-78",
            "CWE-22",
            "CWE-287",
            "CWE-798",
            "CWE-311",
            "CWE-312",
            "CWE-319",
            "CWE-352",
            "CWE-434",
            "CWE-1104",
        ):
            conn.execute(
                sa.text(
                    "DELETE FROM cwe_control_mappings m USING compliance_controls c, compliance_frameworks f "
                    "WHERE m.control_id = c.id AND c.framework_id = f.id AND m.cwe_id = :cwe "
                    "AND f.slug = :slug AND c.control_id = :cid"
                ),
                {"cwe": cwe_id, "slug": slug, "cid": control_id},
            )
