"""Curated SOC 2 + ISO 27001:2013 compliance seed (M10.C; Task 10.5).

The RUNTIME reference copy of the compliance seed — imported by the posture
mapper (C2) and by tests. The Alembic data migration embeds its own inline
copy of this same data (migration-stability discipline: migrations must not
import evolving app code), so this module and the migration are kept in sync
by authoring the same content.

Representative, NOT exhaustive (exhaustive control/CWE coverage is forward-
pinned to post-launch). PCI is omitted at MVP (Enterprise-tier). ISO is the
2013 revision — matching the acceptance-test control A.14.2.5 (the :2022
renumber is a future migration).
"""

from __future__ import annotations

# (slug, name, version)
FRAMEWORKS: list[tuple[str, str, str]] = [
    ("soc2", "SOC 2", "2017"),
    ("iso27001", "ISO/IEC 27001", "2013"),
]

# slug -> list of (control_id, title, description)
CONTROLS: dict[str, list[tuple[str, str, str]]] = {
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

# cwe_id -> list of (framework_slug, control_id)
CWE_MAPPINGS: dict[str, list[tuple[str, str]]] = {
    "CWE-89": [("soc2", "CC6.1"), ("iso27001", "A.14.2.5")],   # SQL injection
    "CWE-79": [("soc2", "CC6.1"), ("iso27001", "A.14.2.5")],   # XSS
    "CWE-78": [("soc2", "CC6.1"), ("iso27001", "A.14.2.5")],   # OS command injection
    "CWE-22": [("soc2", "CC6.1"), ("iso27001", "A.9.4.1")],    # Path traversal
    "CWE-287": [("soc2", "CC6.1"), ("iso27001", "A.9.4.1")],   # Improper authentication
    "CWE-798": [("soc2", "CC6.1"), ("iso27001", "A.9.4.1")],   # Hard-coded credentials
    "CWE-311": [("soc2", "CC6.7"), ("iso27001", "A.10.1.1")],  # Missing encryption
    "CWE-312": [("soc2", "CC6.7"), ("iso27001", "A.10.1.1")],  # Cleartext storage
    "CWE-319": [("soc2", "CC6.7"), ("iso27001", "A.13.1.1")],  # Cleartext transmission
    "CWE-352": [("soc2", "CC6.1"), ("iso27001", "A.14.2.5")],  # CSRF
    "CWE-434": [("soc2", "CC6.6"), ("iso27001", "A.14.2.1")],  # Unrestricted file upload
    "CWE-1104": [("soc2", "CC7.1"), ("iso27001", "A.12.6.1")], # Unmaintained third-party components
}


async def seed_compliance_data(db) -> None:
    """Insert the seed via ORM from the constants above.

    Production seeds via the ``a7c3e9f04b21`` migration's own inline copy; this
    helper is for the test harness (which builds schema via ``create_all``, not
    migrations) and any future reseed tooling. Global reference data — no org
    tenant context (GUC) required.
    """
    from app.models.compliance import (
        ComplianceControl,
        ComplianceFramework,
        CweControlMapping,
    )

    fw_by_slug: dict[str, ComplianceFramework] = {}
    for slug, name, version in FRAMEWORKS:
        fw = ComplianceFramework(slug=slug, name=name, version=version)
        db.add(fw)
        fw_by_slug[slug] = fw
    await db.flush()

    ctl_by_key: dict[tuple[str, str], ComplianceControl] = {}
    for slug, controls in CONTROLS.items():
        for control_id, title, description in controls:
            ctl = ComplianceControl(
                framework_id=fw_by_slug[slug].id,
                control_id=control_id,
                title=title,
                description=description,
            )
            db.add(ctl)
            ctl_by_key[(slug, control_id)] = ctl
    await db.flush()

    for cwe_id, targets in CWE_MAPPINGS.items():
        for slug, control_id in targets:
            db.add(
                CweControlMapping(
                    cwe_id=cwe_id, control_id=ctl_by_key[(slug, control_id)].id
                )
            )
    await db.flush()
