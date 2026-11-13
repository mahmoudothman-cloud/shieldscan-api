"""Compliance catalogs: SOC 2, ISO 27001:2013 (M10.C) + Egypt PDPL and
PCI DSS v4.0.1 (M14, 2026-11-13).

The RUNTIME reference copy of the compliance seed — imported by the posture
mapper and by tests. Each seed migration embeds its own inline copy of the
rows it adds (``a7c3e9f04b21`` for SOC 2 / ISO, ``f7a5b2c3d4e6`` for PDPL /
PCI and the widened CWE map); this module is the union and the two are kept
in sync by authoring the same content.

Representative, NOT exhaustive: the controls are the ones a web-application
scan can say something about. PDPL article numbers follow Law No. 151 of 2020
(English translation, Andersen Egypt, 2026); PCI DSS requirement numbers
follow v4.0.1 (June 2024). CWE ids are normalised ("CWE-89") on both sides of
the join — see ``normalize_cwe``.
"""

from __future__ import annotations

import re

_CWE_RE = re.compile(r"^\s*(?:cwe[-_ ]?)?(\d{1,5})\s*$", re.IGNORECASE)


def normalize_cwe(raw: str | None) -> str | None:
    """ "CWE-89" from any of "89", "cwe-89", "CWE_89", " CWE-89 ". Unknown or
    placeholder values (-1, "N/A", "") become None so they never match."""
    if raw is None:
        return None
    m = _CWE_RE.match(raw)
    if m is None:
        return None
    n = int(m.group(1))
    if n <= 0:
        return None
    return f"CWE-{n}"


# (slug, name, version)
FRAMEWORKS: list[tuple[str, str, str]] = [
    ("soc2", "SOC 2", "2017"),
    ("iso27001", "ISO/IEC 27001", "2013"),
    ("egypt_pdpl", "Egypt Personal Data Protection Law (No. 151/2020)", "2020"),
    ("pci_dss", "PCI DSS", "4.0.1"),
]

# slug -> list of (control_id, title, description)
CONTROLS: dict[str, list[tuple[str, str, str]]] = {
    "soc2": [
        (
            "CC6.1",
            "Logical and Physical Access Controls",
            "Restrict logical access to information assets.",
        ),
        (
            "CC6.6",
            "Boundary Protection",
            "Protect against threats from sources outside system boundaries.",
        ),
        (
            "CC6.7",
            "Data Transmission and Disposal",
            "Protect data during transmission and at rest.",
        ),
        (
            "CC7.1",
            "Vulnerability Detection",
            "Detect and monitor configuration changes and vulnerabilities.",
        ),
        (
            "CC7.2",
            "Security Event Monitoring",
            "Monitor system components for anomalies and security events.",
        ),
        (
            "CC8.1",
            "Change Management",
            "Authorize, design, and implement changes to infrastructure and software.",
        ),
    ],
    "iso27001": [
        (
            "A.9.4.1",
            "Information Access Restriction",
            "Restrict access to information and application functions.",
        ),
        (
            "A.10.1.1",
            "Policy on the Use of Cryptographic Controls",
            "Develop and implement a policy on cryptographic controls.",
        ),
        (
            "A.12.6.1",
            "Management of Technical Vulnerabilities",
            "Obtain timely information about technical vulnerabilities and take action.",
        ),
        (
            "A.13.1.1",
            "Network Controls",
            "Manage and control networks to protect information in systems.",
        ),
        (
            "A.14.2.1",
            "Secure Development Policy",
            "Establish rules for the secure development of software and systems.",
        ),
        (
            "A.14.2.5",
            "Secure System Engineering Principles",
            "Establish and apply secure system engineering principles.",
        ),
    ],
    "egypt_pdpl": [
        (
            "Art.2",
            "Data subject rights",
            "Access, correction, restriction, objection, withdrawal of consent and breach notification rights of the data subject.",
        ),
        (
            "Art.3",
            "Lawful, limited and accurate processing",
            "Personal data is collected for legitimate, specific purposes, kept accurate and retained no longer than needed.",
        ),
        (
            "Art.4(6)",
            "Controller: technical and organisational security measures",
            "The controller takes the technical and organisational measures necessary to protect personal data, its confidentiality, and to prevent breach, tampering or unlawful access.",
        ),
        (
            "Art.5(7)",
            "Processor: protection of processing operations",
            "The processor protects the processing operations and the devices and media used for them.",
        ),
        (
            "Art.7",
            "Breach notification within 72 hours",
            "The Centre is notified of a personal-data breach within 72 hours; affected data subjects within three working days of that.",
        ),
        (
            "Art.8",
            "Data protection officer",
            "A qualified, registered data protection officer is appointed and responsible for compliance.",
        ),
        (
            "Art.12",
            "Sensitive personal data",
            "Sensitive data is processed only under a Centre licence and with explicit written consent.",
        ),
        (
            "Art.13",
            "Security policies for sensitive data",
            "The DPO and staff apply the security policies required for sensitive personal data.",
        ),
        (
            "Art.14",
            "Cross-border transfer",
            "Personal data is transferred abroad only to adequately protected jurisdictions or under a Centre licence.",
        ),
    ],
    "pci_dss": [
        (
            "1.3",
            "Restrict network access to and from the CDE",
            "Inbound and outbound traffic to the cardholder data environment is restricted to what is necessary.",
        ),
        (
            "2.2",
            "Secure configuration of system components",
            "System components are configured and managed securely; vendor defaults and unnecessary services are removed.",
        ),
        (
            "3.5",
            "Stored PAN is rendered unreadable",
            "Primary account numbers are secured wherever stored (hashing, truncation, tokenisation or strong cryptography).",
        ),
        (
            "4.2",
            "Strong cryptography on open, public networks",
            "PAN is protected with strong cryptography during transmission; only trusted keys and certificates, no insecure protocol versions.",
        ),
        (
            "6.2",
            "Bespoke and custom software is developed securely",
            "Software is developed to prevent common attacks (injection, XSS, CSRF, insecure deserialisation, access-control and data-exposure flaws).",
        ),
        (
            "6.3",
            "Security vulnerabilities are identified and addressed",
            "Vulnerabilities in system components and software are identified, ranked and remediated; security patches are applied in time.",
        ),
        (
            "6.4",
            "Public-facing web applications are protected",
            "Public-facing web applications are continually protected against attacks (automated technical solution or reviews).",
        ),
        (
            "7.2",
            "Access to system components and data is appropriately defined",
            "Access is restricted by need to know and least privilege, including application-level access control.",
        ),
        (
            "8.3",
            "Strong authentication for users and administrators",
            "Authentication factors are strong, protected in transit and storage, and defaults are never used.",
        ),
        (
            "10.2",
            "Audit logs capture security events",
            "Audit logs record access to cardholder data and security-relevant events without exposing sensitive data.",
        ),
        (
            "11.3",
            "External and internal vulnerabilities are regularly identified",
            "Vulnerability scans are run at least quarterly and after significant change; high-risk findings are resolved.",
        ),
    ],
}

# cwe_id -> list of (framework_slug, control_id). Normalised ids; the
# mapper normalises the finding side the same way before joining.
_INJECTION = [
    ("soc2", "CC6.1"),
    ("iso27001", "A.14.2.5"),
    ("egypt_pdpl", "Art.4(6)"),
    ("pci_dss", "6.2"),
    ("pci_dss", "6.4"),
]
_ACCESS = [
    ("soc2", "CC6.1"),
    ("iso27001", "A.9.4.1"),
    ("egypt_pdpl", "Art.4(6)"),
    ("pci_dss", "7.2"),
    ("pci_dss", "6.2"),
]
_AUTH = [("soc2", "CC6.1"), ("iso27001", "A.9.4.1"), ("egypt_pdpl", "Art.4(6)"), ("pci_dss", "8.3")]
_CRYPTO_REST = [
    ("soc2", "CC6.7"),
    ("iso27001", "A.10.1.1"),
    ("egypt_pdpl", "Art.4(6)"),
    ("egypt_pdpl", "Art.13"),
    ("pci_dss", "3.5"),
]
_CRYPTO_TRANSIT = [
    ("soc2", "CC6.7"),
    ("iso27001", "A.13.1.1"),
    ("egypt_pdpl", "Art.4(6)"),
    ("egypt_pdpl", "Art.5(7)"),
    ("pci_dss", "4.2"),
]
_EXPOSURE = [
    ("soc2", "CC6.7"),
    ("iso27001", "A.9.4.1"),
    ("egypt_pdpl", "Art.4(6)"),
    ("egypt_pdpl", "Art.3"),
    ("pci_dss", "6.2"),
]
_CONFIG = [
    ("soc2", "CC6.6"),
    ("iso27001", "A.14.2.1"),
    ("egypt_pdpl", "Art.4(6)"),
    ("pci_dss", "2.2"),
]
_PATCHING = [
    ("soc2", "CC7.1"),
    ("iso27001", "A.12.6.1"),
    ("egypt_pdpl", "Art.4(6)"),
    ("pci_dss", "6.3"),
    ("pci_dss", "11.3"),
]
_LOGGING = [
    ("soc2", "CC7.2"),
    ("iso27001", "A.9.4.1"),
    ("egypt_pdpl", "Art.4(6)"),
    ("pci_dss", "10.2"),
]

CWE_MAPPINGS: dict[str, list[tuple[str, str]]] = {
    # injection and input handling
    "CWE-89": _INJECTION,  # SQL injection
    "CWE-79": _INJECTION,  # XSS
    "CWE-78": _INJECTION,  # OS command injection
    "CWE-94": _INJECTION,  # code injection
    "CWE-611": _INJECTION,  # XXE
    "CWE-918": _INJECTION,  # SSRF
    "CWE-352": _INJECTION,  # CSRF
    "CWE-601": _INJECTION,  # open redirect
    "CWE-20": _INJECTION,  # improper input validation
    "CWE-1021": _INJECTION,  # clickjacking (missing frame protection)
    # access control
    "CWE-22": _ACCESS,  # path traversal
    "CWE-264": _ACCESS,  # permissions, privileges, access controls (legacy category)
    "CWE-284": _ACCESS,  # improper access control
    "CWE-285": _ACCESS,  # improper authorization
    "CWE-639": _ACCESS,  # IDOR
    "CWE-434": [
        ("soc2", "CC6.6"),
        ("iso27001", "A.14.2.1"),
        ("egypt_pdpl", "Art.4(6)"),
        ("pci_dss", "6.2"),
        ("pci_dss", "6.4"),
    ],  # unrestricted upload
    # authentication
    "CWE-287": _AUTH,  # improper authentication
    "CWE-306": _AUTH,  # missing authentication
    "CWE-798": _AUTH,  # hard-coded credentials
    "CWE-521": _AUTH,  # weak password requirements
    "CWE-1004": _AUTH,  # cookie without HttpOnly
    "CWE-614": _AUTH,  # cookie without Secure
    # cryptography at rest / in transit
    "CWE-311": _CRYPTO_REST,  # missing encryption
    "CWE-312": _CRYPTO_REST,  # cleartext storage
    "CWE-359": _CRYPTO_REST,  # exposure of private personal information
    "CWE-327": _CRYPTO_REST,  # broken/risky crypto algorithm
    "CWE-310": _CRYPTO_TRANSIT,  # cryptographic issues (legacy category: TLS/SSL findings)
    "CWE-319": _CRYPTO_TRANSIT,  # cleartext transmission
    "CWE-326": _CRYPTO_TRANSIT,  # inadequate encryption strength
    "CWE-295": _CRYPTO_TRANSIT,  # improper certificate validation
    "CWE-345": _CRYPTO_TRANSIT,  # insufficient verification of data authenticity (SRI)
    "CWE-346": _CRYPTO_TRANSIT,  # origin validation error (CORS)
    "CWE-353": _CRYPTO_TRANSIT,  # missing support for integrity check
    # information exposure
    "CWE-200": _EXPOSURE,  # exposure of sensitive information
    "CWE-209": _EXPOSURE,  # error message information leak
    "CWE-497": _EXPOSURE,  # exposure of system data
    "CWE-532": _EXPOSURE + [("pci_dss", "10.2")],  # sensitive information in logs
    "CWE-548": _EXPOSURE,  # directory listing
    # configuration and hardening
    "CWE-16": _CONFIG,  # configuration
    "CWE-525": _CONFIG,  # browser caching of sensitive data
    "CWE-693": _CONFIG,  # protection mechanism failure (missing security headers)
    "CWE-1395": _CONFIG,  # dependency on vulnerable third-party component (also patching)
    # patching
    "CWE-1104": _PATCHING,  # unmaintained third-party components
    "CWE-937": _PATCHING,  # using components with known vulnerabilities
    # logging
    "CWE-778": _LOGGING,  # insufficient logging
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
            db.add(CweControlMapping(cwe_id=cwe_id, control_id=ctl_by_key[(slug, control_id)].id))
    await db.flush()
