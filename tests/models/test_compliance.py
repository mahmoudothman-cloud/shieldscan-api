"""Compliance model + seed tests (M10.C C1; global reference data).

The compliance tables are GLOBAL reference data (SPEC line 345) — no RLS, no
TenantMixin, NOT in TENANT_TABLES (the deliberate inverse of the M10.B reports
table). These tests pin that inverse + the FK chain + the seed content.

Tests seed via ``seed_compliance_data`` (the runtime copy) because the test
harness builds schema via ``create_all``, not migrations — the migration's own
inline seed is verified out-of-band by ``alembic upgrade``.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.db.policies import TENANT_TABLES
from app.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    CweControlMapping,
)
from app.services.compliance.frameworks import (
    CONTROLS,
    CWE_MAPPINGS,
    seed_compliance_data,
)

_COMPLIANCE_TABLES = {
    "compliance_frameworks",
    "compliance_controls",
    "cwe_control_mappings",
}


def test_compliance_tables_are_global_not_tenant_scoped():
    """The mirror-image of M10.B Catch-1: these tables must be ABSENT from
    TENANT_TABLES — global industry reference data, not RLS-scoped."""
    assert _COMPLIANCE_TABLES & set(TENANT_TABLES) == set(), (
        "a compliance reference table leaked into TENANT_TABLES — global "
        "reference data must NOT be RLS/tenant-scoped (SPEC line 345)"
    )


@pytest.mark.asyncio
async def test_seed_populates_frameworks_controls_mappings(db_session):
    # Global data — no org GUC set. Seeding succeeds without tenant context.
    await seed_compliance_data(db_session)
    await db_session.commit()

    fw = (await db_session.execute(select(func.count(ComplianceFramework.id)))).scalar_one()
    ctl = (await db_session.execute(select(func.count(ComplianceControl.id)))).scalar_one()
    mp = (await db_session.execute(select(func.count(CweControlMapping.id)))).scalar_one()
    assert fw == 4  # soc2 + iso27001 + egypt_pdpl + pci_dss (M14)
    assert ctl == sum(len(v) for v in CONTROLS.values())  # 32 after M14
    assert mp == sum(len(v) for v in CWE_MAPPINGS.values())  # 215 after M14


@pytest.mark.asyncio
async def test_iso_is_2013_and_frameworks_have_slugs(db_session):
    await seed_compliance_data(db_session)
    await db_session.commit()
    iso = (
        await db_session.execute(
            select(ComplianceFramework).where(ComplianceFramework.slug == "iso27001")
        )
    ).scalar_one()
    assert iso.version == "2013"  # matches the acceptance-test control A.14.2.5
    soc2 = (
        await db_session.execute(
            select(ComplianceFramework).where(ComplianceFramework.slug == "soc2")
        )
    ).scalar_one()
    assert soc2.name == "SOC 2"


@pytest.mark.asyncio
async def test_cwe89_maps_to_cc6_1_and_a14_2_5(db_session):
    """The Task 10.5 acceptance case: CWE-89 → SOC2 CC6.1 + ISO A.14.2.5."""
    await seed_compliance_data(db_session)
    await db_session.commit()

    rows = (
        await db_session.execute(
            select(ComplianceFramework.slug, ComplianceControl.control_id)
            .select_from(CweControlMapping)
            .join(ComplianceControl, ComplianceControl.id == CweControlMapping.control_id)
            .join(
                ComplianceFramework,
                ComplianceFramework.id == ComplianceControl.framework_id,
            )
            .where(CweControlMapping.cwe_id == "CWE-89")
        )
    ).all()
    pairs = {(slug, cid) for slug, cid in rows}
    assert ("soc2", "CC6.1") in pairs
    assert ("iso27001", "A.14.2.5") in pairs


@pytest.mark.asyncio
async def test_fk_chain_framework_controls(db_session):
    """framework → controls FK chain resolves."""
    await seed_compliance_data(db_session)
    await db_session.commit()
    soc2 = (
        await db_session.execute(
            select(ComplianceFramework).where(ComplianceFramework.slug == "soc2")
        )
    ).scalar_one()
    soc2_controls = (
        await db_session.execute(
            select(func.count(ComplianceControl.id)).where(
                ComplianceControl.framework_id == soc2.id
            )
        )
    ).scalar_one()
    assert soc2_controls == 6


def test_normalize_cwe_accepts_engine_spellings():
    from app.services.compliance.frameworks import normalize_cwe

    assert normalize_cwe("CWE-89") == "CWE-89"
    assert normalize_cwe("89") == "CWE-89"
    assert normalize_cwe("cwe-200") == "CWE-200"
    assert normalize_cwe("CWE_79") == "CWE-79"
    assert normalize_cwe(" CWE-310 ") == "CWE-310"
    for bad in ("-1", "0", "N/A", "", None, "CWE-"):
        assert normalize_cwe(bad) is None


def test_m14_catalogs_are_complete_and_consistent():
    from app.services.compliance.frameworks import CONTROLS, CWE_MAPPINGS, FRAMEWORKS

    slugs = {f[0] for f in FRAMEWORKS}
    assert slugs == {"soc2", "iso27001", "egypt_pdpl", "pci_dss"}
    keys = {(slug, c[0]) for slug, cs in CONTROLS.items() for c in cs}
    for cwe, targets in CWE_MAPPINGS.items():
        assert cwe.startswith("CWE-") and cwe[4:].isdigit()
        for pair in targets:
            assert pair in keys, (cwe, pair)
    # Every framework has at least one assessable control, and the two
    # new ones carry the articles / requirements the review named.
    for slug in slugs:
        assert any(s == slug for t in CWE_MAPPINGS.values() for s, _ in t)
    pdpl = {c[0] for c in CONTROLS["egypt_pdpl"]}
    assert {"Art.4(6)", "Art.5(7)", "Art.7", "Art.14"} <= pdpl
    pci = {c[0] for c in CONTROLS["pci_dss"]}
    assert {"6.2", "6.4", "4.2", "3.5", "8.3", "11.3"} <= pci


@pytest.mark.asyncio
async def test_legacy_cwe_spellings_hit_controls(db_session):
    """A finding whose cwe_id is "264" or "cwe-200" must fail the same
    controls as "CWE-264" / "CWE-200" (the engines emit both)."""
    from app.services.compliance.frameworks import seed_compliance_data
    from app.services.compliance.mapper import _hit_control_ids

    await seed_compliance_data(db_session)
    canonical = await _hit_control_ids(db_session, {"CWE-264", "CWE-200"})
    legacy = await _hit_control_ids(db_session, {"264", "cwe-200", "-1"})
    assert canonical and canonical == legacy
