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
    assert fw == 2  # soc2 + iso27001
    assert ctl == 12
    assert mp == sum(len(v) for v in CWE_MAPPINGS.values())  # 24


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
            .join(
                ComplianceControl, ComplianceControl.id == CweControlMapping.control_id
            )
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
