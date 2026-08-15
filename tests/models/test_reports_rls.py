"""Cross-tenant RLS isolation guard for the reports table (M10.B; Gotcha 3).

The reports table is a standard TenantMixin + RLS table (ADR-034) — NOT an
ADR-012 carve-out. This test proves the tenant_isolation policy actually
blocks cross-tenant reads: a row written under org A must be invisible to a
session scoped to org B, and visible to org A.

Reads go through raw SQL (not the ORM) so the identity map can't mask an
RLS-blocked row — mirrors tests/models/test_credential_indexed_rls.py.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import text

from app.models.identity import Organization
from app.models.projects import Project
from app.models.reports import Report, ReportFormat
from app.models.scans import Scan, ScanStatus, ScanType
from app.db.tenant_context import set_tenant_context


def test_report_format_persists_db_valid_lowercase_values():
    """Regression (5th live-bring-up finding): the reports.format column MUST
    persist the enum VALUE (lowercase "pdf"/"sarif"/"json"), matching the
    report_format DB type created by migration f1a2b3c4d5e6 — NOT the member
    NAME ("PDF").

    SQLAlchemy's Enum defaults to the member NAME. Without values_callable the
    stored-PDF path (generate_or_get_pdf_report) sends "PDF" to the lowercase
    DB enum → asyncpg InvalidTextRepresentationError → report/pdf 500. JSON and
    SARIF are rendered on-demand and never persisted, so they were unaffected.
    The test harness builds schema via create_all (from this model), so the bug
    was invisible to tests until it hit the migration-built prod enum.
    """
    enum_type = Report.__table__.c.format.type
    assert enum_type.values_callable is not None, (
        "reports.format must map enum→value (lowercase), not the default name"
    )
    assert enum_type.values_callable(ReportFormat) == ["pdf", "sarif", "json"]
    # And the enum values themselves are the DB-valid lowercase labels.
    assert [e.value for e in ReportFormat] == ["pdf", "sarif", "json"]


@pytest.mark.asyncio
async def test_reports_cross_tenant_read_blocked(db_session):
    """A report row under org A is invisible to org B, visible to org A."""
    # Two orgs (organizations is not tenant-scoped — no GUC needed here).
    org_a = Organization(name="Org A", slug=f"orga-{uuid4().hex[:8]}")
    org_b = Organization(name="Org B", slug=f"orgb-{uuid4().hex[:8]}")
    db_session.add_all([org_a, org_b])
    await db_session.flush()

    # Seed org A's chain under org A's tenant context (RLS WITH CHECK).
    await set_tenant_context(db_session, org_a.id)
    project = Project(
        organization_id=org_a.id,
        name="RptApp",
        target_url="https://rpt.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()
    scan = Scan(
        organization_id=org_a.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.COMPLETED,
        priority="normal",
        config={},
    )
    db_session.add(scan)
    await db_session.flush()
    report = Report(
        organization_id=org_a.id,
        scan_id=scan.id,
        format=ReportFormat.PDF,
        r2_key=f"reports/{scan.id}/{uuid4()}.pdf",
        size_bytes=12345,
        generated_at=datetime.now(timezone.utc),
    )
    db_session.add(report)
    await db_session.commit()

    # Org B cannot see the row — RLS blocks it.
    await set_tenant_context(db_session, org_b.id)
    blocked = (
        await db_session.execute(
            text("SELECT id FROM reports WHERE id = :rid"), {"rid": report.id}
        )
    ).first()
    assert blocked is None, "org B read an org-A report row — RLS is not isolating"

    # Org A can see it.
    await set_tenant_context(db_session, org_a.id)
    visible = (
        await db_session.execute(
            text("SELECT id FROM reports WHERE id = :rid"), {"rid": report.id}
        )
    ).first()
    assert visible is not None, "org A cannot read its own report row"
    assert visible[0] == report.id
