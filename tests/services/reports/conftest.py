"""Fixtures for the report-generator tests (M10.B C2).

Builds an Org→Project→Scan chain under a set tenant GUC so the plain seed
helpers (add_vulnerability / add_raw_finding, imported from
tests/services/ai/conftest per PY7) can persist tenant-scoped rows. Fixtures
live here — they do not cross sibling conftest directories.
"""

from __future__ import annotations

from uuid import uuid4

import pytest_asyncio
from sqlalchemy import text

from app.models.identity import Organization
from app.models.projects import Project
from app.models.scans import Scan, ScanStatus, ScanType


@pytest_asyncio.fixture
async def report_scan(db_session):
    """A committed Org + Project + COMPLETED Scan under an active tenant GUC.

    Returns ``(scan, org, project)`` for the seed helpers.
    """
    org = Organization(name="Report Org", slug=f"rptorg-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await db_session.execute(text(f"SET app.current_org_id = '{org.id}'"))

    project = Project(
        organization_id=org.id,
        name="ReportApp",
        target_url="https://report.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()

    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.COMPLETED,
        priority="normal",
        config={},
        executive_summary="Two findings; one critical SQLi requires immediate attention.",
    )
    db_session.add(scan)
    await db_session.commit()
    return scan, org, project
