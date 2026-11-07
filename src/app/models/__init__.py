"""Import model modules so Base.metadata sees every table.

Alembic's autogenerate walks Base.metadata.tables, and those tables only
register when their modules are imported. Keep this list in sync with new
model files under src/app/models/.
"""

from app.models import (  # noqa: F401
    ai,
    audit,
    base,
    compliance,
    identity,
    mobile,
    projects,
    public_scans,
    raw_findings,
    recon,
    reports,
    scans,
    vulnerabilities,
)
