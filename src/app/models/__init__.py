"""Import model modules so Base.metadata sees every table.

Alembic's autogenerate walks Base.metadata.tables, and those tables only
register when their modules are imported. Keep this list in sync with new
model files under src/app/models/.
"""

from app.models import (  # noqa: F401
    audit,
    base,
    identity,
    mobile,
    projects,
    raw_findings,
    recon,
    scans,
    vulnerabilities,
)
