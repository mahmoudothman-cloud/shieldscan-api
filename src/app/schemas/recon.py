"""Pydantic schemas for recon / attack-surface endpoint responses (Task 8.3β).

Response shape canonical authority: SPEC §6.3 Attack Surface Response +
Task 8.3α design doc V-LB acceptance criteria. Consumed by the
``GET /orgs/{org_id}/scans/{scan_id}/attack-surface`` endpoint, which
reads ``AttackSurface`` rows populated by the M8.1β.2 phase-1 recon
dispatch (ADR-028).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SubdomainEntry(BaseModel):
    """Single subdomain entry in attack-surface response (SPEC §6.3).

    ``url`` maps the model's ``full_url`` column; ``status`` carries the
    row-level model fidelity (live / dead / timeout) per Y1 — the
    aggregate live/dead counts on the parent bucket timeout-as-dead, but
    each row reports its true status here.
    """

    model_config = ConfigDict(from_attributes=True)

    url: str
    status: str  # live / dead / timeout (row-level model fidelity per Y1)
    status_code: int | None = None
    tech_stack: list[str] | None = None
    # Y2: SPEC-literal join on the vulnerabilities table; 0 until the M9
    # AI pipeline populates vulnerabilities (forward-pinned).
    vulnerability_count: int = 0
    last_probed_at: datetime | None = None


class AttackSurfaceResponse(BaseModel):
    """Attack-surface response per Task 8.3α design doc V-LB + SPEC §6.3."""

    model_config = ConfigDict(from_attributes=True)

    root_domain: str
    total_discovered: int
    live: int  # Y1: count(status == "live")
    dead: int  # Y1: count(status in {"dead", "timeout"}) — timeout bucketed as dead
    subdomains: list[SubdomainEntry]
