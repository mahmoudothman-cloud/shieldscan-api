"""Compliance posture mapper (M10.C; Task 10.5; ADR-none).

Three-state posture over the CWE→control map (G2.1):
  - ``fail``          — ≥1 of the scan's vulnerability CWEs maps to the control.
  - ``pass``          — the control HAS CWE mappings, but none of the scan's
                        vulnerabilities hit it.
  - ``not_assessed``  — the control has NO CWE mapping at all, so a vulnerability
                        scan cannot assess it. Never claimed as ``pass`` —
                        honesty for a compliance artifact.

Join path: ``Vulnerability.cwe_id`` → ``cwe_control_mappings`` → ``compliance_controls``.
Tenant scoping is enforced by RLS (the request's org GUC) on the Vulnerability
reads; the compliance tables themselves are global (no RLS).
"""

from __future__ import annotations

from enum import Enum
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    CweControlMapping,
)
from app.models.vulnerabilities import Vulnerability, VulnerabilityStatus
from app.services.compliance.frameworks import normalize_cwe


class ControlState(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_ASSESSED = "not_assessed"


class FrameworkNotFoundError(LookupError):
    """Raised when a framework slug does not resolve to a seeded framework."""


async def _assessable_control_ids(db: AsyncSession) -> set[UUID]:
    """Control ids that have ≥1 CWE mapping (across all frameworks)."""
    return set((await db.execute(select(CweControlMapping.control_id).distinct())).scalars().all())


def _control_state(control_id: UUID, hit: set[UUID], assessable: set[UUID]) -> ControlState:
    if control_id in hit:
        return ControlState.FAIL
    if control_id in assessable:
        return ControlState.PASS
    return ControlState.NOT_ASSESSED


def _summarise(states: list[ControlState]) -> dict[str, int]:
    return {
        "pass": sum(s is ControlState.PASS for s in states),
        "fail": sum(s is ControlState.FAIL for s in states),
        "not_assessed": sum(s is ControlState.NOT_ASSESSED for s in states),
        "total": len(states),
    }


async def _hit_control_ids(db: AsyncSession, cwes: set[str]) -> set[UUID]:
    # Findings carry CWE ids in whatever form the engine emitted ("264",
    # "cwe-200", "CWE-310", "-1"); the map is keyed by the normalised form.
    cwes = {n for n in (normalize_cwe(c) for c in cwes if c is not None) if n is not None}
    if not cwes:
        return set()
    return set(
        (
            await db.execute(
                select(CweControlMapping.control_id).where(CweControlMapping.cwe_id.in_(cwes))
            )
        )
        .scalars()
        .all()
    )


async def compute_scan_posture(*, db: AsyncSession, scan_id: UUID, framework_slug: str) -> dict:
    """Per-control three-state posture for one scan against one framework."""
    framework = (
        await db.execute(
            select(ComplianceFramework).where(ComplianceFramework.slug == framework_slug)
        )
    ).scalar_one_or_none()
    if framework is None:
        raise FrameworkNotFoundError(framework_slug)

    controls = (
        (
            await db.execute(
                select(ComplianceControl).where(ComplianceControl.framework_id == framework.id)
            )
        )
        .scalars()
        .all()
    )

    scan_cwes = set(
        (
            await db.execute(
                select(Vulnerability.cwe_id).where(
                    Vulnerability.scan_id == scan_id,
                    Vulnerability.cwe_id.is_not(None),
                )
            )
        )
        .scalars()
        .all()
    )
    hit = await _hit_control_ids(db, scan_cwes)
    assessable = await _assessable_control_ids(db)

    control_results = []
    states = []
    for c in controls:
        state = _control_state(c.id, hit, assessable)
        states.append(state)
        control_results.append({"control_id": c.control_id, "title": c.title, "state": state.value})

    return {
        "framework": {
            "slug": framework.slug,
            "name": framework.name,
            "version": framework.version,
        },
        "scan_id": str(scan_id),
        "controls": control_results,
        "summary": _summarise(states),
    }


async def compute_org_posture(*, db: AsyncSession, org_id: UUID) -> dict:
    """Org-wide worst-state-per-control aggregate.

    A control fails org-wide iff any of the org's OPEN vulnerabilities maps to
    it — the worst-state aggregate collapses to a single org-wide CWE set.

    Only ``status == open`` counts (M11): a control must stop failing once the
    team resolves the finding or marks it a false positive, otherwise the
    posture page can never show progress and "accepted risk" has no meaning.
    All scans still contribute (an open row on an older scan is still open
    work); cross-scan dedup is the follow-up logged in DRIFT-LOG 2026-11-07.
    """
    org_cwes = set(
        (
            await db.execute(
                select(Vulnerability.cwe_id).where(
                    Vulnerability.organization_id == org_id,
                    Vulnerability.status == VulnerabilityStatus.OPEN,
                    Vulnerability.superseded_by_id.is_(None),
                    Vulnerability.cwe_id.is_not(None),
                )
            )
        )
        .scalars()
        .all()
    )
    hit = await _hit_control_ids(db, org_cwes)
    assessable = await _assessable_control_ids(db)

    frameworks = (await db.execute(select(ComplianceFramework))).scalars().all()

    framework_results = []
    for framework in frameworks:
        controls = (
            (
                await db.execute(
                    select(ComplianceControl).where(ComplianceControl.framework_id == framework.id)
                )
            )
            .scalars()
            .all()
        )
        states = [_control_state(c.id, hit, assessable) for c in controls]
        framework_results.append(
            {
                "slug": framework.slug,
                "name": framework.name,
                "version": framework.version,
                "controls": [
                    {"control_id": c.control_id, "title": c.title, "state": s.value}
                    for c, s in zip(controls, states)
                ],
                "summary": _summarise(states),
            }
        )

    return {"organization_id": str(org_id), "frameworks": framework_results}
