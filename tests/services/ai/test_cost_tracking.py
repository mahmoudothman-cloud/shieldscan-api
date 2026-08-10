"""Tests for AI cost tracking + budget enforcement (ADR-029 Q2; M9.0 C3.2).

Covers aggregate computation, hybrid pre/post-call budget checks, per-call
logging, per-scan isolation, and the SPEC §8.5 budget regression-guard.
"""

from __future__ import annotations

from decimal import Decimal
from uuid import uuid4

import pytest

from app.models.identity import Organization
from app.models.projects import Project
from app.models.scans import Scan, ScanStatus, ScanType
from app.services.ai import cost_tracking
from tests.conftest import use_org


async def _seed_scan(db_session, *, scan_type=ScanType.FULL_WEB):
    org = Organization(name="Cost Org", slug=f"cost-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    project = Project(
        organization_id=org.id,
        name="CostApp",
        target_url="https://cost.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()
    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=scan_type,
        status=ScanStatus.ANALYZING,
        priority="normal",
        config={},
    )
    db_session.add(scan)
    await db_session.commit()
    return org, scan


@pytest.mark.asyncio
async def test_get_consumed_cost_returns_zero_for_no_calls(db_session):
    _org, scan = await _seed_scan(db_session)
    consumed = await cost_tracking.get_consumed_cost(db=db_session, scan_id=scan.id)
    assert consumed == Decimal("0")


@pytest.mark.asyncio
async def test_log_ai_call_then_aggregate_sum(db_session):
    org, scan = await _seed_scan(db_session)
    for cost in ("0.01", "0.02", "0.03"):
        await cost_tracking.log_ai_call(
            db=db_session,
            organization_id=org.id,
            scan_id=scan.id,
            provider="openai",
            model="text-embedding-3-small",
            operation_type="embedding",
            tokens_in=100,
            tokens_out=None,
            cost_usd=Decimal(cost),
        )
    await db_session.commit()
    consumed = await cost_tracking.get_consumed_cost(db=db_session, scan_id=scan.id)
    assert consumed == Decimal("0.06")


@pytest.mark.asyncio
async def test_check_budget_true_when_within(db_session):
    _org, scan = await _seed_scan(db_session, scan_type=ScanType.FULL_WEB)
    # FULL_WEB budget is 0.75; nothing consumed → permitted.
    assert await cost_tracking.check_budget(
        db=db_session, scan_id=scan.id, scan_type=ScanType.FULL_WEB
    )


@pytest.mark.asyncio
async def test_check_budget_false_when_exceeded(db_session):
    org, scan = await _seed_scan(db_session, scan_type=ScanType.QUICK)
    # QUICK budget is 0.15; log 0.20 → over.
    await cost_tracking.log_ai_call(
        db=db_session,
        organization_id=org.id,
        scan_id=scan.id,
        provider="anthropic",
        model="claude-sonnet-4-6",
        operation_type="fix_generation",
        tokens_in=500,
        tokens_out=800,
        cost_usd=Decimal("0.20"),
    )
    await db_session.commit()
    assert not await cost_tracking.check_budget(
        db=db_session, scan_id=scan.id, scan_type=ScanType.QUICK
    )


@pytest.mark.asyncio
async def test_check_budget_pre_call_estimate_blocks_overrun(db_session):
    """Q2 B.c: pre-call check with an estimate that would breach is denied."""
    _org, scan = await _seed_scan(db_session, scan_type=ScanType.CONTAINER)
    # CONTAINER budget is 0.15; estimate 0.20 → denied pre-call.
    assert not await cost_tracking.check_budget(
        db=db_session,
        scan_id=scan.id,
        scan_type=ScanType.CONTAINER,
        estimated_cost_usd=Decimal("0.20"),
    )


@pytest.mark.asyncio
async def test_summary_budget_reserved_from_fixes(db_session):
    """The executive summary must get its budget regardless of fix count.

    Regression for the live full_web finding (26 findings): fix spend ran the
    FULL_WEB budget down and the summary (which runs last) fell back to the
    template. Fix-generation now gates against ``budget - reserve``, so once
    fix spend reaches that ceiling further fixes are refused while the
    summary — gating against the full budget — is still permitted.
    """
    org, scan = await _seed_scan(db_session, scan_type=ScanType.FULL_WEB)
    budget = cost_tracking.SCAN_TYPE_BUDGETS_USD[ScanType.FULL_WEB]  # 0.75
    reserve = cost_tracking.RESERVED_SUMMARY_BUDGET_USD  # 0.05
    # Consume right up to the fix ceiling (budget - reserve).
    await cost_tracking.log_ai_call(
        db=db_session,
        organization_id=org.id,
        scan_id=scan.id,
        provider="anthropic",
        model="claude-sonnet-4-6",
        operation_type="fix_generation",
        tokens_in=1,
        tokens_out=1,
        cost_usd=budget - reserve,  # 0.70
    )
    await db_session.commit()

    # A further fix is refused — it would eat into the reserved summary slice.
    assert not await cost_tracking.check_budget(
        db=db_session,
        scan_id=scan.id,
        scan_type=ScanType.FULL_WEB,
        estimated_cost_usd=Decimal("0.025"),
        reserve_usd=reserve,
    )
    # The summary is still permitted: 0.70 + 0.05 <= 0.75 (no reserve for it).
    assert await cost_tracking.check_budget(
        db=db_session,
        scan_id=scan.id,
        scan_type=ScanType.FULL_WEB,
        estimated_cost_usd=reserve,
    )


@pytest.mark.asyncio
async def test_log_ai_call_per_scan_isolation(db_session):
    org, scan_a = await _seed_scan(db_session)
    # Second scan in the SAME org so the org GUC stays valid.
    scan_b = Scan(
        organization_id=org.id,
        project_id=scan_a.project_id,
        scan_type=ScanType.FULL_WEB,
        status=ScanStatus.ANALYZING,
        priority="normal",
        config={},
    )
    db_session.add(scan_b)
    await db_session.flush()
    await cost_tracking.log_ai_call(
        db=db_session,
        organization_id=org.id,
        scan_id=scan_a.id,
        provider="openai",
        model="text-embedding-3-small",
        operation_type="embedding",
        tokens_in=100,
        tokens_out=None,
        cost_usd=Decimal("0.04"),
    )
    await db_session.commit()
    assert await cost_tracking.get_consumed_cost(
        db=db_session, scan_id=scan_a.id
    ) == Decimal("0.04")
    assert await cost_tracking.get_consumed_cost(
        db=db_session, scan_id=scan_b.id
    ) == Decimal("0")


def test_scan_type_budgets_cover_all_scan_types():
    """Regression-guard (SPEC §8.5): every non-PUBLIC ScanType has a budget so
    check_budget never hits the 'no budget configured' path for a real scan."""
    for st in ScanType:
        assert st in cost_tracking.SCAN_TYPE_BUDGETS_USD, st


def test_scan_type_budgets_match_spec_8_5():
    # Enforcement caps per SPEC §8.5 "Per-scan AI budget caps" — raised above
    # the typical-spend targets at the live full_web bring-up so rich scans
    # aren't starved. Keep in sync with the SPEC §8.5 table.
    b = cost_tracking.SCAN_TYPE_BUDGETS_USD
    assert b[ScanType.QUICK] == Decimal("0.15")
    assert b[ScanType.FULL_WEB] == Decimal("0.75")
    assert b[ScanType.FULL_WEB_SOURCE] == Decimal("1.00")
    assert b[ScanType.FULL_SPECTRUM] == Decimal("1.50")
    assert b[ScanType.API] == Decimal("0.30")
    assert b[ScanType.MOBILE] == Decimal("0.20")
    assert b[ScanType.CONTAINER] == Decimal("0.15")
    assert b[ScanType.PUBLIC] == Decimal("0.15")
    assert cost_tracking.RESERVED_SUMMARY_BUDGET_USD == Decimal("0.05")
