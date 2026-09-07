"""Delete the nikto findings that describe an error page rather than a site.

Nikto 2.1.5 cannot negotiate TLS, so against a target on port 443 it spoke
plain HTTP, got nginx's "400 The plain HTTP request was sent to HTTPS port",
and reported that page's headers as findings (engine Drift #71). Those rows
say nothing about the customer's application, and one of them actively
contradicts it: nikto reported "X-Frame-Options header is not present" for a
site that returns "x-frame-options: SAMEORIGIN".

Safe by default: prints what it would do and changes nothing unless --apply
is passed. Re-derives its target set on every run from the artifact itself —
a plain-http:// target_url on port 443 — never from a date or a saved list,
so it is safe to run twice and cannot act on stale analysis.

    python scripts/cleanup_nikto_artifacts.py            # dry run
    python scripts/cleanup_nikto_artifacts.py --apply    # delete

Refuses to act if any vulnerability is backed by BOTH nikto artifacts and
real findings from another tool. See app.services.nikto_artifacts.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from sqlalchemy import select

from app.db import AsyncSessionLocal
from app.db.tenant_context import set_tenant_context
from app.logging_config import configure_logging
from app.models.identity import Organization
from app.services.nikto_artifacts import CLEANUP_REASON, Plan, apply_plan, build_plan

logger = logging.getLogger("cleanup_nikto_artifacts")


async def plan_for_every_org() -> list[tuple[object, Plan]]:
    """Build a plan per organization.

    Organizations are enumerated first because raw_findings and
    vulnerabilities are under FORCE ROW LEVEL SECURITY: with no tenant GUC
    the policy matches nothing, so a cross-org query returns zero rows
    rather than failing. Sweeping org by org makes the scoping explicit.
    """
    async with AsyncSessionLocal() as db:
        org_ids = (await db.execute(select(Organization.id))).scalars().all()

    plans = []
    for org_id in org_ids:
        async with AsyncSessionLocal() as db:
            await set_tenant_context(db, org_id)
            plan = await build_plan(db)
            if plan.raw_finding_ids:
                plans.append((org_id, plan))
    return plans


def report(plans: list) -> None:
    if not plans:
        print("No nikto artifacts found. Nothing to do.")
        return

    total_rf = sum(len(p.raw_finding_ids) for _, p in plans)
    total_pure = sum(len(p.pure_vulnerability_ids) for _, p in plans)
    total_mixed = sum(len(p.mixed_vulnerabilities) for _, p in plans)
    total_scans = sum(len(p.scans_touched) for _, p in plans)

    print(f"{total_rf} nikto raw_finding(s) across {total_scans} scan(s)\n")

    for org_id, plan in plans:
        print(f"  organization {org_id}")
        print("    target_urls (every one is plain HTTP on the TLS port):")
        for url, n in sorted(plan.target_urls.items(), key=lambda kv: -kv[1]):
            print(f"      {n:>4}  {url}")
        print(f"    raw_findings to delete       : {len(plan.raw_finding_ids)}")
        print(f"    vulnerabilities to delete    : {len(plan.pure_vulnerability_ids)}"
              "   (backed by nikto artifacts only)")
        print(f"    vulnerabilities BLOCKING     : {len(plan.mixed_vulnerabilities)}"
              "   (also backed by real findings)")
        for m in plan.mixed_vulnerabilities:
            print(f"      ! {m['severity']:<9} artifacts={m['artifact_rows']} "
                  f"real={m['real_rows']} dangling={m['dangling_rows']} "
                  f"tools={m['tools']}")
            print(f"        {m['vulnerability_id']}  {m['title'][:60]!r}")
        print()

    print(f"Totals: {total_rf} raw_findings, {total_pure} vulnerabilities, "
          f"{total_mixed} blocked.")
    if total_mixed:
        print(
            "\nBLOCKED. Some vulnerabilities cite both a nikto artifact and real\n"
            "findings from another tool. Deleting them loses real data; removing\n"
            "only the nikto ids leaves a promoted vulnerability whose score came\n"
            "from evidence that is now gone. Decide per row, then re-run."
        )


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually delete (default: report only)",
    )
    args = parser.parse_args()

    configure_logging()
    plans = await plan_for_every_org()
    report(plans)

    if not plans:
        return 0
    if any(p.blocked for _, p in plans):
        return 2
    if not args.apply:
        print("\nDry run — nothing written. Re-run with --apply to delete.")
        print(f"Each affected scan will record: {CLEANUP_REASON!r}")
        return 0

    # Re-derive rather than reuse the plan printed above. Between the
    # report and the write a scan may have finished and added rows.
    plans = await plan_for_every_org()
    if any(p.blocked for _, p in plans):
        print("\nA blocking vulnerability appeared between the report and the "
              "write. Nothing deleted; re-run to see it.")
        return 2

    totals = {"vulnerabilities": 0, "raw_findings": 0, "scans_annotated": 0}
    for org_id, plan in plans:
        async with AsyncSessionLocal() as db:
            await set_tenant_context(db, org_id)
            counts = await apply_plan(db, plan)
            await db.commit()
        for k, v in counts.items():
            totals[k] += v

    print(f"\nDeleted {totals['vulnerabilities']} vulnerability(ies) and "
          f"{totals['raw_findings']} raw_finding(s); annotated "
          f"{totals['scans_annotated']} scan(s).")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
