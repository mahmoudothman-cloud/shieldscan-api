"""Mark the scan jobs whose workers died before reporting them as failed.

One-shot recovery for jobs stranded before the engine's reliable-queue
hand-off existed (engine Drift #70). A stranded job sits at ``queued``
forever, so its parent scan never aggregates, so ``_maybe_complete_scan``
never fires — and the raw findings its SIBLING jobs already produced are
never analysed. Failing the stranded job releases all of that: this is
recovery of compute already spent, not tidying up a wrong status.

Safe by default: prints what it would do and changes nothing unless
``--apply`` is passed. Re-derives the stranded set every run (see
``app.services.stranded_jobs`` for the ghost test), so a stale list from
an earlier investigation can never be acted on, and so it is safe to run
twice.

    python scripts/backfill_stranded_jobs.py            # dry run
    python scripts/backfill_stranded_jobs.py --apply    # write

The events it replays go through the ordinary CompletionsConsumer path,
so Python remains the sole writer of scan state (ADR-013).
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
from app.redis_client import close_redis, init_redis
from app.services.completions_consumer import CompletionsConsumer
from app.services.stranded_jobs import (
    StrandedJob,
    fail_stranded_jobs,
    find_stranded_jobs,
    payload_index,
)

logger = logging.getLogger("backfill_stranded_jobs")


async def collect(redis) -> tuple[list[StrandedJob], set[str]]:
    """Return every stranded job across every organization.

    Organizations are enumerated first because ``scan_jobs`` is under
    FORCE ROW LEVEL SECURITY: with no tenant GUC set the policy matches
    nothing, so a cross-org query would silently return zero rows rather
    than fail. Sweeping org by org makes the scoping explicit.
    """
    present = await payload_index(redis)

    async with AsyncSessionLocal() as db:
        org_ids = (await db.execute(select(Organization.id))).scalars().all()

    stranded: list[StrandedJob] = []
    for org_id in org_ids:
        async with AsyncSessionLocal() as db:
            await set_tenant_context(db, org_id)
            stranded.extend(await find_stranded_jobs(db, present))
    return stranded, present


def report(stranded: list[StrandedJob]) -> None:
    if not stranded:
        print("No stranded jobs. Nothing to do.")
        return

    by_scan: dict[str, list[StrandedJob]] = {}
    for job in stranded:
        by_scan.setdefault(str(job.scan_id), []).append(job)

    print(f"{len(stranded)} stranded job(s) across {len(by_scan)} scan(s):\n")
    for scan_id, jobs in sorted(by_scan.items()):
        print(f"  scan {scan_id}")
        for job in sorted(jobs, key=lambda j: j.engine):
            print(f"    {job.engine:<10} {job.status:<8} job={job.job_id}")
    print()


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually mark the jobs failed (default: report only)",
    )
    args = parser.parse_args()

    configure_logging()
    redis = await init_redis()
    try:
        stranded, present = await collect(redis)
        logger.info(
            "backfill: %d payload(s) live in Redis; %d stranded job(s) found",
            len(present),
            len(stranded),
        )
        report(stranded)

        if not stranded:
            return 0
        if not args.apply:
            print("Dry run — nothing written. Re-run with --apply to mark these failed.")
            return 0

        # Re-derive rather than reuse the list above. Between the report
        # and the write a worker may have picked one up; the second read
        # narrows that window to the loop below.
        stranded, _ = await collect(redis)

        consumer = CompletionsConsumer(session_factory=AsyncSessionLocal, redis=redis)
        applied = await fail_stranded_jobs(consumer, stranded)
        print(f"Marked {applied}/{len(stranded)} stranded job(s) failed.")
        return 0 if applied == len(stranded) else 1
    finally:
        await close_redis()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
