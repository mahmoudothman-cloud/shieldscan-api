"""Recovery for scan jobs whose worker died without reporting them.

A worker used to take a job off the queue with BRPOP, which destroys the
payload. From that moment the only copy lived in the worker's memory, so
a crash — SIGKILL, an unhandled signal, a host reboot — destroyed the job
outright. Nothing ever emitted a completion event for it, and because
Python is the sole writer of scan state (ADR-013) nothing ever moved the
row off ``queued``. Its parent scan then waited forever for a sibling
that was never coming, so ``_maybe_complete_scan`` never fired and the
findings its OTHER jobs had already produced were never analysed.

The engine now checks jobs out into a per-worker processing list and
reclaims them when the worker's heartbeat is gone (engine Drift #70), so
no NEW job can be stranded this way. This module is for the ones stranded
before that landed.

**The ghost test.** Non-terminal status in PostgreSQL is NOT sufficient:
a job legitimately waiting in the queue also reads ``queued``. What
separates a ghost from a pending job is that its payload no longer exists
anywhere in Redis — neither on a priority queue nor in any worker's
processing list. That test is the reason this module reads Redis at all,
and ``payload_index`` is the single place it is written.

Two properties are deliberate:

* **Evaluated when it runs, never from a snapshot.** The set of stranded
  jobs is re-derived at call time. A list captured during an
  investigation goes stale the moment a scan finishes or a worker picks
  something up, and acting on a stale list would fail live work.
* **A distinct error_message.** These jobs are marked failed with
  ``STRANDED_ERROR_MESSAGE``, so they stay separable from jobs a tool
  genuinely failed. Without it the recovery would be indistinguishable
  from the thing it is recovering from.

ADR-013 is intact. Nothing here writes scan state directly: each stranded
job is turned into the ``job_completed`` event its worker never sent, and
handed to the ordinary ``CompletionsConsumer`` path — which is also what
makes the parent scan aggregate, and what dispatches the AI pipeline over
findings that have been sitting unanalysed.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final, Iterable
from uuid import UUID

from sqlalchemy import select

from app.models.scans import ScanJob
from app.services.scan_queue import ScanQueue

logger = logging.getLogger(__name__)

# Job-dispatch list keys, per priority. Mirrors ScanQueue's own prefix;
# the priorities come from ScanQueue so the two cannot drift.
_QUEUE_KEY_PREFIX: Final[str] = "shieldscan:queue:"

# Per-worker, per-priority in-flight lists the engine writes
# (shieldscan:processing:{worker_id}:{priority}). A payload here belongs
# to a job a worker is holding right now — emphatically not a ghost.
_PROCESSING_KEY_PREFIX: Final[str] = "shieldscan:processing:"

# ScanJob statuses that mean "still expected to report".
NON_TERMINAL_JOB_STATUSES: Final[frozenset[str]] = frozenset({"queued", "running"})

# The reason written to scan_jobs.error_message. Distinct on purpose: a
# query for genuine tool failures must be able to exclude these.
STRANDED_ERROR_MESSAGE: Final[str] = (
    "stranded: the worker holding this job died before it reported, and the "
    "destructive queue hand-off in use at the time destroyed the job payload "
    "with it. Marked failed by backfill; not retried. See engine Drift #70."
)


@dataclass(frozen=True)
class StrandedJob:
    """One job that can never report for itself."""

    job_id: UUID
    scan_id: UUID
    organization_id: UUID
    engine: str
    idempotency_key: str
    status: str


async def payload_index(redis) -> set[str]:
    """Every ``idempotency_key`` whose payload still exists in Redis.

    Reads both halves of the keyspace a job payload can live in: the four
    priority dispatch lists, and every worker's processing lists. A key
    in this set belongs to a job that is queued or actively running, and
    must not be touched.

    Read once per sweep rather than per job — the lists are short (bounded
    by pending work plus WORKER_CONCURRENCY per worker) and a single read
    gives every job the same consistent view.
    """
    list_keys: list[str] = [f"{_QUEUE_KEY_PREFIX}{p}" for p in ScanQueue.PRIORITIES]

    async for key in redis.scan_iter(match=f"{_PROCESSING_KEY_PREFIX}*"):
        list_keys.append(key.decode() if isinstance(key, bytes) else key)

    present: set[str] = set()
    for list_key in list_keys:
        for raw in await redis.lrange(list_key, 0, -1):
            if isinstance(raw, bytes):
                raw = raw.decode(errors="replace")
            try:
                payload = json.loads(raw)
            except (TypeError, ValueError):
                # An undecodable payload is somebody else's problem (the
                # engine logs it). It cannot be matched to a job, so it
                # cannot protect one either.
                logger.warning(
                    "stranded-job sweep: undecodable payload on %s; ignoring",
                    list_key,
                )
                continue
            key = payload.get("idempotency_key")
            if key:
                present.add(key)
    return present


async def find_stranded_jobs(db, present: set[str]) -> list[StrandedJob]:
    """Non-terminal jobs whose payload is absent from Redis.

    The caller MUST have established the RLS tenant context for the
    organization being swept (``set_tenant_context``); this query is
    org-scoped by the policy, not by a WHERE clause.
    """
    rows = (
        await db.execute(
            select(ScanJob).where(ScanJob.status.in_(sorted(NON_TERMINAL_JOB_STATUSES)))
        )
    ).scalars().all()

    return [
        StrandedJob(
            job_id=job.id,
            scan_id=job.scan_id,
            organization_id=job.organization_id,
            engine=job.engine,
            idempotency_key=job.idempotency_key,
            status=job.status,
        )
        for job in rows
        if job.idempotency_key not in present
    ]


def failure_event(job: StrandedJob) -> dict:
    """The ``job_completed`` event this job's worker never sent.

    Shaped exactly like a worker-emitted terminal failure (SPEC §7.3) so
    it takes the ordinary consumer path: ScanJob goes terminal, the
    parent scan aggregates, and any findings its siblings produced reach
    the AI pipeline.
    """
    return {
        "event_type": "job_completed",
        "job_id": str(job.job_id),
        "scan_id": str(job.scan_id),
        "organization_id": str(job.organization_id),
        "engine": job.engine,
        "status": "failed",
        "finding_count": 0,
        "duration_ms": 0,
        "idempotency_key": job.idempotency_key,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event_seq": {"index": 1, "total": 1},
        "error_message": STRANDED_ERROR_MESSAGE,
    }


async def fail_stranded_jobs(consumer, jobs: Iterable[StrandedJob]) -> int:
    """Mark each job failed by replaying the event that never arrived.

    Returns how many were applied. Errors on one job are logged and the
    sweep continues: a single unwritable row must not strand the rest,
    which is the failure mode this whole module exists to undo.
    """
    applied = 0
    for job in jobs:
        try:
            await consumer.apply_event(failure_event(job))
        except Exception:  # noqa: BLE001 — deliberately broad; see docstring
            logger.exception(
                "stranded-job backfill: could not fail job_id=%s scan_id=%s",
                job.job_id,
                job.scan_id,
            )
            continue
        applied += 1
        logger.info(
            "stranded-job backfill: failed job_id=%s scan_id=%s engine=%s "
            "previous_status=%s",
            job.job_id,
            job.scan_id,
            job.engine,
            job.status,
        )
    return applied
