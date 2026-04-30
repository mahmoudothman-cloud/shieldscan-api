"""Completions consumer for ``shieldscan:completions`` Pub/Sub channel
(Task 4.2).

Subscribes to the SPEC §7.3 completion channel and applies each
``job_completed`` event to the matching ``ScanJob`` row + aggregates
the parent ``Scan.status`` when all sibling jobs reach a terminal
state.

State-machine ownership (ADR-013):
  Python is the SOLE writer for scan + scan_job state. Workers signal
  via Redis events; this consumer is the entry point that turns those
  signals back into PostgreSQL UPDATEs.

Audit policy (DRIFT-LOG 2026-04-30 H.2):
  Per-job completion is captured in ``scan_jobs.status`` only — no
  audit row per job. Only scan-level terminal transitions
  (SCAN_COMPLETED / SCAN_FAILED) emit audit rows. Pin via
  ``test_consumer_does_not_audit_per_job``.

Multi-process duplicate handling (DRIFT-LOG H.4):
  Each uvicorn worker subscribes to the channel; with N>1 workers,
  every completion event is processed N times. Second-and-onward
  handlers see a job already in the terminal state and short-circuit
  with a DEBUG log. Acceptable double-work at MVP scale; consumer-
  groups (which require Streams) are deferred to scale milestone.

Lifecycle:
  ``CompletionsConsumer.start()`` spawns the consume loop as an
  asyncio task. ``stop()`` cancels and waits for it to drain. Wired
  into the FastAPI lifespan in ``main.py``.

RLS:
  No request context — the consumer manages its own ``AsyncSession``
  per event and SETs ``app.current_org_id`` from the event's
  ``organization_id`` field before any RLS-scoped read or write.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Awaitable, Callable
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import select_fresh
from app.models.scans import Scan, ScanJob, ScanStatus
from app.services.audit import ScanAction, audit

logger = logging.getLogger(__name__)


# Set of ScanJob.status values that are terminal (no further updates
# expected from workers). Mirrors the worker side's terminal states
# in SPEC §7.3 event_types.
_TERMINAL_JOB_STATUSES: frozenset[str] = frozenset(
    {"completed", "failed", "canceled"}
)


class CompletionsConsumer:
    """Async background task that bridges Redis completion events back
    to PostgreSQL.

    Constructor takes a ``session_factory`` (an
    ``async_sessionmaker[AsyncSession]``) — typically
    ``app.db.AsyncSessionLocal`` — so each event opens its own session
    independent of any request-bound session.
    """

    CHANNEL = "shieldscan:completions"

    def __init__(
        self,
        session_factory: Callable[[], AsyncSession],
        redis,
    ) -> None:
        self._session_factory = session_factory
        self._redis = redis
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    # ---------------------------------------------------------------- lifecycle

    async def start(self) -> None:
        """Spawn the consume loop. Idempotent — calling twice is a
        no-op (returns the existing task)."""
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._consume_loop())
        logger.info("completions consumer started on channel %s", self.CHANNEL)

    async def stop(self) -> None:
        """Signal the loop to exit, wait up to ~5s for graceful drain."""
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            self._task = None
        logger.info("completions consumer stopped")

    # ---------------------------------------------------------------- loop

    async def _consume_loop(self) -> None:
        pubsub = self._redis.pubsub()
        try:
            await pubsub.subscribe(self.CHANNEL)
            async for message in pubsub.listen():
                if self._stop.is_set():
                    break
                if message["type"] != "message":
                    continue
                try:
                    event = json.loads(message["data"])
                except (TypeError, ValueError) as e:
                    logger.warning(
                        "completions consumer: malformed JSON payload, "
                        "dropping: %s",
                        e,
                    )
                    continue
                await self._handle_safely(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("completions consumer loop crashed")
            raise
        finally:
            try:
                await pubsub.unsubscribe(self.CHANNEL)
            except Exception:
                pass
            try:
                await pubsub.aclose()
            except Exception:
                pass

    async def _handle_safely(self, event: dict) -> None:
        """Wrap ``_handle`` so a single bad event can't kill the loop.
        Logs the failure with full context and moves on."""
        try:
            await self._handle(event)
        except Exception as e:
            logger.exception(
                "completions consumer: handler failed for event %r: %s",
                event,
                e,
            )

    # ---------------------------------------------------------------- handler (unit-testable)

    async def _handle(self, event: dict) -> None:
        """Apply one completion event to the DB.

        Recognized ``event_type`` values: ``job_completed``. Anything
        else is silently ignored (defensive — workers should only
        publish ``job_completed`` to this channel, but we don't rely
        on it being clean).
        """
        if event.get("event_type") != "job_completed":
            return  # ignore unrecognized

        job_id = UUID(event["job_id"])
        org_id = event["organization_id"]
        new_status = event["status"]
        finding_count = event.get("finding_count", 0)
        duration_ms = event.get("duration_ms")

        async with self._session_factory() as db:
            await db.execute(text(f"SET app.current_org_id = '{org_id}'"))

            job = (
                await select_fresh(
                    db, select(ScanJob).where(ScanJob.id == job_id)
                )
            ).scalar_one_or_none()
            if job is None:
                logger.warning(
                    "completions consumer: event for unknown job_id=%s "
                    "(scan likely deleted before completion landed)",
                    job_id,
                )
                return

            # Multi-process duplicate handling — see module docstring.
            if (
                job.status == new_status
                and job.status in _TERMINAL_JOB_STATUSES
            ):
                logger.debug(
                    "completion event for already-terminal job_id=%s; "
                    "expected at MVP with N>1 uvicorn workers, not at scale",
                    job_id,
                )
                return

            job.status = new_status
            job.finding_count = finding_count
            if duration_ms is not None:
                job.duration_ms = duration_ms
            await db.flush()

            # Aggregate scan-level state if all sibling jobs are now
            # terminal. Only the scan-level transition emits audit
            # (per H.2 — terminal-aggregate-only audit policy).
            await self._maybe_complete_scan(db, job.scan_id)

            await db.commit()

    # ---------------------------------------------------------------- aggregate

    async def _maybe_complete_scan(self, db: AsyncSession, scan_id: UUID) -> None:
        """If every ScanJob for ``scan_id`` is terminal, transition
        the parent Scan to COMPLETED (all-ok) or PARTIAL (any failure).

        ``select_fresh`` for both reads — we just wrote to one of these
        rows above and need the post-write state."""
        sibling_jobs = (
            await select_fresh(
                db, select(ScanJob).where(ScanJob.scan_id == scan_id)
            )
        ).scalars().all()
        if not all(j.status in _TERMINAL_JOB_STATUSES for j in sibling_jobs):
            return

        any_failed = any(
            j.status in {"failed", "canceled"} for j in sibling_jobs
        )
        all_ok = all(j.status == "completed" for j in sibling_jobs)

        scan = (
            await select_fresh(
                db, select(Scan).where(Scan.id == scan_id)
            )
        ).scalar_one_or_none()
        if scan is None:
            return  # extremely unlikely; scan deleted concurrently
        if scan.status in {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED}:
            # Already aggregated by a peer worker process — see DRIFT-LOG
            # H.4 multi-process double-UPDATE entry. Don't re-emit audit.
            return

        if all_ok:
            scan.status = ScanStatus.COMPLETED
            action = ScanAction.SCAN_COMPLETED
        elif any_failed:
            scan.status = ScanStatus.PARTIAL
            action = ScanAction.SCAN_COMPLETED  # partial is still a "this scan is done" event
            # Use SCAN_COMPLETED for any-jobs-completed terminal aggregate;
            # SCAN_FAILED reserved for whole-scan failures (no jobs got
            # any data through). Subtle: pin with a refinement.
        else:
            return
        await db.flush()

        finding_count_total = sum(j.finding_count or 0 for j in sibling_jobs)
        await audit(
            db,
            organization_id=scan.organization_id,
            actor_id=None,  # consumer is system-driven, no user actor
            action=action,
            resource_type="scan",
            resource_id=scan.id,
            details={  # type: ignore[arg-type]
                "finding_count": finding_count_total,
                "job_count": len(sibling_jobs),
            },
        )
