"""AI Pipeline Consumer — in-api long-running BRPOP-loop task (ADR-029 Phase-1).

M9.0 Stage 3 C2.1. Mirrors ``CompletionsConsumer`` lifecycle (V-JJG): idempotent
``start``, ``stop`` with bounded drain, and a resilient consume loop where a single
bad message can't kill the loop. Distinct transport: this consumes a Redis *list*
queue via BRPOP (``shieldscan:ai_pipeline``), not a Pub/Sub channel (V-JJF).

Flow per scan (ADR-029 Q1 + DQ2 + DQ5):
  1. dispatch_ai_pipeline has already set the scan ANALYZING + emitted
     SCAN_DISPATCHED_AI_PIPELINE + LPUSHed {scan_id, organization_id}.
  2. This consumer sets the RLS GUC from the payload org_id, loads the scan,
     and processes only if it is still ANALYZING (idempotency guard for
     re-delivered messages).
  3. Runs the AI pipeline (M9.A embed+dedup; ADR-030), then re-derives the
     terminal status
     from sibling ScanJobs (DQ2) — COMPLETED if all jobs completed, else
     PARTIAL — and emits the SCAN_COMPLETED audit (relocated here per DQ5).
  4. On failure: a fresh session marks the scan FAILED + ai_pipeline_degraded
     (Q8) so a pipeline crash can never strand a scan in ANALYZING.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


from app.db.tenant_context import set_tenant_context
from app.models.scans import Scan, ScanJob, ScanStatus
from app.services.ai.pipeline import run
from app.services.audit import ScanAction, audit

logger = logging.getLogger(__name__)

_TERMINAL_OK = "completed"
_TERMINAL_FAILED = {"failed", "canceled"}


class AIPipelineConsumer:
    """Drains ``shieldscan:ai_pipeline`` and runs the AI pipeline per scan."""

    QUEUE = "shieldscan:ai_pipeline"
    _BRPOP_TIMEOUT = 1  # seconds; bounds stop-event latency

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
        """Spawn the consume loop. Idempotent (V-JJG CompletionsConsumer parity)."""
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._consume_loop())
        logger.info("ai-pipeline consumer started on queue %s", self.QUEUE)

    async def stop(self) -> None:
        """Signal the loop to exit; wait up to ~5s for graceful drain."""
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            self._task = None
        logger.info("ai-pipeline consumer stopped")

    # ---------------------------------------------------------------- loop

    async def _consume_loop(self) -> None:
        try:
            while not self._stop.is_set():
                msg = await self._redis.brpop(self.QUEUE, timeout=self._BRPOP_TIMEOUT)
                if msg is None:
                    continue  # timeout tick — re-check stop event
                try:
                    payload = json.loads(msg[1])
                except (TypeError, ValueError) as e:
                    logger.warning(
                        "ai-pipeline consumer: malformed payload, dropping: %s", e
                    )
                    continue
                await self._handle_safely(payload)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("ai-pipeline consumer loop crashed")
            raise

    async def _handle_safely(self, payload: dict) -> None:
        """Wrap ``_process`` so one bad message can't kill the loop."""
        try:
            await self._process(payload)
        except Exception:
            logger.exception(
                "ai-pipeline consumer: processing failed for payload=%s", payload
            )

    # ---------------------------------------------------------------- handler

    async def _process(self, payload: dict) -> None:
        scan_id = UUID(payload["scan_id"])
        org_uuid = UUID(payload["organization_id"])

        try:
            async with self._session_factory() as db:
                # RLS preamble — org_uuid is a validated UUID (safe f-string),
                # matching the completions_consumer convention.
                await set_tenant_context(db, org_uuid)
                await self._run_pipeline_and_finalize(db, scan_id)
        except Exception as exc:
            logger.exception(
                "ai-pipeline failed for scan_id=%s — marking FAILED + degraded",
                scan_id,
            )
            await self._fail_scan(scan_id, org_uuid, error=str(exc))

    async def _run_pipeline_and_finalize(
        self, db: AsyncSession, scan_id: UUID
    ) -> None:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            logger.warning("ai-pipeline: scan %s vanished; skipping", scan_id)
            return
        # Idempotency guard (DQ4): only ANALYZING scans are ours to finalize.
        if scan.status != ScanStatus.ANALYZING:
            logger.info(
                "ai-pipeline: scan %s not ANALYZING (status=%s); skipping",
                scan_id,
                scan.status,
            )
            return

        # M9.A real pipeline: embed + dedup + Path C promotion (ADR-030).
        await run(db=db, scan_id=scan_id)

        # DQ2: re-derive terminal status from sibling ScanJobs.
        jobs = (
            await db.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
        ).scalars().all()
        any_failed = any(j.status in _TERMINAL_FAILED for j in jobs)
        scan.status = ScanStatus.PARTIAL if any_failed else ScanStatus.COMPLETED
        # M9.D (ADR-033 Q1/Q2): terminal metadata. completed_at at every consumer
        # terminal transition; PARTIAL gets a job-failure summary, COMPLETED
        # leaves error_message null.
        scan.completed_at = datetime.now(timezone.utc)
        if any_failed:
            n_failed = sum(1 for j in jobs if j.status in _TERMINAL_FAILED)
            scan.error_message = (
                f"{n_failed} of {len(jobs)} scan jobs failed; "
                "partial results available"
            )
        await db.flush()

        # DQ5: SCAN_COMPLETED audit relocated here (post-pipeline terminal).
        finding_count_total = sum(j.finding_count or 0 for j in jobs)
        await audit(
            db,
            organization_id=scan.organization_id,
            actor_id=None,  # system-driven, no user actor
            action=ScanAction.SCAN_COMPLETED,
            resource_type="scan",
            resource_id=scan.id,
            details={  # type: ignore[arg-type]
                "finding_count": finding_count_total,
                "job_count": len(jobs),
            },
        )
        await db.commit()

    async def _fail_scan(
        self, scan_id: UUID, org_uuid: UUID, *, error: str | None = None
    ) -> None:
        """Mark a scan FAILED + ai_pipeline_degraded in a fresh session (Q8).

        A pipeline crash must never strand a scan in ANALYZING. Best-effort:
        if even this fails, the loop has already logged the original error.
        ``error`` carries the pipeline exception text for Scan.error_message
        (M9.D ADR-033 Q2; threaded from the _process except handler).
        """
        try:
            async with self._session_factory() as fail_db:
                await set_tenant_context(fail_db, org_uuid)
                scan = await fail_db.get(Scan, scan_id)
                if scan is not None:
                    scan.status = ScanStatus.FAILED
                    scan.ai_pipeline_degraded = True
                    # M9.D (ADR-033 Q1/Q2): FAILED is a consumer terminal
                    # transition — stamp completed_at + record the failure.
                    scan.completed_at = datetime.now(timezone.utc)
                    scan.error_message = error
                    await fail_db.commit()
        except Exception:
            logger.exception(
                "ai-pipeline: failed to mark scan %s FAILED after pipeline error",
                scan_id,
            )
