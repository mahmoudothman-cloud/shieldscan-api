"""Completions consumer for ``shieldscan:completions`` Pub/Sub channel
(Task 4.2 + findings-ingest extension per ADR-025).

Subscribes to the SPEC §7.3 completion channel and applies each event
to the matching ``ScanJob`` row + aggregates the parent ``Scan.status``
when all sibling jobs reach a terminal state. As of the findings-
ingest extension, ALSO inserts the per-event ``findings[]`` array into
``raw_findings`` in the same database transaction as the
``ScanJob.status`` update — closing ADR-024 §3.2 "Python ingest scope
deferred" + ADR-017 Task 5.5 cross-repo follow-up.

State-machine ownership (ADR-013):
  Python is the SOLE writer for scan + scan_job state. Workers signal
  via Redis events; this consumer is the entry point that turns those
  signals back into PostgreSQL UPDATEs (and now INSERTs for findings).
  Findings ingest + ScanJob update commit atomically per ADR-013's
  sole-writer guarantee — if the findings INSERT fails, ScanJob
  status stays ``running`` and Pub/Sub redelivery re-fires the event.

Audit policy (DRIFT-LOG 2026-04-30 H.2):
  Per-job completion is captured in ``scan_jobs.status`` only — no
  audit row per job. Only scan-level terminal transitions
  (SCAN_COMPLETED / SCAN_FAILED) emit audit rows. Pin via
  ``test_consumer_does_not_audit_per_job``.

Sequencing (ADR-017):
  Jobs producing >1000 findings emit multiple events with
  ``event_seq.total > 1`` per ADR-017's soft cap. Intermediate events
  use ``event_type="partial_findings"`` + ``status="partial_findings"``;
  the terminal event carries the canonical status + authoritative
  ``finding_count``. Findings from intermediate events accumulate in
  ``self._accumulator`` (process-local, asyncio.Lock-guarded); the
  terminal event drains the accumulator + commits all findings + the
  ScanJob update in a single transaction.

  Forcing-function test: ``test_consumer_aggregates_sequenced_findings``
  pins the contract per ADR-017 line 1474-1475.

Multi-process duplicate handling (DRIFT-LOG H.4 + ADR-025):
  Each uvicorn worker subscribes to the channel; with N>1 workers,
  every completion event is processed N times. Second-and-onward
  handlers see a job already in the terminal state and short-circuit
  with a DEBUG log. The findings-ingest extension PRESERVES this
  short-circuit on terminal-event paths to bound damage at MVP scale
  (each worker would otherwise commit its own subset of accumulated
  findings, producing duplicates AND/OR partial subsets depending on
  Pub/Sub ordering). Honest acknowledgment: the short-circuit bounds
  the damage but does not eliminate it; the genuine fix is ADR-018
  Streams + consumer-groups, deferred to scale milestone. Trigger to
  revisit: first deployment with N>1 uvicorn workers.

RLS:
  No request context — the consumer manages its own ``AsyncSession``
  per event and establishes tenant context from the event's
  ``organization_id`` field, via ``db.tenant_context.set_tenant_context``,
  before any RLS-scoped read or write.

  This docstring previously described the form
  ``text("SET app.current_org_id = :org_id"), {"org_id": ...}`` as what the
  consumer used. That form does not work and was never used: PostgreSQL does
  not accept a bind parameter on a bare ``SET`` (it raises ProgrammingError),
  so every call site interpolated the uuid into the SQL string instead. The
  helper now uses ``set_config('app.current_org_id', :org_id, false)``, which
  is an ordinary function call and takes a real bind parameter — so the
  statement is parameterized in fact rather than in description.

Job-completion logging:
  ``_persist`` emits one ``job_completed`` line at INFO per job, after
  commit, for every terminal outcome — including failed and canceled,
  which are the outcomes most worth having in the log. It carries
  engine, status, finding_count, persisted_count, duration_ms, scan_id,
  job_id and idempotency_key, both in the message and in ``extra`` for a
  structured handler to pick up. ``error_message`` is appended when the
  event carries one, and is now also written to
  ``scan_jobs.error_message`` — it was NULL for every row in production
  until the job reclaimer (engine Drift #70) made the reason the whole
  point of the event.

  finding_count vs persisted_count is the reason the line exists:
  the first is the engine's claim, the second is what survived
  validation into ``raw_findings``. Divergence is silent finding loss
  and was previously invisible without a query. Pinned by
  ``test_completions_consumer_logging.py``.

Lifecycle:
  ``CompletionsConsumer.start()`` spawns the consume loop as an
  asyncio task. ``stop()`` cancels and waits for it to drain. Wired
  into the FastAPI lifespan in ``main.py``.

References:
  - ADR-013 Python sole writer (atomicity invariant)
  - ADR-017 Findings inline + sequencing
  - ADR-024 §3.2 RawFinding schema extension columns-ready posture
    (closed by this implementation)
  - ADR-025 (shieldscan-docs SPECIFICATION.md §13) — Pydantic
    strictness + service-class accumulator + RLS atomic ingest
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Callable
from uuid import UUID, uuid4

from datetime import datetime, timezone
from urllib.parse import urlparse

from pydantic import ValidationError
from sqlalchemy import func, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import select_fresh
from app.models.raw_findings import RawFinding
from app.models.recon import AttackSurface, SubdomainStatus
from app.db.tenant_context import set_tenant_context
from app.models.scans import Scan, ScanJob, ScanStatus
from app.schemas.raw_findings import RawFindingCreate
from app.services.vulnerability_identity import reconcile_scan_history
from app.services.audit import ScanAction, audit

logger = logging.getLogger(__name__)


# Set of ScanJob.status values that are terminal (no further updates
# expected from workers). Mirrors the worker side's terminal states
# in SPEC §7.3 event_types.
_TERMINAL_JOB_STATUSES: frozenset[str] = frozenset(
    {"completed", "failed", "canceled"}
)
# How many rejected findings get a full per-finding WARNING before the
# loop falls back to the aggregate count alone. A schema mismatch rejects
# every finding in a batch identically, so the first few carry all the
# diagnostic value and the rest is repetition.
_MAX_REJECTION_DETAILS = 3

# Note: "partial" (a terminal status per ADR-017 sequencing) is NOT
# in this set. Adding it would extend multi-process short-circuit
# coverage to partial events but would also require updating
# _maybe_complete_scan's aggregation logic to recognize "partial" as
# a non-failure terminal — that's M4 Task 4.2 scope, not findings-
# ingest. Trade-off accepted at MVP scale (single uvicorn worker;
# duplicate events don't arrive). Trigger to revisit: same as the
# multi-process posture — first deployment with N>1 uvicorn workers.


def _parse_event_timestamp(raw) -> datetime | None:
    """Permissive RFC3339 timestamp parser for engine-emitted event
    fields (timestamp + last_probed_at per SPEC §7.6). Returns None
    on missing/malformed input — caller falls back to event-level
    timestamp or accepts None (the column is nullable).

    Accepts both ``Z`` suffix and explicit ``+00:00`` offset
    notations; datetime.fromisoformat handles ``+00:00`` natively
    (Python 3.11+ also handles ``Z`` directly, but normalize for
    older runtimes consistent with VERSIONS.md). Task 8.3α helper.
    """
    if not raw:
        return None
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


class CompletionsConsumer:
    """Async background task that bridges Redis completion events back
    to PostgreSQL.

    Constructor takes a ``session_factory`` (an
    ``async_sessionmaker[AsyncSession]``) — typically
    ``app.db.AsyncSessionLocal`` — so each event opens its own session
    independent of any request-bound session.

    As of the findings-ingest extension (ADR-025), also maintains a
    process-local accumulator for sequenced events (``event_seq.total
    > 1``); see module docstring sequencing section.
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

        # Findings accumulator for sequenced events (ADR-025; ADR-017
        # §3.3 sequencing contract). Keyed by (scan_id, job_id);
        # populated by intermediate events; drained + cleared by the
        # terminal event after successful commit. Lock guards both
        # mutation paths against concurrent asyncio task scheduling.
        # Process-local: at MVP scale (1 uvicorn worker) this is
        # complete; at scale (N>1 workers) the multi-process posture
        # documented in module docstring applies (ADR-018 Streams +
        # consumer-groups is the genuine fix).
        self._accumulator: dict[tuple[UUID, UUID], list[dict]] = {}
        self._accumulator_lock = asyncio.Lock()

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

    # ---------------------------------------------------------------- routing (unit-testable)

    async def apply_event(self, event: dict) -> None:
        """Apply one completion event directly, bypassing Pub/Sub.

        The only caller is the stranded-job backfill
        (``app.services.stranded_jobs``), which replays the events dead
        workers never sent. It exists so that recovery goes through the
        exact routing, persistence and scan-aggregation path a live event
        takes, rather than a second implementation of the same writes
        that could drift from it.

        Exceptions propagate, unlike the consume loop's
        ``_handle_safely``: a backfill wants to know what failed.
        """
        await self._handle(event)

    async def _handle(self, event: dict) -> None:
        """Route one completion event to the appropriate handler based
        on ``event_type``, ``event_seq``, and ``status``.

        Recognized ``event_type`` values: ``job_completed`` (single-
        event jobs OR terminal sequenced events) and
        ``partial_findings`` (intermediate sequenced events). Anything
        else is silently ignored (defensive — workers should only
        publish these types to this channel, but we don't rely on it
        being clean).

        Routing matrix:

          status              event_seq.total  → handler
          ------              ---------------  ---------------
          failed/canceled     any              → status-only update
          completed/partial   1                → single-event ingest
          partial_findings    >1               → intermediate accumulate
          completed/partial   >1               → terminal ingest
          else                                 → defensive log + skip
        """
        # Per Phase-0 Deviation 2: extend filter to accept BOTH
        # job_completed AND partial_findings event types. Sequenced
        # intermediate events arrive with event_type="partial_findings"
        # per ADR-017 + SPEC §7.3; the pre-extension filter would
        # silently drop them and the accumulator would never trigger.
        event_type = event.get("event_type")

        # Task 8.3α: attack_surface events route to the dedicated
        # _handle_attack_surface UPSERT path. Distinct lifecycle from
        # job_completed/partial_findings: AttackSurface rows are
        # UPSERT-idempotent-by-construction (uq_scan_subdomain +
        # ON CONFLICT DO UPDATE per Q-MULTI-PROCESS-POSTURE b) and
        # do NOT participate in event_seq sequencing per Q-LIFECYCLE.
        # Drift #58 Layer B repair routing.
        if event_type == "attack_surface":
            await self._handle_attack_surface(event)
            return

        if event_type not in ("job_completed", "partial_findings"):
            return  # ignore unrecognized

        status = event.get("status")
        event_seq = event.get("event_seq", {"index": 1, "total": 1})
        total = event_seq.get("total", 1)

        if status in ("failed", "canceled"):
            # No findings on these events per SPEC §7.3 line 817
            # ("findings is REQUIRED on terminal events ... and absent
            # on failed/canceled events"). Status-only update path.
            await self._handle_failed_or_canceled_event(event)
        elif total == 1:
            # Single-event job (≤1000 findings).
            await self._handle_single_event(event)
        elif status == "partial_findings":
            # Intermediate sequenced event — accumulate; no DB write.
            await self._handle_intermediate_event(event)
        elif status in ("completed", "partial"):
            # Terminal sequenced event — drain accumulator + commit.
            await self._handle_terminal_event(event)
        else:
            # Defensive: unknown status combination — log + skip. New
            # status values surface as engineer-visible signals here.
            logger.error(
                "completions consumer: unknown status combination "
                "status=%r event_seq=%r scan_id=%s job_id=%s",
                status,
                event_seq,
                event.get("scan_id"),
                event.get("job_id"),
            )

    # ---------------------------------------------------------------- event handlers

    async def _handle_failed_or_canceled_event(self, event: dict) -> None:
        """Status-only update path (no findings ingest). Mirrors the
        pre-findings-ingest behavior of the M4 Task 4.2 handler."""
        await self._persist(event, finding_dicts=[])

    async def _handle_single_event(self, event: dict) -> None:
        """Single-event ingest (event_seq.total == 1; ≤1000 findings).

        Validate findings via Pydantic; assemble finding_dicts
        (excluding ``job_id`` per Phase-0 Deviation 1 — RawFinding has
        no such column); insert + ScanJob update commit atomically.
        """
        finding_dicts = self._build_finding_dicts(event.get("findings", []))
        await self._persist(event, finding_dicts=finding_dicts)

    async def _handle_intermediate_event(self, event: dict) -> None:
        """Intermediate sequenced event (status="partial_findings").

        Validate findings via Pydantic; append to accumulator under
        the accumulator lock. NO database write; NO ScanJob update —
        both are deferred to the terminal event per ADR-017.
        """
        scan_id = UUID(event["scan_id"])
        job_id = UUID(event["job_id"])

        # Validate; failure surfaces cross-repo schema drift.
        finding_dicts = self._build_finding_dicts(event.get("findings", []))

        async with self._accumulator_lock:
            key = (scan_id, job_id)
            accumulated = self._accumulator.setdefault(key, [])
            accumulated.extend(finding_dicts)

        # Intentionally no DB I/O here. Per ADR-017 sequencing
        # contract: intermediate events accumulate; terminal event
        # commits the union.

    async def _handle_terminal_event(self, event: dict) -> None:
        """Terminal sequenced event (status in {"completed", "partial"}
        and event_seq.total > 1).

        Validate this event's findings; assemble accumulated_findings ∪
        this_event_findings; persist + clear accumulator after commit
        succeeds (per Phase-0 Deviation 5 cleanup ordering).

        If commit fails: accumulator retains data for retry-via-
        redelivery semantics. Per Phase-0 Deviation 5: clear ONLY
        AFTER successful commit; reverse ordering creates data-loss-
        on-commit-failure bugs.
        """
        scan_id = UUID(event["scan_id"])
        job_id = UUID(event["job_id"])
        key = (scan_id, job_id)

        # Validate this event's findings. Cross-repo schema drift
        # surfaces here at the terminal event boundary too — not just
        # at intermediate events.
        this_event_dicts = self._build_finding_dicts(event.get("findings", []))

        # Lock briefly to capture accumulator state; release during DB
        # I/O to keep the lock window minimal. The accumulator is NOT
        # cleared yet — clear only after commit succeeds.
        async with self._accumulator_lock:
            accumulated = list(self._accumulator.get(key, []))

        all_finding_dicts = accumulated + this_event_dicts

        # Persist (insert + ScanJob update + scan-aggregate, atomic
        # per ADR-013). _persist's short-circuit check (job already
        # terminal) protects against N>1 multi-process worker damage
        # per Phase-0 Deviation 4. _persist raises on commit failure;
        # we let that propagate so the accumulator retains data for
        # retry-via-redelivery (Phase-0 Deviation 5 cleanup ordering).
        await self._persist(event, finding_dicts=all_finding_dicts)

        # Reached only on non-raise return from _persist:
        #   - True: commit succeeded; data is persisted.
        #   - False: short-circuited (peer worker already wrote OR
        #     unknown job OR malformed org_id). In all three cases
        #     the accumulator entry is no longer useful — peer
        #     wrote our data, OR the data is fundamentally
        #     undeliverable. Clear in both cases.
        # If _persist raised, the `await` above re-raises and we
        # never reach this point; accumulator stays.
        async with self._accumulator_lock:
            self._accumulator.pop(key, None)

    # ---------------------------------------------------------------- attack-surface handler

    async def _handle_attack_surface(self, event: dict) -> None:
        """UPSERT AttackSurface rows from an engine EventAttackSurface
        event. Drift #58 Layer B repair (api consumer absence).

        Per Task 8.3α design doc 0030319 §3.5 + plan dba6a7c §3.5:
          - Y-UPSERT-ATOMICITY (c): atomic-per-event transaction; all
            subdomains in a single commit. uq_scan_subdomain +
            ON CONFLICT (scan_id, subdomain) DO UPDATE makes duplicate
            delivery safe by construction (Q-MULTI-PROCESS-POSTURE b).
          - Y-EVENT-PAYLOAD-VALIDATION (b): permissive parse — match
            existing _persist convention; malformed UUIDs / URLs are
            skipped with a WARN log rather than killing the loop.
          - Q-RLS-GUC: SET app.current_org_id from event.organization_id
            pre-write per V-MB / Phase-0 Deviation 3 pattern (no LOCAL;
            UUID-validated f-string interpolation).
          - ADR-013 sole-writer continuity: api consumer is the SOLE
            writer of AttackSurface rows; engine never writes directly.
          - ADR-017 sequencing NOT invoked: AttackSurface UPSERT does
            not require event_seq.total handling — uq_scan_subdomain
            UPSERT inherently idempotent.

        Wire shape canonical: SPEC.md §7.6. Engine emission canonical:
        TOOL-ARCHITECTURE.md §8.5 + shieldscan-engine fc75a98.
        """
        scan_id_raw = event.get("scan_id")
        org_id_raw = event.get("organization_id")
        root_domain = event.get("root_domain")
        subdomains = event.get("subdomains") or []

        if not scan_id_raw or not org_id_raw or not root_domain:
            logger.warning(
                "completions consumer: attack_surface event missing "
                "required field(s); dropping (scan_id=%r org=%r root=%r)",
                scan_id_raw,
                org_id_raw,
                root_domain,
            )
            return

        try:
            scan_id = UUID(str(scan_id_raw))
            org_uuid = UUID(str(org_id_raw))
        except (TypeError, ValueError):
            logger.warning(
                "completions consumer: attack_surface event malformed "
                "UUID; dropping (scan_id=%r org=%r)",
                scan_id_raw,
                org_id_raw,
            )
            return

        # Build value rows BEFORE opening the session — malformed-URL
        # entries are skipped permissively per Y-EVENT-PAYLOAD-VALIDATION
        # (b); the surviving rows form the atomic-per-event commit.
        event_ts = _parse_event_timestamp(event.get("timestamp"))
        values: list[dict] = []
        for sub in subdomains:
            url = sub.get("url")
            status_raw = sub.get("status")
            if not url or not status_raw:
                continue
            parsed = urlparse(url)
            subdomain_label = parsed.hostname
            if not subdomain_label:
                continue
            try:
                status_enum = SubdomainStatus(status_raw)
            except ValueError:
                # Unknown status string — skip permissively.
                continue
            values.append(
                {
                    "scan_id": scan_id,
                    "organization_id": org_uuid,
                    "root_domain": root_domain,
                    "subdomain": subdomain_label,
                    "full_url": url,
                    "status": status_enum,
                    "status_code": sub.get("status_code"),
                    "tech_stack": sub.get("tech_stack"),
                    "last_probed_at": _parse_event_timestamp(
                        sub.get("last_probed_at")
                    )
                    or event_ts,
                }
            )

        # UPSERT the discovered attack surface (Task 8.3α; Phase-1
        # persistence). Empty `values` (recon found no live targets, or
        # all rows filtered) skips the UPSERT but STILL proceeds to the
        # phase-2 trigger below — empty-AttackSurface is correct
        # recon-first behavior and must emit the always-emit phase-2
        # audit (M8.1β.2 ADR-028 Q2 i + Q5 b.i).
        if values:
            async with self._session_factory() as db:
                # RLS preamble. f-string is safe because org_uuid is a
                # validated UUID. Mirrors existing _persist + project
                # patterns (Phase-0 Deviation 3).
                await set_tenant_context(db, org_uuid)

                stmt = pg_insert(AttackSurface).values(values)
                stmt = stmt.on_conflict_do_update(
                    index_elements=["scan_id", "subdomain"],
                    set_={
                        "full_url": stmt.excluded.full_url,
                        "status": stmt.excluded.status,
                        "status_code": stmt.excluded.status_code,
                        "tech_stack": stmt.excluded.tech_stack,
                        "last_probed_at": stmt.excluded.last_probed_at,
                        "updated_at": datetime.now(timezone.utc),
                    },
                )
                await db.execute(stmt)
                await db.commit()

        # M8.1β.2 ADR-028 Phase-2 dispatch trigger. Sequential session
        # per Q7 (c.ii): the AttackSurface UPSERT committed above (its own
        # session); phase-2 now opens a NEW session. dispatch_phase2 is
        # self-contained (persist + audit + commit + enqueue); it reads
        # the just-UPSERTed AttackSurface rows + re-dispatches per-(target,
        # tool) tool ScanJobs (Q1 c hybrid follow-up dispatch).
        await self._trigger_phase2_dispatch(scan_id, org_uuid)

    async def _trigger_phase2_dispatch(self, scan_id: UUID, org_uuid: UUID) -> None:
        """Invoke orchestrator.dispatch_phase2 in a fresh session after
        the AttackSurface UPSERT commits (M8.1β.2 ADR-028 Phase-2; Q7
        c.ii sequential sessions). Fail-loud per Q7 (c.ii.B): on any
        dispatch exception, mark the scan FAILED with a diagnostic-rich
        audit (Y-PHASE2-DISPATCH-FAILURE-AUDIT-SHAPE b) in a separate
        session so the failure is durable + operator-visible.

        Import is local to avoid a module-level orchestrator↔consumer
        import cycle (orchestrator imports models; consumer imports
        orchestrator only at this call boundary).
        """
        from app.services.orchestrator import ScanOrchestrator

        try:
            async with self._session_factory() as dispatch_session:
                await set_tenant_context(dispatch_session, org_uuid)
                orchestrator = ScanOrchestrator(dispatch_session, self._redis)
                await orchestrator.dispatch_phase2(scan_id=scan_id)
        except Exception:  # noqa: BLE001 — fail-loud per Q7 c.ii.B
            logger.exception(
                "completions consumer: phase-2 dispatch failed for "
                "scan_id=%s; marking scan FAILED",
                scan_id,
            )
            async with self._session_factory() as fail_session:
                await set_tenant_context(fail_session, org_uuid)
                fail_orchestrator = ScanOrchestrator(fail_session, self._redis)
                await fail_orchestrator._fail_scan_phase2(
                    scan_id, reason="phase2_dispatch_exception"
                )

    # ---------------------------------------------------------------- persistence helper

    async def _persist(self, event: dict, finding_dicts: list[dict]) -> bool:
        """Open session, SET RLS, fetch ScanJob, short-circuit if
        terminal, bulk-insert findings (if any), update ScanJob.status
        + finding_count + duration_ms, aggregate parent Scan, commit.

        Returns True if the commit landed; False if short-circuited
        (job already terminal — peer worker handled it). Raises on
        SQLAlchemy errors so the caller can decide retry behavior
        (accumulator retention etc.).

        Per Phase-0 Deviation 3: ``SET app.current_org_id`` (no LOCAL),
        parameterized form. Matches existing project pattern.

        Per Phase-0 Deviation 4: short-circuit BEFORE bulk insert
        when ScanJob already terminal — bounds N>1 multi-process
        worker damage at MVP scale.
        """
        job_id_raw = event["job_id"]
        org_id = event["organization_id"]
        new_status = event["status"]
        finding_count = event.get("finding_count", 0)
        duration_ms = event.get("duration_ms")

        try:
            job_id = UUID(job_id_raw)
        except (TypeError, ValueError):
            logger.warning(
                "completions consumer: malformed job_id=%r; dropping",
                job_id_raw,
            )
            return False

        # PostgreSQL's `SET` admin command does NOT accept bind
        # parameters (asyncpg surfaces this as a syntax error at $1).
        # The existing project pattern uses f-string interpolation;
        # we add UUID validation as defense-in-depth so any non-UUID
        # value rejects BEFORE reaching the SQL string. UUID() raises
        # ValueError on anything that isn't a 36-char hex+hyphen
        # string, so f-string interpolation is safe by construction.
        try:
            org_uuid = UUID(str(org_id))
        except (TypeError, ValueError):
            logger.warning(
                "completions consumer: malformed organization_id=%r; "
                "dropping event for job_id=%s",
                org_id,
                job_id,
            )
            return False

        async with self._session_factory() as db:
            # RLS preamble. f-string is safe because org_uuid is a
            # validated UUID (no SQL chars possible). Matches existing
            # project pattern at completions_consumer.py (pre-extension
            # line 177), identity.py, audit.py, db/policies.py.
            await set_tenant_context(db, org_uuid)

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
                return False

            # Multi-process duplicate handling — see module docstring.
            # Phase-0 Deviation 4: applies on terminal-event paths too,
            # bounding N>1 worker damage. Short-circuit BEFORE bulk
            # insert so peer-worker-handled events don't leak stale
            # finding rows.
            #
            # Terminal is terminal, whatever the incoming status says.
            # This used to short-circuit only when the two statuses
            # matched, which was enough while every event came from the
            # worker that ran the job. The engine's job reclaimer
            # (engine Drift #70) breaks that assumption: it publishes
            # job_completed(status=failed) for jobs whose worker died,
            # and it can lose a race with an acknowledgement. Under the
            # old rule such an event would overwrite a job that had just
            # completed — findings ingested, scan aggregated — with
            # `failed`. Refusing to move a job off a terminal status
            # makes that impossible by construction rather than by
            # timing, and it aligns job-level behaviour with the
            # scan-level cancel-wins policy (Task 4.5 H.2).
            if job.status in _TERMINAL_JOB_STATUSES:
                if job.status == new_status:
                    logger.debug(
                        "completion event for already-terminal job_id=%s "
                        "(status=%s); peer process handled — skipping ingest "
                        "+ status update",
                        job_id,
                        job.status,
                    )
                else:
                    logger.warning(
                        "completion event would change an already-terminal "
                        "job_id=%s from status=%s to status=%s; ignored. A "
                        "reclaimed job that finished after all, or two "
                        "producers for one job.",
                        job_id,
                        job.status,
                        new_status,
                    )
                return False

            # Bulk insert findings (if any). Per Phase-0 Deviation 1:
            # no job_id column; scan_id + organization_id are derived
            # from the authoritative ScanJob row, not from per-finding
            # payload (engine processor populates per-finding scan_id /
            # org_id but Pydantic-validated dicts already exclude them
            # via _build_finding_dicts). uuid4() for the primary key;
            # TimestampMixin's created_at / updated_at auto-populate.
            if finding_dicts:
                enriched = [
                    {
                        **fd,
                        "id": uuid4(),
                        "organization_id": UUID(str(org_id)),
                        "scan_id": job.scan_id,
                    }
                    for fd in finding_dicts
                ]
                await db.execute(insert(RawFinding), enriched)

            job.status = new_status
            job.finding_count = finding_count
            if duration_ms is not None:
                job.duration_ms = duration_ms
            # The column has existed since the first scans migration and
            # was never written, so every failed job in production says
            # only "failed". Persisting it here is what makes a reclaimed
            # job distinguishable from a job the tool itself failed — the
            # reclaimer's whole diagnostic value is in the reason string
            # (engine Drift #70), and a log line is not queryable.
            # Assigned only when the event carries one, so a re-delivered
            # success can never blank a reason already stored.
            if event.get("error_message"):
                job.error_message = event["error_message"]
            await db.flush()

            # Aggregate scan-level state if all sibling jobs are now
            # terminal. Only the scan-level transition emits audit
            # (per H.2 — terminal-aggregate-only audit policy).
            # M9.0 (ADR-029 Q1): returns scan_id when the AI pipeline must be
            # dispatched (raw_findings present); we dispatch AFTER commit in a
            # fresh session (Q7 c.ii sequential), mirroring phase-2.
            ai_dispatch_scan_id = await self._maybe_complete_scan(db, job.scan_id)

            await db.commit()

            # One structured line per job, on every terminal outcome —
            # completed, partial, failed, canceled. Emitted AFTER commit so
            # it describes persisted state, not intent.
            #
            # persisted_count next to finding_count is the point of the line,
            # not decoration. finding_count is what the engine asserts it
            # found; persisted_count is how many rows survived
            # _build_finding_dicts validation and landed in raw_findings.
            # Those two diverging is silent data loss — it is how nmap
            # produced zero findings for 14 consecutive runs while every
            # status field read "completed". On one line, the divergence is
            # visible in the log without anyone thinking to run a query.
            #
            # engine / idempotency_key prefer the event but fall back to the
            # ScanJob row: both are `omitempty` on the Go side
            # (events.JobCompletedEvent), so an event can legitimately omit
            # them while the row always has them.
            #
            # error_message has no fallback because there is nothing to fall
            # back TO: the event is the only carrier. It is now persisted to
            # scan_jobs.error_message above — that column was NULL for all
            # 198 rows in production, including all 7 failed and canceled
            # ones, until the reclaimer made the reason load-bearing. The
            # line still carries it because the log is where an operator
            # looks first, and because it is the only record for events that
            # short-circuit before the write.
            error_message = event.get("error_message") or None
            log_fields = {
                "event": "job_completed",
                "engine": event.get("engine") or job.engine,
                "status": new_status,
                "finding_count": finding_count,
                "persisted_count": len(finding_dicts),
                "duration_ms": duration_ms,
                "scan_id": str(job.scan_id),
                "job_id": str(job_id),
                "idempotency_key": (
                    event.get("idempotency_key") or job.idempotency_key
                ),
                # Always in `extra`, even when None, so a structured handler
                # sees one stable field set rather than a shape that varies
                # by outcome.
                "error_message": error_message,
            }
            # %s throughout, never %d: finding_count / duration_ms come
            # straight off the wire and a non-numeric value would make the
            # formatting itself the failure.
            message = (
                "job_completed engine=%s status=%s finding_count=%s "
                "persisted_count=%s duration_ms=%s scan_id=%s job_id=%s "
                "idempotency_key=%s"
            )
            args = [
                log_fields["engine"],
                log_fields["status"],
                log_fields["finding_count"],
                log_fields["persisted_count"],
                log_fields["duration_ms"],
                log_fields["scan_id"],
                log_fields["job_id"],
                log_fields["idempotency_key"],
            ]
            if error_message is not None:
                # Rendered only when present, and last: it is free text of
                # unbounded length, so trailing it keeps the fixed key=value
                # fields in a stable, greppable position. %r quotes it, so
                # embedded spaces and newlines can't fake a field boundary.
                message += " error_message=%r"
                args.append(error_message)
            logger.info(message, *args, extra=log_fields)

        if ai_dispatch_scan_id is not None:
            await self._trigger_ai_pipeline_dispatch(
                ai_dispatch_scan_id, org_uuid
            )
        return True

    # ---------------------------------------------------------------- finding_dict builder

    def _build_finding_dicts(self, raw_findings: list) -> list[dict]:
        """Validate each finding via ``RawFindingCreate`` and return a
        list of dicts ready for ``insert(RawFinding).values(...)``.

        Per Phase-0 Deviations 1 + 5 (mobile alias) + 8 (no
        completed_at): each dict excludes ``scan_id`` and ``org_id``
        (both derived from ScanJob in ``_persist``) and uses
        ``model_dump(by_alias=False)`` so SQLAlchemy column names land
        in the dict (``mobile_permission`` not the wire alias
        ``permission``; ``tool_metadata`` not the wire alias
        ``metadata``); inserting wire aliases would fail with
        unknown-column errors.

        **Per-finding fault isolation.** Each finding is validated
        independently; a ``ValidationError`` on one finding is logged and
        skipped rather than propagated. Previously a single malformed
        finding aborted the whole engine's batch at insert time (one bad
        zap event discarded all 608 findings).

        **Rejection logging.** The first ``_MAX_REJECTION_DETAILS`` failures
        log in full at WARNING (which validator, which field, which tool);
        the loop then emits one aggregate at ERROR with the counts, flagging
        the total-loss case explicitly. Both levels were raised from
        debug/warning: the per-finding reason sat at DEBUG and so produced
        no output at all, which is a large part of why the nmap and
        tool_metadata diagnoses were reconstructions from the database
        rather than reads of a log (DRIFT-LOG #68).

        Empty input returns ``[]`` so caller's status-only path remains
        cheap.
        """
        if not raw_findings:
            return []
        total = len(raw_findings)
        dicts: list[dict] = []
        rejected = 0
        reject_tools: set[str] = set()
        for raw in raw_findings:
            try:
                validated = RawFindingCreate.model_validate(raw)
            except ValidationError as exc:
                # Isolate the bad finding; keep the rest of the batch.
                rejected += 1
                if isinstance(raw, dict):
                    reject_tools.add(str(raw.get("tool_name", "unknown")))
                # First few in full detail at WARNING, not DEBUG. This was
                # the only place that said WHY a finding was dropped, and at
                # debug it never produced a single line of output in the
                # process's life — the API has no logging configuration, so
                # debug and info both went nowhere (see DRIFT-LOG #68).
                # Capped rather than uncapped: a schema mismatch rejects
                # every finding in the batch, and 642 identical tracebacks
                # would bury the aggregate below.
                if rejected <= _MAX_REJECTION_DETAILS:
                    logger.warning(
                        "raw finding rejected by RawFindingCreate validation "
                        "(%d of at most %d shown; tool=%s): %s",
                        rejected,
                        _MAX_REJECTION_DETAILS,
                        (raw.get("tool_name", "unknown")
                         if isinstance(raw, dict) else "unknown"),
                        exc,
                    )
                continue
            # by_alias=False → Python field names (mobile_permission,
            # mobile_component_name, tool_metadata); by_alias=True would
            # emit wire aliases (permission, component_name, metadata)
            # which RawFinding has no columns for.
            d = validated.model_dump(by_alias=False)
            # Drop scan_id and org_id from the per-finding payload;
            # the authoritative scope comes from ScanJob (Phase-0
            # Deviation 1). Inserting Pydantic's None into a non-null
            # column would also fail.
            d.pop("scan_id", None)
            d.pop("org_id", None)
            dicts.append(d)
        if rejected:
            # ERROR, not WARNING: findings reaching the consumer and failing
            # validation is data loss from a cross-repo schema mismatch, not
            # a degraded-but-working condition. Total loss (rejected ==
            # total) is called out explicitly — that is the nmap shape,
            # where the job reports success and persists nothing.
            logger.error(
                "raw findings rejected during ingest: %d of %d%s (tool=%s)",
                rejected,
                total,
                " — ENTIRE BATCH LOST" if rejected == total else "",
                ",".join(sorted(reject_tools)) or "unknown",
            )
        return dicts

    # ---------------------------------------------------------------- aggregate

    async def _mark_running(self, db: AsyncSession, scan_id: UUID) -> None:
        """QUEUED → RUNNING + ``started_at`` on the first job report.

        Idempotent: a scan already past QUEUED (RUNNING, ANALYZING,
        CANCELED, terminal) is left alone, so cancel-wins and the AI
        pipeline's ownership of later transitions are preserved.
        ``started_at`` is stamped only when still NULL.
        """
        scan = (
            await select_fresh(db, select(Scan).where(Scan.id == scan_id))
        ).scalar_one_or_none()
        if scan is None or scan.status != ScanStatus.QUEUED:
            return
        scan.status = ScanStatus.RUNNING
        if scan.started_at is None:
            scan.started_at = datetime.now(timezone.utc)
        await db.flush()

    async def _maybe_complete_scan(
        self, db: AsyncSession, scan_id: UUID
    ) -> UUID | None:
        """Aggregate scan-level state once all sibling jobs are terminal.

        Returns the ``scan_id`` when the caller must dispatch the AI pipeline
        (post-commit, sequential session), or ``None`` otherwise.

        ADR-029 Q1 interposition: a scan with raw_findings transitions to
        ANALYZING via the AI pipeline (dispatched by the caller after commit;
        the orchestrator owns the ANALYZING transition + LPUSH + audit), and
        the terminal COMPLETED/PARTIAL transition + SCAN_COMPLETED audit are
        emitted by the AIPipelineConsumer after the pipeline runs (DQ2 / DQ5).
        A scan with NO raw_findings short-circuits to terminal inline — no AI
        work to do (DQ3). ANALYZING is in the skip-set so a re-delivered
        completion event can't re-dispatch (DQ4); CANCELED still wins.

        ``select_fresh`` for both reads — we just wrote to one of these rows
        above and need the post-write state.
        """
        sibling_jobs = (
            await select_fresh(
                db, select(ScanJob).where(ScanJob.scan_id == scan_id)
            )
        ).scalars().all()
        if not all(j.status in _TERMINAL_JOB_STATUSES for j in sibling_jobs):
            # M11 pre-work: the first job to report back is the earliest
            # PG-visible proof the scan is executing. Workers never write
            # scans (ADR-013), so until now a scan sat in QUEUED from
            # dispatch to the last job — the dashboard could not tell
            # "waiting for a worker" from "six engines running". Flip
            # QUEUED → RUNNING and stamp started_at here; terminal and
            # ANALYZING transitions are untouched.
            await self._mark_running(db, scan_id)
            return None

        any_failed = any(
            j.status in {"failed", "canceled"} for j in sibling_jobs
        )
        all_ok = all(j.status == "completed" for j in sibling_jobs)
        if not (all_ok or any_failed):
            return None

        scan = (
            await select_fresh(
                db, select(Scan).where(Scan.id == scan_id)
            )
        ).scalar_one_or_none()
        if scan is None:
            return None  # extremely unlikely; scan deleted concurrently
        if scan.status in {
            ScanStatus.COMPLETED,
            ScanStatus.PARTIAL,
            ScanStatus.FAILED,
            # CANCELED added in Task 4.5 H.2 (cancel-wins). User intent
            # at scan-level is sticky: if the cancel endpoint set
            # CANCELED before this completion landed, we do NOT
            # overwrite. Job-level state still reflects what each
            # worker reported (some completed, some canceled). See
            # DRIFT-LOG 2026-04-30 Task 4.5 cancel-wins entry.
            ScanStatus.CANCELED,
            # ANALYZING added at M9.0 (DQ4): the AI pipeline has already
            # been dispatched; a re-delivered completion event must not
            # re-dispatch. The AIPipelineConsumer owns the onward terminal
            # transition.
            ScanStatus.ANALYZING,
        }:
            return None

        # A single-job scan reaches here straight from QUEUED; make sure
        # it still carries a start time (same stamp _mark_running uses).
        if scan.started_at is None:
            scan.started_at = datetime.now(timezone.utc)

        # DQ3: no raw_findings → nothing for the AI pipeline to analyse;
        # transition straight to terminal inline (preserves the empty-scan
        # fast path) and emit SCAN_COMPLETED here.
        raw_findings_count = await db.scalar(
            select(func.count(RawFinding.id)).where(
                RawFinding.scan_id == scan_id
            )
        )
        # Public quick scans (M11 pre-work) never enter the AI pipeline:
        # the result page is built from raw findings, and free scans must
        # not spend AI budget. Finalise inline exactly like the empty-scan
        # fast path.
        if not raw_findings_count or scan.is_public:
            scan.status = (
                ScanStatus.COMPLETED if all_ok else ScanStatus.PARTIAL
            )
            scan.completed_at = datetime.now(timezone.utc)
            # M11: a clean scan is still evidence — older open issues this
            # scan covered are auto-resolved (the pipeline path does the
            # same after promotion). No-op for public scans.
            await reconcile_scan_history(db, scan)
            await db.flush()
            finding_count_total = sum(j.finding_count or 0 for j in sibling_jobs)
            await audit(
                db,
                organization_id=scan.organization_id,
                actor_id=None,  # consumer is system-driven, no user actor
                action=ScanAction.SCAN_COMPLETED,
                resource_type="scan",
                resource_id=scan.id,
                details={  # type: ignore[arg-type]
                    "finding_count": finding_count_total,
                    "job_count": len(sibling_jobs),
                },
            )
            return None

        # DQ1: raw_findings exist → defer the terminal transition to the AI
        # pipeline. Do NOT mutate scan.status here; the caller dispatches in a
        # fresh session post-commit (orchestrator sets ANALYZING + LPUSH +
        # audit), and the AIPipelineConsumer finalizes COMPLETED/PARTIAL.
        return scan_id

    async def _trigger_ai_pipeline_dispatch(
        self, scan_id: UUID, org_uuid: UUID
    ) -> None:
        """Dispatch the AI pipeline in a fresh session (ADR-029 Q1 e.ii).

        Mirrors ``_trigger_phase2_dispatch``: the completion session has
        already committed (job status + findings); this opens a new session,
        sets the RLS GUC, and calls ``ScanOrchestrator.dispatch_ai_pipeline``
        (ANALYZING + LPUSH + audit + commit). Fail-loud (Q8): on dispatch
        failure mark the scan FAILED + ai_pipeline_degraded so it can never be
        stranded pre-ANALYZING.
        """
        from app.services.orchestrator import ScanOrchestrator

        try:
            async with self._session_factory() as dispatch_session:
                await set_tenant_context(dispatch_session, org_uuid)
                orchestrator = ScanOrchestrator(dispatch_session, self._redis)
                await orchestrator.dispatch_ai_pipeline(scan_id=scan_id)
        except Exception:
            logger.exception(
                "ai-pipeline dispatch failed for scan_id=%s — marking FAILED",
                scan_id,
            )
            async with self._session_factory() as fail_session:
                await set_tenant_context(fail_session, org_uuid)
                fail_scan = await fail_session.get(Scan, scan_id)
                if fail_scan is not None:
                    fail_scan.status = ScanStatus.FAILED
                    fail_scan.ai_pipeline_degraded = True
                    await fail_session.commit()
