"""Scan orchestrator service (Task 4.2).

Composes the M4 ingredients into a single dispatch flow:

    ScanOrchestrator.dispatch(scan, identity)
      ↓ persists ScanJob rows (one per tool in SCAN_TYPE_TOOLS[scan_type])
      ↓ emits one SCAN_DISPATCHED audit row
      ↓ COMMITs the DB transaction        ← H.3: commit-then-dispatch
      ↓ pushes one job payload per tool to the priority queue

Commit-then-dispatch ordering (DRIFT-LOG 2026-04-30):
  Two failure modes; we preferred the visible-failure one.

  * If commit succeeds + queue.dispatch fails  → DB rows ('ghost
    queued') visible to the customer; M5+ retry janitor recovers.
    VISIBLE failure — easy to triage.
  * If commit fails (which it shouldn't past flush)              → no
    ghost rows because nothing committed.

  The rejected alternative (dispatch-then-commit) buried failures in
  worker logs as orphan queue entries with no DB row to explain them.

State-machine ownership (ADR-013):
  Python is the SOLE writer for Scan + ScanJob status columns. Workers
  signal via Redis events (Streams for progress, Pub/Sub for cancel +
  completions); they never write to PostgreSQL. The companion
  ``CompletionsConsumer`` listens to ``shieldscan:completions`` and
  applies job-completion events back to the DB.

Public scans (``ScanType.PUBLIC``) are NOT routed through this
orchestrator. They live in the separate ``public_scans`` table per
ADDENDUM-CRITICAL-5 §2.4. Calling ``dispatch`` with a public scan
raises ``UnsupportedScanTypeError`` — fail-loud, no silent skip.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import AuthIdentity
from app.models.mobile import MobileUpload
from app.models.scans import Scan, ScanJob, ScanType
from app.services.audit import ScanAction, audit
from app.services.scan_queue import ScanQueue

logger = logging.getLogger(__name__)


# ================================================================ priority enum


class ScanPriority(str, PyEnum):
    """Per-scan dispatch priority. Lives at the orchestrator boundary.

    The underlying ``ScanQueue`` (Task 4.1) accepts plain strings and
    raises ``ValueError`` on unknown values. This enum is where typed
    validation happens before reaching the queue — feeding an invalid
    string to ``ScanPriority(...)`` raises early with a clear message.
    """

    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


class UnsupportedScanTypeError(ValueError):
    """Raised when ``scan.scan_type`` isn't routable through this
    orchestrator (currently: only ``ScanType.PUBLIC`` triggers this)."""


# ================================================================ scan_type → tools


# Each ScanType (excluding PUBLIC) maps to a non-empty tuple of tools.
# Order in the tuple is informational only — workers receive each as
# a separate job payload and there's no inter-tool sequencing here
# (recon-driven target expansion is Go-side per Task 8.1).
SCAN_TYPE_TOOLS: Final[dict[ScanType, tuple[str, ...]]] = {
    ScanType.QUICK: ("subfinder", "httpx", "nuclei_fast", "sslyze"),
    ScanType.FULL_WEB: (
        "subfinder",
        "httpx",
        "nuclei",
        "zap",
        "wapiti",
        "nikto",
        "nmap",
        "sslyze",
    ),
    ScanType.FULL_WEB_SOURCE: (
        "subfinder",
        "httpx",
        "nuclei",
        "zap",
        "wapiti",
        "nikto",
        "nmap",
        "sslyze",
        "semgrep",
        "gitleaks",
        "dependency_check",
    ),
    ScanType.API: ("nuclei_api", "zap_api", "corstest", "sqlmap"),
    ScanType.MOBILE: ("mobsf",),
    ScanType.CONTAINER: ("trivy-container", "checkov"),
    ScanType.FULL_SPECTRUM: (
        "subfinder",
        "httpx",
        "nuclei",
        "zap",
        "wapiti",
        "nikto",
        "sqlmap",
        "nmap",
        "sslyze",
        "semgrep",
        "gitleaks",
        "dependency_check",
        "trivy-fs",
        "corstest",
        "checkov",
    ),
}

# Module-import assertion: every non-PUBLIC ScanType has a mapping.
# A future engineer adding a ScanType but forgetting to map it crashes
# at import — better than silently dispatching an empty job list.
assert {
    t for t in ScanType if t != ScanType.PUBLIC
} == set(SCAN_TYPE_TOOLS.keys()), (
    "SCAN_TYPE_TOOLS missing mapping for at least one non-PUBLIC ScanType"
)


def _target_type_for(scan_type: ScanType) -> str:
    """SPEC §7.1 ``target.target_type`` value."""
    if scan_type == ScanType.MOBILE:
        return "mobile"
    if scan_type == ScanType.CONTAINER:
        return "container"
    if scan_type == ScanType.API:
        return "api"
    return "web"


# ================================================================ orchestrator


class ScanOrchestrator:
    """Persist ScanJob rows + dispatch them to the priority queue.

    Caller responsibilities (Task 4.3 route handler):
      - Provide a fully-formed ``Scan`` ORM object with ``project``
        eager-loaded (SQLAlchemy lazy-load in async raises
        ``MissingGreenlet``).
      - Provide an ``AuthIdentity`` from ``require_org_membership``.
      - Tenant GUC must be set on the session before calling.

    Orchestrator responsibilities:
      - Validate scan_type + priority (raise on invalid).
      - INSERT ScanJob rows + emit SCAN_DISPATCHED audit.
      - COMMIT the transaction (caller must NOT commit again).
      - PUSH job payloads to Redis queue AFTER commit (H.3 ordering).

    See module docstring for failure-mode reasoning.
    """

    def __init__(self, db: AsyncSession, redis) -> None:
        self.db = db
        self.queue = ScanQueue(redis)

    async def dispatch(
        self,
        scan: Scan,
        identity: AuthIdentity,
        request_ip: str | None = None,
        user_agent: str | None = None,
    ) -> list[ScanJob]:
        """Build, persist, audit, commit, then dispatch.

        Returns the list of persisted ``ScanJob`` instances (in-memory
        references; the caller can use them for the response shape).
        """
        # 1. Type + priority validation. Raises before any side effects.
        if scan.scan_type not in SCAN_TYPE_TOOLS:
            raise UnsupportedScanTypeError(
                f"scan_type={scan.scan_type!r} is not dispatchable through "
                f"ScanOrchestrator. Public scans live in the public_scans "
                f"table (ADDENDUM-CRITICAL-5 §2.4)."
            )
        priority = ScanPriority(scan.priority)  # raises ValueError on unknown

        # 2. Build ScanJob rows. One unix_ts shared across the scan's
        #    jobs — collision-free because engine varies (idempotency
        #    keys remain unique within the scan).
        tools = SCAN_TYPE_TOOLS[scan.scan_type]
        unix_ts = int(time.time())
        target_url = scan.project.target_url if scan.scan_type != ScanType.MOBILE else ""

        jobs = [
            ScanJob(
                organization_id=scan.organization_id,
                scan_id=scan.id,
                engine=tool,
                target_url=target_url,
                status="queued",
                idempotency_key=f"{scan.id}:{tool}:{unix_ts}",
            )
            for tool in tools
        ]
        for job in jobs:
            self.db.add(job)
        await self.db.flush()

        # 3. Audit. Aggregated at scan level (per-job audit deliberately
        #    skipped — see DRIFT-LOG 2026-04-30 H.2 entry).
        actor_id = identity.user.id if identity.user is not None else None
        details: dict = {
            "scan_type": scan.scan_type.value,
            "priority": priority.value,
            "job_count": len(jobs),
        }
        if identity.api_key is not None:
            details["api_key_prefix"] = identity.api_key.key_prefix

        await audit(
            self.db,
            organization_id=scan.organization_id,
            actor_id=actor_id,
            action=ScanAction.SCAN_DISPATCHED,
            resource_type="scan",
            resource_id=scan.id,
            ip_address=request_ip,
            user_agent=user_agent,
            details=details,  # type: ignore[arg-type]
        )

        # 4. COMMIT — H.3 ordering. After this, DB state is durable.
        await self.db.commit()

        # 5. Build payloads + dispatch to Redis. If this fails AFTER
        #    commit, we have ghost-queued DB rows; M5+ retry janitor
        #    will surface and recover them. Visible failure > silent
        #    failure (DRIFT-LOG H.3 entry).
        for job in jobs:
            payload = await self._build_job_payload(scan, job)
            await self.queue.dispatch(priority.value, payload)

        return jobs

    async def _build_job_payload(self, scan: Scan, job: ScanJob) -> dict:
        """Construct the SPEC §7.1 job-dispatch payload.

        ``auth`` is intentionally ``None`` pending ADR-015 (decrypted
        credentials in Redis transit). Pinned by
        ``test_dispatch_payload_auth_is_null_pending_adr_015``.

        ``callback_stream`` (renamed from plan-literal ``callback_channel``)
        reflects the ADR-014 vocabulary shift to Redis Streams.
        """
        payload: dict = {
            "id": str(job.id),
            "scan_id": str(scan.id),
            "organization_id": str(scan.organization_id),
            "engine": job.engine,
            "idempotency_key": job.idempotency_key,
            "target": {
                "url": scan.project.target_url,
                "target_type": _target_type_for(scan.scan_type),
                "domain_verified": scan.project.domain_verified,
            },
            "auth": None,  # TODO(M5+): inject decrypted credential — see ADR-015 (deferred).
            "config": dict(scan.config or {}),
            "mobile_config": None,
            "callback_stream": f"shieldscan:progress:{scan.id}",
            "created_at": (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            ),
        }

        if scan.scan_type == ScanType.MOBILE and scan.mobile_upload_id is not None:
            upload = await self.db.get(MobileUpload, scan.mobile_upload_id)
            if upload is not None:
                payload["mobile_config"] = {
                    "upload_ref": f"r2://{upload.r2_key}",
                    "platform": upload.platform.value,
                    # Default flipped from "both" to "static" per Task 7.4
                    # D-PLAN-7 Path (c) — engine-side MobSF consumer ships
                    # v1 STATIC only; dynamic + source-tree analysis are
                    # forward-pinned. Overrideable via scan.config when v2
                    # lands. Cross-reference: shieldscan-engine commit (TBD;
                    # Task 7.4 Phase 4 atomic).
                    "analysis_type": (scan.config or {}).get("analysis_type", "static"),
                }

        return payload
