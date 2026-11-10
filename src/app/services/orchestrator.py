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
    queued') visible to the customer. VISIBLE failure — easy to
    triage, but NOT automatically recovered: the "M5+ retry janitor"
    this comment named for four months was never built (engine Drift
    #69). ``scripts/backfill_stranded_jobs.py`` (2026-08-20) marks
    such rows FAILED so their scan can aggregate; re-dispatch is
    still manual.
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

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Final
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import AuthIdentity
from app.models.audit import AuditLog
from app.models.mobile import MobileUpload
from app.models.projects import Project, ProjectCredential
from app.models.recon import AttackSurface
from app.models.scans import Scan, ScanJob, ScanStatus, ScanType
from app.services.audit import ScanAction, audit
from app.services.credentials import decrypt_credential
from app.services.r2 import generate_presigned_get_url
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
# a separate job payload and there's no inter-tool sequencing here.
#
# M8.1β.2 ADR-028 (SPEC §13): subfinder + httpx are NO LONGER in any
# entry. Recon is dispatched as a phase-1 engine="recon" ScanJob
# (orchestrator-implicit for web-ScanTypes; see _WEB_SCAN_TYPES +
# dispatch()), keeping SCAN_TYPE_TOOLS semantically pure as a
# tools-only list. The tools below are the phase-2 per-(target, tool)
# dispatch set for web-ScanTypes (after recon-driven target expansion)
# and the direct dispatch set for non-web-ScanTypes. Drift #60
# recon-orphan sub-category resolved structurally (subfinder + httpx
# removed; no longer dispatch to an unregistered engine).
SCAN_TYPE_TOOLS: Final[dict[ScanType, tuple[str, ...]]] = {
    ScanType.QUICK: ("nuclei", "sslyze"),
    ScanType.FULL_WEB: (
        "nuclei",
        "zap",
        "wapiti",
        "nikto",
        "nmap",
        "sslyze",
    ),
    ScanType.FULL_WEB_SOURCE: (
        "nuclei",
        "zap",
        "wapiti",
        "nikto",
        "nmap",
        "sslyze",
        "semgrep",
        "gitleaks",
        "depcheck",
    ),
    ScanType.API: ("nuclei", "zap", "corstest", "sqlmap"),
    ScanType.MOBILE: ("mobsf",),
    ScanType.CONTAINER: ("trivy-container", "checkov"),
    ScanType.FULL_SPECTRUM: (
        "nuclei",
        "zap",
        "wapiti",
        "nikto",
        "sqlmap",
        "nmap",
        "sslyze",
        "semgrep",
        "gitleaks",
        "depcheck",
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


def _build_config_block(scan: Scan) -> dict:
    """SPEC §7.1 ``config`` block — merges per-ScanType variant
    defaults with caller-supplied ``scan.config``.

    Per M8.1β.1 engine-variant resolution (SPEC §13 ADR-022 addendum
    continuation, shieldscan-docs ``bb3e75f``): the artificial
    ``nuclei_fast`` engine name (former QUICK ScanType entry) is
    folded into ``engine=nuclei`` plus a default ``depth="quick"``
    injected here. Caller-supplied ``scan.config["depth"]`` wins —
    operators tuning at scan-create time stay authoritative.

    The engine ``ScanConfig.Depth`` knob (Go side, ``runner.go:206``)
    translates per-tool: Nuclei → ``-severity high,critical`` for
    "quick"; Wapiti → scan-module reduction; etc.
    """
    block = dict(scan.config or {})
    depth_default = _DEPTH_FOR_SCAN_TYPE.get(scan.scan_type)
    if depth_default is not None and "depth" not in block:
        block["depth"] = depth_default
    # M13: QUICK means the same thing everywhere — the passive template set
    # the public endpoint runs (headers, cookies, exposures, TLS, DNS,
    # fingerprints) with no severity filter. The old "quick" depth
    # (high/critical only) returned 0 findings on Juice Shop while the
    # public scan of the same host returned 19. Caller-supplied values win.
    if scan.scan_type == ScanType.QUICK and "template_categories" not in block:
        block["template_categories"] = list(QUICK_TEMPLATE_TAGS)
    return block


# Source-Ingestion Fix (TOOL-ARCH §3.2 addendum 9d6ab25): ScanTypes
# that dispatch ``trivy-fs`` and therefore require ``source_repo_url``
# threaded into the wire ``target`` block. Engine clones at job-pickup
# time per Q-WIRE engine-clones lock.
_SOURCE_REQUIRING_SCAN_TYPES: frozenset[ScanType] = frozenset({
    ScanType.FULL_WEB_SOURCE,
    ScanType.FULL_SPECTRUM,
})


# M8.1β.1 engine-variant resolution (SPEC §13 ADR-022 addendum
# continuation; bb3e75f): per-ScanType default value of
# ScanConfig.Depth ("quick" | "standard" | "deep"). The engine
# Nuclei runner consumes this knob via buildArgs(cfg) to translate
# to its severity filter (-severity high,critical for "quick", etc.).
# Other DAST tools (Wapiti) also honor Depth per runner.go:206-211.
#
# Per Y-ENGINE-VARIANT-RESOLUTION (a) config-flag, the artificial
# nuclei_fast engine name (former QUICK ScanType entry) is folded
# into engine=nuclei + Depth="quick". For ScanTypes that don't
# require a Depth override, the wire ``config`` block stays whatever
# scan.config carried (caller-supplied or empty). Per-scan
# scan.config wins over the default — operators can still tune.
_DEPTH_FOR_SCAN_TYPE: Final[dict[ScanType, str]] = {
    ScanType.QUICK: "deep",  # no severity filter; the tag set below bounds the run
}

# Nuclei template tags for a quick scan (engine maps them to -tags). Shared
# with services/public_scans.py so in-app and public quick scans agree.
QUICK_TEMPLATE_TAGS: Final[tuple[str, ...]] = ("misconfig", "exposure", "ssl", "dns", "tech")


# M8.1β.2 ADR-028 recon-first architecture (SPEC §13; design doc
# 3f07611; plan fb61129). Web-ScanTypes dispatch a single phase-1
# recon ScanJob (engine="recon"; orchestrator-implicit per Y-RECON-
# ENGINE-NAME a.ii); the per-(target, tool) tool ScanJobs are
# dispatched at phase-2 (dispatch_phase2) after recon emits
# EventAttackSurface → completions_consumer UPSERTs AttackSurface.
# Non-web ScanTypes (API, MOBILE, CONTAINER) skip phase-1 and
# dispatch all SCAN_TYPE_TOOLS engines directly (no recon phase).
_WEB_SCAN_TYPES: Final[frozenset[ScanType]] = frozenset({
    ScanType.QUICK,
    ScanType.FULL_WEB,
    ScanType.FULL_WEB_SOURCE,
    ScanType.FULL_SPECTRUM,
})


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
        unix_ts = int(time.time())
        target_url = scan.project.target_url if scan.scan_type != ScanType.MOBILE else ""
        if scan.is_public:
            # Public quick scans probe the exact URL the requester typed
            # (path included); the system-org project only groups them.
            target_url = (scan.config or {}).get("target_url") or target_url

        if scan.scan_type in _WEB_SCAN_TYPES and not scan.is_public:
            # M8.1β.2 ADR-028 Phase-1: dispatch a SINGLE recon ScanJob
            # (engine="recon"; orchestrator-implicit per Y-RECON-ENGINE-
            # NAME a.ii). The per-(target, tool) tool ScanJobs are
            # dispatched at phase-2 (dispatch_phase2) after recon emits
            # EventAttackSurface → completions_consumer UPSERTs
            # AttackSurface. The engine processor.Process routes
            # engine="recon" to recon.RunRecon directly (NOT via
            # registry per ADR-022; engine commit 2cf6f5d).
            jobs = [
                ScanJob(
                    organization_id=scan.organization_id,
                    scan_id=scan.id,
                    engine="recon",
                    target_url=target_url,
                    status="queued",
                    # Y-RECON-SCANJOB-IDEMPOTENCY-KEY (a): one recon job
                    # per scan; no per-target hash needed at phase-1.
                    idempotency_key=f"{scan.id}:recon:{unix_ts}",
                )
            ]
        else:
            # Non-web ScanTypes (API, MOBILE, CONTAINER): no recon phase;
            # dispatch all SCAN_TYPE_TOOLS engines directly (existing
            # behavior preserved).
            #
            # Public quick scans (``scan.is_public``, M11 pre-work) take
            # this path too: no recon, no subdomain expansion — the free
            # scan probes exactly the URL the requester typed, which is
            # what keeps it bounded (a public scan of a large domain must
            # never fan out into hundreds of jobs). See DRIFT-LOG
            # 2026-11-07 (public quick scans).
            tools = SCAN_TYPE_TOOLS[scan.scan_type]
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

        # 3b. ADR-015 enablement — credential lookup + decrypt + audit.
        #     ProjectCredential is per-project (unique=True per M1
        #     invariant + Task 3.X migration d4f6b1e9a527); scalar_one_
        #     or_none returns 0-or-1 row. Decrypt + audit ONCE per
        #     dispatch (not per job — credential is per-project, not
        #     per-tool). Audit policy: scan-level only per
        #     ScanAction docstring (per-job audit deliberately skipped).
        #     auth_payload (or None) is threaded into _build_job_payload
        #     so every job in this dispatch carries the same auth.
        cred_result = await self.db.execute(
            select(ProjectCredential).where(
                ProjectCredential.project_id == scan.project_id
            )
        )
        credential = cred_result.scalar_one_or_none()
        auth_payload: dict | None = None
        if credential is not None:
            decrypted = decrypt_credential(credential.encrypted_data)
            # Q3 (a) discriminator translation: DB `auth_type` → wire `type`.
            auth_payload = {
                "type": credential.auth_type,
                "data": decrypted["data"],
            }
            if "fields" in decrypted:
                auth_payload["fields"] = decrypted["fields"]
            await audit(
                self.db,
                organization_id=scan.organization_id,
                actor_id=actor_id,
                action=ScanAction.SCAN_CREDENTIAL_DECRYPTED,
                resource_type="scan",
                resource_id=scan.id,
                ip_address=request_ip,
                user_agent=user_agent,
                details={
                    "credential_id": str(credential.id),
                    "credential_auth_type": credential.auth_type,
                },  # type: ignore[arg-type]
            )

        # 3c. MobSF R2 pre-signed URL task — mobile_config lookup +
        #     URL generation + audit. Single-lookup + single-URL +
        #     single-audit per dispatch (ScanAction policy: scan-level
        #     only, never per-job; mirrors Drift #42 emission-site
        #     refactor from ADR-015 enablement; mirrors Q1 (β)
        #     sibling-field decision: emit both upload_ref +
        #     signed_fetch_url during migration window per ADR-013
        #     Pre-Signed URL Extension addendum at 8f71b01).
        mobile_payload: dict | None = None
        if scan.scan_type == ScanType.MOBILE and scan.mobile_upload_id is not None:
            upload = await self.db.get(MobileUpload, scan.mobile_upload_id)
            if upload is not None:
                # Q2 (a) 600s default expiry per R2 design doc b25e9ba §3.2.
                signed_url = await generate_presigned_get_url(
                    r2_key=upload.r2_key, expiry=600
                )
                mobile_payload = {
                    "upload_ref": f"r2://{upload.r2_key}",
                    "signed_fetch_url": signed_url,
                    "platform": upload.platform.value,
                    # Default flipped from "both" to "static" per Task 7.4
                    # D-PLAN-7 Path (c) — engine-side MobSF consumer ships
                    # v1 STATIC only; dynamic + source-tree analysis are
                    # forward-pinned. Overrideable via scan.config when v2
                    # lands.
                    "analysis_type": (scan.config or {}).get(
                        "analysis_type", "static"
                    ),
                }
                # Q5 (a) SCAN_PRESIGNED_URL_GENERATED audit per R2 design
                # doc b25e9ba §3.5 (analog to ADR-015 SCAN_CREDENTIAL_
                # DECRYPTED forensics posture).
                await audit(
                    self.db,
                    organization_id=scan.organization_id,
                    actor_id=actor_id,
                    action=ScanAction.SCAN_PRESIGNED_URL_GENERATED,
                    resource_type="scan",
                    resource_id=scan.id,
                    ip_address=request_ip,
                    user_agent=user_agent,
                    details={
                        "r2_key": upload.r2_key,
                        "expiry_seconds": 600,
                    },  # type: ignore[arg-type]
                )

        # 4. COMMIT — H.3 ordering. After this, DB state is durable.
        await self.db.commit()

        # 5. Build payloads + dispatch to Redis. If this fails AFTER
        #    commit, we have ghost-queued DB rows. Visible failure >
        #    silent failure (DRIFT-LOG H.3 entry) — but nothing
        #    re-dispatches them; see the module docstring.
        for job in jobs:
            payload = await self._build_job_payload(
                scan,
                job,
                auth_payload,
                mobile_payload,
                # Public quick scans: wire target is the typed URL (set on
                # the ScanJob above), not the system project's root.
                target_url_override=job.target_url if scan.is_public else None,
            )
            await self.queue.dispatch(priority.value, payload)

        return jobs

    async def _build_job_payload(
        self,
        scan: Scan,
        job: ScanJob,
        auth_payload: dict | None,
        mobile_payload: dict | None,
        target_url_override: str | None = None,
    ) -> dict:
        """Construct the SPEC §7.1 job-dispatch payload.

        ``auth_payload`` is the pre-built credential dict (or None)
        constructed once per dispatch in ``dispatch()`` per ADR-015
        enablement; every job in a dispatch shares the same auth.
        ``None`` is the canonical credential-less-project value
        (legacy null path preserved).

        ``mobile_payload`` is the pre-built MobSF mobile-config dict
        (or None) constructed once per dispatch in ``dispatch()`` per
        MobSF R2 pre-signed URL task; includes both ``upload_ref``
        (legacy r2:// reference) + ``signed_fetch_url`` (Q1 (β)
        sibling-field per ADR-013 Pre-Signed URL Extension addendum).

        ``target_url_override`` (M8.1β.2 ADR-028 phase-2): when set, the
        wire ``target.url`` is the discovered subdomain URL rather than
        the project root ``target_url``. Phase-2 per-(target, tool)
        ScanJobs scan the recon-discovered live subdomains; the default
        None preserves existing phase-1 / non-web behavior (root URL).

        ``callback_stream`` (renamed from plan-literal ``callback_channel``)
        reflects the ADR-014 vocabulary shift to Redis Streams.
        """
        target_block: dict = {
            "url": target_url_override or scan.project.target_url,
            "target_type": _target_type_for(scan.scan_type),
            "domain_verified": scan.project.domain_verified,
        }
        # Source-Ingestion Fix (TOOL-ARCH §3.2 addendum 9d6ab25):
        # thread source_repo_url for ScanTypes that dispatch trivy-fs
        # per Q-WIRE engine-clones lock. Engine clones at job-pickup
        # time (lazy per-job at worker per Q-RECON-TIMING) and stages
        # under $TRIVY_SCAN_BASE_PATH/<scan_id>/ per Q-STAGING-PATH.
        # ScanCreateRequest validator (routes/scans.py) guarantees
        # source_repo_url is non-None when scan_type requires it.
        # Drift #54 root-cause repair (api layer).
        if scan.scan_type in _SOURCE_REQUIRING_SCAN_TYPES:
            target_block["source_repo_url"] = scan.project.source_repo_url
        return {
            "id": str(job.id),
            "scan_id": str(scan.id),
            "organization_id": str(scan.organization_id),
            "engine": job.engine,
            "idempotency_key": job.idempotency_key,
            "target": target_block,
            "auth": auth_payload,
            "config": _build_config_block(scan),
            "mobile_config": mobile_payload,
            "callback_stream": f"shieldscan:progress:{scan.id}",
            "created_at": (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            ),
        }

    # ============================================================ M8.1β.2 phase-2

    async def dispatch_phase2(self, *, scan_id: UUID) -> list[ScanJob]:
        """ADR-028 Phase-2: dispatch per-(target, tool) ScanJobs after
        recon completes.

        Invoked by ``completions_consumer._handle_attack_surface`` in a
        fresh session after the AttackSurface UPSERT commits (Q7 c.ii
        sequential sessions). Self-contained like ``dispatch()``:
        persist + audit + commit + enqueue. The caller sets the RLS GUC
        (``app.current_org_id``) before calling.

        Per Q1 (c) hybrid follow-up dispatch + Q7 (c) orchestrator
        method + Q7.4 V-WD Option α audit-log lookup (Drift #61
        refinement). Identity context is recovered from the most recent
        ``SCAN_DISPATCHED`` AuditLog row's ``actor_id`` (V-XB query
        pattern: ``resource_type='scan'`` + ``resource_id=scan_id``) —
        no AuthIdentity object is reconstructed (``audit()`` takes
        ``actor_id`` directly; AuthIdentity is a frozen dataclass with
        ``user: User``, not ``user_id``, so a partial reconstruction
        would be ill-typed — Y-AUTHIDENTITY-RECONSTRUCTION-SHAPE (a)
        minimal resolves to actor_id-only).

        Empty-AttackSurface is correct behavior (Q2 i recon-first
        semantics): zero phase-2 jobs, but the SCAN_DISPATCHED_PHASE2
        audit is still emitted (Q5 b.i always-emit). Dispatch-precondition
        failures (no dispatch-audit / scan-not-found) fail loud (Q7
        c.ii.B) via ``_fail_scan_phase2``.
        """
        # Q7.4 Option α: audit-log lookup for identity context.
        dispatch_row = (
            await self.db.execute(
                select(AuditLog)
                .where(
                    AuditLog.resource_type == "scan",
                    AuditLog.resource_id == scan_id,
                    AuditLog.action == ScanAction.SCAN_DISPATCHED.value,
                )
                .order_by(AuditLog.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if dispatch_row is None:
            # Implicit-ordering-dependency violation (ADR-028 documented
            # constraint): phase-2 trigger fired without a phase-1
            # SCAN_DISPATCHED audit. Fail loud.
            await self._fail_scan_phase2(scan_id, reason="no_dispatch_audit_found")
            return []
        actor_id = dispatch_row.actor_id

        scan = await self.db.get(Scan, scan_id)
        if scan is None:
            await self._fail_scan_phase2(
                scan_id, reason="scan_not_found", actor_id=actor_id
            )
            return []
        # No ORM relationship for Scan.project (route handler + dispatch
        # set it ad-hoc); load + attach for _build_job_payload.
        project = await self.db.get(Project, scan.project_id)
        scan.project = project  # type: ignore[attr-defined]

        priority = ScanPriority(scan.priority)

        # Load the recon-discovered live attack surface.
        surface_rows = list(
            (
                await self.db.execute(
                    select(AttackSurface).where(AttackSurface.scan_id == scan_id)
                )
            ).scalars()
        )

        non_recon_tools = [
            t for t in SCAN_TYPE_TOOLS[scan.scan_type] if t != "recon"
        ]

        # Empty-AttackSurface (Q2 i): no live targets → no phase-2 jobs.
        # Still emit the phase-2 audit (Q5 b.i) for operator visibility.
        if not surface_rows:
            await self._emit_phase2_audit(
                scan,
                actor_id=actor_id,
                target_count=0,
                tool_count=len(non_recon_tools),
                job_count=0,
                recon_event_id=dispatch_row.id,
            )
            await self.db.commit()
            return []

        # Credential lookup for the phase-2 tool jobs (no audit — the
        # SCAN_CREDENTIAL_DECRYPTED audit was already emitted at phase-1
        # dispatch; re-emitting here would double-count).
        credential = (
            await self.db.execute(
                select(ProjectCredential).where(
                    ProjectCredential.project_id == scan.project_id
                )
            )
        ).scalar_one_or_none()
        auth_payload: dict | None = None
        if credential is not None:
            decrypted = decrypt_credential(credential.encrypted_data)
            auth_payload = {
                "type": credential.auth_type,
                "data": decrypted["data"],
            }
            if "fields" in decrypted:
                auth_payload["fields"] = decrypted["fields"]

        # Build per-(target, tool) ScanJobs. Idempotency-key per Q2
        # (a.ii): {scan_id}:{tool}:{sha256(target_url)[:16]}:{ts} —
        # deterministic per (scan, tool, target), order-independent.
        unix_ts = int(time.time())
        created_jobs: list[ScanJob] = []
        for surface in surface_rows:
            target_hash = hashlib.sha256(
                surface.full_url.encode()
            ).hexdigest()[:16]
            for tool in non_recon_tools:
                created_jobs.append(
                    ScanJob(
                        organization_id=scan.organization_id,
                        scan_id=scan_id,
                        engine=tool,
                        target_url=surface.full_url,
                        status="queued",
                        idempotency_key=f"{scan_id}:{tool}:{target_hash}:{unix_ts}",
                    )
                )
        for job in created_jobs:
            self.db.add(job)
        await self.db.flush()

        await self._emit_phase2_audit(
            scan,
            actor_id=actor_id,
            target_count=len(surface_rows),
            tool_count=len(non_recon_tools),
            job_count=len(created_jobs),
            recon_event_id=dispatch_row.id,
        )

        # H.3 commit-then-dispatch ordering (mirrors dispatch()).
        await self.db.commit()

        for job in created_jobs:
            payload = await self._build_job_payload(
                scan,
                job,
                auth_payload,
                None,
                target_url_override=job.target_url,
            )
            await self.queue.dispatch(priority.value, payload)

        return created_jobs

    async def _emit_phase2_audit(
        self,
        scan: Scan,
        *,
        actor_id: UUID | None,
        target_count: int,
        tool_count: int,
        job_count: int,
        recon_event_id: UUID,
    ) -> None:
        """Emit SCAN_DISPATCHED_PHASE2 (Q5 b two-phase + b.i always-emit
        + rich details). Does not commit (caller owns the transaction
        boundary)."""
        await audit(
            self.db,
            organization_id=scan.organization_id,
            actor_id=actor_id,
            action=ScanAction.SCAN_DISPATCHED_PHASE2,
            resource_type="scan",
            resource_id=scan.id,
            details={
                "scan_type": scan.scan_type.value,
                "priority": scan.priority,
                "phase": "tools",
                "target_count": target_count,
                "tool_count": tool_count,
                "job_count": job_count,
                "recon_event_id": str(recon_event_id),
            },  # type: ignore[arg-type]
        )

    async def _fail_scan_phase2(
        self,
        scan_id: UUID,
        *,
        reason: str,
        actor_id: UUID | None = None,
    ) -> None:
        """Fail-loud phase-2 dispatch (Q7 c.ii.B) with a diagnostic-rich
        SCAN_FAILED audit (Y-PHASE2-DISPATCH-FAILURE-AUDIT-SHAPE b).
        Marks the scan FAILED when it exists; commits its own transaction
        (the surrounding dispatch_phase2 returns early after this)."""
        scan = await self.db.get(Scan, scan_id)
        org_id = scan.organization_id if scan is not None else None
        if scan is not None:
            scan.status = ScanStatus.FAILED
        if org_id is not None:
            await audit(
                self.db,
                organization_id=org_id,
                actor_id=actor_id,
                action=ScanAction.SCAN_FAILED,
                resource_type="scan",
                resource_id=scan_id,
                details={
                    "phase": "tools",
                    "failure": "phase2_dispatch_precondition",
                    "reason": reason,
                },  # type: ignore[arg-type]
            )
        await self.db.commit()

    # AI pipeline queue (ADR-029 Q1 e.ii). Distinct from the per-priority
    # ScanQueue lists — a single list the in-api AIPipelineConsumer BRPOPs.
    AI_PIPELINE_QUEUE = "shieldscan:ai_pipeline"

    async def dispatch_ai_pipeline(self, *, scan_id: UUID) -> None:
        """Transition a scan to ANALYZING and enqueue it for the AI pipeline.

        ADR-029 Q1 e.ii: invoked by completions_consumer in a fresh session
        (sequential per Q7 c.ii) once all jobs are terminal AND raw_findings
        exist. Mirrors ``dispatch_phase2`` — orchestrator owns the writes:
        status → ANALYZING, LPUSH {scan_id, organization_id} onto
        ``shieldscan:ai_pipeline`` (org_id travels in the payload so the
        consumer can set its RLS GUC before loading the scan), and emits the
        SCAN_DISPATCHED_AI_PIPELINE audit. Self-contained commit.

        The terminal COMPLETED/PARTIAL transition + SCAN_COMPLETED audit are
        the AIPipelineConsumer's responsibility after the pipeline runs (DQ2 /
        DQ5).
        """
        scan = await self.db.get(Scan, scan_id)
        if scan is None:
            raise RuntimeError(f"scan {scan_id} not found at dispatch_ai_pipeline")

        scan.status = ScanStatus.ANALYZING
        await self.db.flush()

        await audit(
            self.db,
            organization_id=scan.organization_id,
            actor_id=None,  # system-driven (consumer context), no user actor
            action=ScanAction.SCAN_DISPATCHED_AI_PIPELINE,
            resource_type="scan",
            resource_id=scan.id,
            details={
                "scan_type": scan.scan_type.value,
                "priority": scan.priority,
                "phase": "ai_pipeline",
            },  # type: ignore[arg-type]
        )
        await self.db.commit()

        # Enqueue after commit — the ANALYZING transition is durable before the
        # consumer can pick the work up. Fire-and-forget LPUSH (ADR-014).
        await self.queue.redis.lpush(
            self.AI_PIPELINE_QUEUE,
            json.dumps(
                {
                    "scan_id": str(scan_id),
                    "organization_id": str(scan.organization_id),
                }
            ),
        )
