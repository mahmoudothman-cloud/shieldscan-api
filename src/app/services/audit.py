"""Audit logger helper + canonical AuthAction enum (Sub-task 2.3.2).

Every auth-related event writes one ``audit_logs`` row via ``audit(...)``.
The helper is deliberately stateless and context-free — it accepts
IP/user-agent as arguments rather than reading from an HTTP request,
so scheduled jobs and CLI tools can emit the same event shape.

Idempotency is the caller's responsibility: calling ``audit(...)``
twice in the same transaction writes two rows. A regression test
pins that behavior so any future "silent dedupe" refactor has to be
an explicit design change.

The ``details`` JSONB column holds event-specific structured data
(never free-form strings). ``AuditDetails`` is a ``TypedDict`` so
callers get IDE hints and future-us can grep every call site if the
shape ever needs migration.

Note: ``ip_address`` and ``user_agent`` live in dedicated top-level
columns on ``audit_logs`` (INET and Text respectively), not inside
``details``. INET is indexable for CIDR queries; keeping them out
of JSONB preserves that. Callers pass them as top-level kwargs.
"""

from __future__ import annotations

from enum import Enum as PyEnum
from typing import TypedDict
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog


class AuthAction(str, PyEnum):
    """Canonical identifiers for auth-domain audit rows.

    Dotted-string values are stable API — log consumers and SIEM
    queries depend on the exact string. Renaming a value is a
    breaking change to the audit contract.

    Per-domain enum split (Task 3.2): ``AuthAction`` carries auth
    events; ``ProjectAction`` (below) carries project events. Future
    domains (scans, findings, credentials) get their own enums.
    The single ``audit_logs.action`` column accepts strings from any
    enum; the enum-side guard is for typo prevention. Disjointness
    of string values across enums is regression-tested
    (``test_action_enum_values_are_globally_disjoint``).

    Values in the ``# === reserved ===`` block are not yet emitted
    by any endpoint but are declared here so the schema does not
    churn as each endpoint lands.
    """

    # === emitted in M2.3 ===
    USER_REGISTERED = "user.registered"
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILURE = "auth.login.failure"
    LOGOUT = "auth.logout"
    TOKEN_REFRESHED = "auth.token.refreshed"
    TOKEN_REVOKED = "auth.token.revoked"

    # === reserved — land in later M2 sub-tasks, declared here to
    #     freeze the enum values and prevent schema churn ===
    PASSWORD_CHANGED = "auth.password.changed"
    EMAIL_VERIFIED = "auth.email.verified"
    EMAIL_VERIFICATION_SENT = "auth.email.verification_sent"
    PASSWORD_RESET_REQUESTED = "auth.password.reset.requested"
    PASSWORD_RESET_COMPLETED = "auth.password.reset.completed"
    API_KEY_CREATED = "auth.api_key.created"
    API_KEY_REVOKED = "auth.api_key.revoked"


class ProjectAction(str, PyEnum):
    """Project-domain audit events. Split from ``AuthAction`` at
    Task 3.2 to prevent the auth enum from becoming a sprawling
    catch-all (see DRIFT-LOG 2026-04-23 audit-enum-split entry).

    Same dotted-string contract as AuthAction. Disjoint from
    AuthAction's values — pinned by
    ``test_action_enum_values_are_globally_disjoint``.

    Reserved values are declared early to prevent schema churn as
    later M3 sub-tasks land their endpoints (project credentials,
    stats endpoints, etc.).
    """

    # === emitted starting in Task 3.1 (back-fill) + 3.2 ===
    PROJECT_CREATED = "project.created"
    PROJECT_UPDATED = "project.updated"
    PROJECT_ARCHIVED = "project.archived"
    PROJECT_DOMAIN_VERIFIED = "project.domain.verified"
    PROJECT_DOMAIN_VERIFICATION_FAILED = "project.domain.verification_failed"
    # === emitted starting in Task 3.3 ===
    PROJECT_MOBILE_UPLOADED = "project.mobile.uploaded"
    # === emitted starting in Task 3.X ===
    PROJECT_CREDENTIAL_SET = "project.credential.set"
    PROJECT_CREDENTIAL_DELETED = "project.credential.deleted"
    # === emitted starting in Credential Revocation Flow task (2026-05-28) ===
    # Per SPEC §13 ADR-015 Addendum: Credential Lifecycle Extension.
    # Emitted at revoke-action (BEFORE delete); cascade-canceled scans
    # emit existing ScanAction.SCAN_CANCELED per Task 4.5 reuse (Q6 b).
    PROJECT_CREDENTIAL_REVOKED = "project.credential.revoked"


class ScanAction(str, PyEnum):
    """Scan-domain audit events (Task 4.2).

    Splits from ``ProjectAction`` for the same reason that split from
    ``AuthAction`` at Task 3.2: keep per-domain enums focused, prevent
    a sprawling catch-all. Disjoint from the other action enums per
    ``test_action_enum_values_are_globally_disjoint`` (auto-covered
    via ``ALL_ACTION_ENUMS`` registry).

    Audit policy for scans (DRIFT-LOG 2026-04-30 — terminal-aggregate-
    only): per-job completion is captured in ``scan_jobs.status``
    column, NOT in ``audit_logs``. Only scan-level transitions emit
    audit rows. Don't ``helpfully'' add per-job audit values here —
    that dilutes the audit log and breaks the design pin.
    """

    # === emitted in M4 ===
    SCAN_DISPATCHED = "scan.dispatched"  # Task 4.2 orchestrator
    SCAN_DISPATCHED_PHASE2 = "scan.dispatched_phase2"  # M8.1β.2 ADR-028 phase-2 tool dispatch
    SCAN_DISPATCHED_AI_PIPELINE = "scan.dispatched_ai_pipeline"  # M9.0 ADR-029 Q1 e.ii AI pipeline dispatch
    SCAN_CANCELED = "scan.canceled"  # Task 4.5 cancel endpoint
    SCAN_COMPLETED = "scan.completed"  # Task 4.2 completions consumer (terminal)
    SCAN_FAILED = "scan.failed"  # Task 4.2 completions consumer (terminal)
    SCAN_COMPARED = "scan.compared"  # Task 4.6 compare endpoint

    # === emitted in M5+ (ADR-015 enablement) ===
    SCAN_CREDENTIAL_DECRYPTED = "scan.credential_decrypted"  # ADR-015 enablement; one row per credential-bearing dispatch

    # === emitted in M5+ (MobSF R2 pre-signed URL task) ===
    SCAN_PRESIGNED_URL_GENERATED = "scan.presigned_url_generated"  # MobSF R2 task; one row per mobile-scan-dispatch consuming pre-signed R2 URL

    # === reserved — declared early to freeze values for M5+ ===
    SCAN_JOB_RETRIED = "scan.job.retried"  # M5+ worker retry policy


class VulnerabilityAction(str, PyEnum):
    """Vulnerability-domain audit events (M10.A Task 10.1).

    Split per the established per-domain enum discipline (AuthAction →
    ProjectAction → ScanAction lineage; anti-catch-all design pin).
    """

    VULNERABILITY_STATUS_CHANGED = "vulnerability.status_changed"  # M10.A PATCH endpoint; one row per actual transition (Q8)


class OrgAction(str, PyEnum):
    """Organization-domain audit events (M11 pre-work: settings + members).

    Same per-domain split as the enums above. Membership changes are the
    one place a tenant's trust boundary moves, so every one of them is a
    row: who was added, with which role, by whom; every role change with
    its from/to; every removal.
    """

    ORG_UPDATED = "organization.updated"  # PATCH /orgs/{id}; details.fields lists what changed
    MEMBER_INVITED = "organization.member_invited"  # POST /members; details.target_user_id + role
    MEMBER_ROLE_CHANGED = "organization.member_role_changed"  # PATCH /members/{uid}; previous_role → role
    MEMBER_REMOVED = "organization.member_removed"  # DELETE /members/{uid}


# Registry of all action-enum classes. Add new enums here as they
# land (FindingAction, etc.) so the global-disjointness test
# auto-covers them without manual updates.
ALL_ACTION_ENUMS: tuple[type[PyEnum], ...] = (
    AuthAction,
    ProjectAction,
    ScanAction,
    VulnerabilityAction,
    OrgAction,
)


class AuditDetails(TypedDict, total=False):
    """Event-specific structured payload for ``audit_logs.details``.

    Holds event-specific metadata only. Request-context fields
    (``ip_address``, ``user_agent``) are top-level columns on
    ``audit_logs``, not part of ``details`` — they use dedicated
    INET/Text columns for indexable CIDR queries. Populate them via
    the ``audit()`` kwargs.

    All keys optional — set only the ones relevant to the emitting
    event. Do NOT add free-form strings: future analytics queries
    need these fields to stay indexable via JSONB operators.
    """

    reason: str  # e.g. "wrong_password", "unverified_email", "rate_limited"
    target_user_id: str  # UUID as str for JSONB stability (UUIDs are not JSON-native)
    api_key_prefix: str
    token_jti: str
    method: str  # e.g. "email", "sms" — channel for verification/reset actions
    platform: str  # e.g. "android", "ios" — mobile-upload events
    size_bytes: int  # bytes of the uploaded artifact (mobile uploads)
    scan_type: str  # e.g. "full_web", "mobile" — scan-domain events
    priority: str  # e.g. "normal", "high" — scan dispatch
    job_count: int  # number of ScanJob rows dispatched
    finding_count: int  # aggregate findings from a completed scan
    failure_reason: str  # e.g. "all_jobs_failed" — terminal-state context
    role: str  # membership role granted / resulting ("admin" | "member" | "viewer")
    previous_role: str  # membership role before a change
    fields: list[str]  # names of the org settings fields a PATCH changed
    invited_new_user: bool  # invite created the user (vs. added an existing one)


async def audit(
    db: AsyncSession,
    *,
    organization_id: UUID,
    actor_id: UUID | None,
    action: AuthAction | ProjectAction | ScanAction | VulnerabilityAction | OrgAction,
    resource_type: str,
    resource_id: UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details: AuditDetails | None = None,
) -> AuditLog:
    """Append one row to ``audit_logs`` inside the caller's transaction.

    Does **not** commit — the caller's ``async with db.begin():`` owns
    the transaction boundary. If the surrounding transaction rolls
    back, the audit row rolls back with it, which is correct: we do
    not want audit entries for events that didn't actually happen.

    ``actor_id=None`` is legal for system-generated events (scheduled
    jobs, webhook handlers without a user context). ``organization_id``
    is always required and must match the RLS tenant context
    (``SET app.current_org_id``); the RLS ``WITH CHECK`` clause will
    reject the INSERT otherwise.

    Returns the created ``AuditLog`` instance (post-``flush``), so
    callers who want the id can have it.
    """
    row = AuditLog(
        organization_id=organization_id,
        actor_id=actor_id,
        action=action.value,  # store the dotted string, not the enum repr
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
        details=dict(details) if details is not None else None,
    )
    db.add(row)
    await db.flush()
    return row
