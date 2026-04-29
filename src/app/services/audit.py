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

    # === reserved — declared here to freeze values for later 3.x ===
    PROJECT_CREDENTIAL_SET = "project.credential.set"
    PROJECT_CREDENTIAL_DELETED = "project.credential.deleted"


# Registry of all action-enum classes. Add new enums here as they
# land (ScanAction, FindingAction, etc.) so the global-disjointness
# test auto-covers them without manual updates.
ALL_ACTION_ENUMS: tuple[type[PyEnum], ...] = (AuthAction, ProjectAction)


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


async def audit(
    db: AsyncSession,
    *,
    organization_id: UUID,
    actor_id: UUID | None,
    action: AuthAction | ProjectAction,
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
