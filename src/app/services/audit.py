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
    """Canonical identifiers for auth-event audit rows.

    Dotted-string values are stable API — log consumers and SIEM
    queries depend on the exact string. Renaming a value is a
    breaking change to the audit contract.

    Values in the ``# === reserved ===`` block are not yet emitted
    by any endpoint but are declared here so the schema does not
    churn as each M2 endpoint lands.
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


class AuditDetails(TypedDict, total=False):
    """Event-specific structured payload for ``audit_logs.details``.

    All keys optional — set only the ones relevant to the emitting
    event. Do NOT add free-form strings: future analytics queries
    need these fields to stay indexable via JSONB operators.
    """

    reason: str  # e.g. "wrong_password", "unverified_email", "rate_limited"
    target_user_id: str  # UUID as str for JSONB stability (UUIDs are not JSON-native)
    api_key_prefix: str
    token_jti: str


async def audit(
    db: AsyncSession,
    *,
    organization_id: UUID,
    actor_id: UUID | None,
    action: AuthAction,
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
