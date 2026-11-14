"""On-prem agents (M14 slice 1; On-Prem Agent Design v1.0 §4).

An agent is a customer-run copy of the engine's job processor that
reaches the cloud only over outbound HTTPS. It is created by an org
admin in Settings → Agents (which mints a one-time enrolment token),
enrolled from the customer machine (token → long-lived agent key,
SHA-256 at rest like API keys), and from then on heartbeats every 30 s
and long-polls for jobs.

NOT under RLS: the row is found by SHA-256 of the agent key before the
tenant is known, so ``agents`` is the second credential-indexed table
(ADR-012 amendment; ``db/policies.CREDENTIAL_INDEXED_TABLES``). Every
org-facing read filters on ``organization_id`` at the application layer,
and the gateway sets the tenant context from the row it found.

``status`` is what the API last knew: ``pending`` until enrolled,
``active`` after, ``revoked`` when an admin revokes. ``offline`` is a
read-time view (``last_seen_at`` older than ``AGENT_OFFLINE_AFTER_S``),
never written.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum as PyEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantMixin, TimestampMixin


class AgentStatus(str, PyEnum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"


class Agent(Base, TimestampMixin, TenantMixin):
    __tablename__ = "agents"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[AgentStatus] = mapped_column(
        Enum(AgentStatus, name="agent_status", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=AgentStatus.PENDING,
    )
    # One-time enrolment token (hash + expiry); cleared on enrolment.
    enrolment_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enrolment_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Long-lived agent key, minted at enrolment. ``key_prefix`` is for display.
    key_prefix: Mapped[str | None] = mapped_column(String(16), nullable=True)
    key_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # name -> {"status": "ok" | "missing" | "error", "version": "..."} from the last heartbeat
    tools: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
