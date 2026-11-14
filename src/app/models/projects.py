from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantMixin, TimestampMixin


def _new_verification_token() -> str:
    return uuid4().hex


class Project(Base, TimestampMixin, TenantMixin):
    __tablename__ = "projects"

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_url: Mapped[str] = mapped_column(String(500), nullable=False)
    root_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_repo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    container_image: Mapped[str | None] = mapped_column(String(255), nullable=True)
    domain_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # M14: bound to an on-prem agent. Scans on this project run only on
    # that agent; domain verification is replaced by the agent enrolment
    # (On-Prem Agent Design v1.0 A5).
    agent_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    verification_token: Mapped[str] = mapped_column(
        String(100), nullable=False, default=_new_verification_token
    )
    archived_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ProjectCredential(Base, TimestampMixin, TenantMixin):
    __tablename__ = "project_credentials"

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    project_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        # UNIQUE: exactly one credential per project. M1 missed this;
        # added in Task 3.X migration d4f6b1e9a527 to enable UPSERT
        # replace-in-place semantics (PATCH /credentials).
        unique=True,
    )
    # See app.services.credentials.AuthType for the canonical enum
    # (Task 3.X lifted M1's inline comment into a proper enum).
    auth_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Fernet-encrypted blob (ciphertext is bytes)
    encrypted_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
