from __future__ import annotations

from datetime import datetime
from enum import Enum as PyEnum
from uuid import UUID, uuid4

from sqlalchemy import BigInteger, DateTime, Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantMixin, TimestampMixin


class MobilePlatform(str, PyEnum):
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


class MobileUpload(Base, TimestampMixin, TenantMixin):
    __tablename__ = "mobile_uploads"

    id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    project_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Nullable: API-key uploads have no user actor (Task 3.3, mirrors the
    # audit_logs.actor_id pattern from Task 2.3.2). Migration
    # c8e3d2a4f9b1 dropped NOT NULL. JWT upload writes the user.id;
    # API-key upload writes NULL.
    uploaded_by: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_extension: Mapped[str] = mapped_column(String(10), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    platform: Mapped[MobilePlatform] = mapped_column(
        Enum(MobilePlatform, name="mobile_platform"), nullable=False
    )
    r2_key: Mapped[str] = mapped_column(String(500), nullable=False)
    mobsf_file_hash: Mapped[str | None] = mapped_column(String(100), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
