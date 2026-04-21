"""Structural tests for Base/TenantMixin/TimestampMixin.

Uses a throwaway DeclarativeBase per test so the fake models don't register
with the real `app.models.base.Base.metadata` (which would break
create_all/drop_all in later tests — those leak FKs onto `organizations`).
"""

from sqlalchemy import Integer, inspect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.models.base import TenantMixin, TimestampMixin


def test_tenantmixin_has_org_id_column() -> None:
    class _IsolatedBase(DeclarativeBase):
        pass

    class TenantModel(_IsolatedBase, TenantMixin):
        __tablename__ = "isolated_tenant_model"
        id: Mapped[int] = mapped_column(Integer, primary_key=True)

    cols = {c.name for c in inspect(TenantModel).columns}
    assert "organization_id" in cols


def test_timestampmixin_has_created_and_updated_at() -> None:
    class _IsolatedBase(DeclarativeBase):
        pass

    class TimestampedModel(_IsolatedBase, TimestampMixin):
        __tablename__ = "isolated_timestamped_model"
        id: Mapped[int] = mapped_column(Integer, primary_key=True)

    cols = {c.name for c in inspect(TimestampedModel).columns}
    assert "created_at" in cols
    assert "updated_at" in cols
