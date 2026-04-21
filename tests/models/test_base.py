from sqlalchemy import inspect

from app.models.base import Base, TenantMixin, TimestampMixin


def test_tenantmixin_has_org_id_column() -> None:
    class TenantModel(Base, TenantMixin):
        __tablename__ = "test_tenant_model"
        from sqlalchemy import Integer
        from sqlalchemy.orm import Mapped, mapped_column
        id: Mapped[int] = mapped_column(Integer, primary_key=True)

    cols = {c.name for c in inspect(TenantModel).columns}
    assert "organization_id" in cols


def test_timestampmixin_has_created_and_updated_at() -> None:
    class TimestampedModel(Base, TimestampMixin):
        __tablename__ = "test_timestamped_model"
        from sqlalchemy import Integer
        from sqlalchemy.orm import Mapped, mapped_column
        id: Mapped[int] = mapped_column(Integer, primary_key=True)

    cols = {c.name for c in inspect(TimestampedModel).columns}
    assert "created_at" in cols
    assert "updated_at" in cols
