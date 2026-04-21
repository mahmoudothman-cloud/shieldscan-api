from __future__ import annotations

from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.identity import (
    APIKey,
    Membership,
    MembershipRole,
    Organization,
    User,
)


# --- Structural tests: addendum columns on Organization ------------------


def test_organization_has_addendum_columns() -> None:
    cols = {c.name: c for c in inspect(Organization).columns}
    for name in (
        "industry",
        "country",
        "company_size",
        "certificate_eligible_since",
        "continuous_clean_days",
    ):
        assert name in cols, f"Organization missing addendum column {name!r}"


def test_organization_industry_column_shape() -> None:
    col = inspect(Organization).columns["industry"]
    assert col.nullable is True
    # VARCHAR(50) per ADDENDUM-CRITICAL-5 §3.3
    assert getattr(col.type, "length", None) == 50


def test_organization_country_column_shape() -> None:
    col = inspect(Organization).columns["country"]
    assert col.nullable is True
    # CHAR(2) ISO 3166-1 alpha-2
    assert getattr(col.type, "length", None) == 2


def test_organization_company_size_column_shape() -> None:
    col = inspect(Organization).columns["company_size"]
    assert col.nullable is True
    assert getattr(col.type, "length", None) == 20


def test_organization_certificate_eligible_since_is_timestamptz_nullable() -> None:
    col = inspect(Organization).columns["certificate_eligible_since"]
    assert col.nullable is True
    # timezone=True (TIMESTAMPTZ)
    assert getattr(col.type, "timezone", False) is True


def test_organization_continuous_clean_days_default_zero() -> None:
    col = inspect(Organization).columns["continuous_clean_days"]
    assert col.nullable is False
    # default=0 on the ORM side
    assert col.default is not None
    assert col.default.arg == 0


# --- CRUD tests from the plan --------------------------------------------


async def test_create_organization(db_session: AsyncSession) -> None:
    org = Organization(name="Test Org", slug="test-org")
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    assert org.id is not None
    assert org.name == "Test Org"
    # Default applied from ORM
    assert org.continuous_clean_days == 0
    # Optional fields left unset
    assert org.industry is None
    assert org.country is None
    assert org.company_size is None
    assert org.certificate_eligible_since is None


async def test_create_organization_with_addendum_fields(db_session: AsyncSession) -> None:
    org = Organization(
        name="Egypt Fintech",
        slug="egypt-fintech",
        industry="finance",
        country="EG",
        company_size="medium",
    )
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    assert org.industry == "finance"
    assert org.country == "EG"
    assert org.company_size == "medium"


async def test_create_user(db_session: AsyncSession) -> None:
    user = User(email="user@test.com", hashed_password="...", full_name="Test User")
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    assert user.id is not None
    assert user.email_verified is False


async def test_membership_links_user_to_org(db_session: AsyncSession) -> None:
    org = Organization(name="Acme", slug="acme")
    user = User(email="admin@acme.test", hashed_password="x", full_name="Admin")
    db_session.add_all([org, user])
    await db_session.flush()

    m = Membership(
        user_id=user.id, organization_id=org.id, role=MembershipRole.ADMIN
    )
    db_session.add(m)
    await db_session.commit()
    await db_session.refresh(m)
    assert m.role == MembershipRole.ADMIN


async def test_api_key_belongs_to_org(db_session: AsyncSession) -> None:
    org = Organization(name="KeyCo", slug="keyco")
    db_session.add(org)
    await db_session.flush()

    key = APIKey(
        organization_id=org.id,
        name="CI key",
        key_prefix="ss_live_abc",
        key_hash="deadbeef" * 8,
    )
    db_session.add(key)
    await db_session.commit()
    await db_session.refresh(key)
    assert key.id is not None
    assert key.revoked_at is None
