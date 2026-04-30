"""Regression test for ``app.db.select_fresh`` — pins the cache-bypass
behavior so a future "simplification" that drops ``populate_existing``
can't slip through silently.

See DEVELOPMENT-PATTERNS.md (shieldscan-docs) for the full pattern.
First discovered: Task 3.X PATCH /credentials.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select, text

from app.db import select_fresh
from app.models.identity import Organization
from tests.conftest import use_org


@pytest.mark.asyncio
async def test_select_fresh_bypasses_identity_map(db_session):
    """Proof that ``select_fresh`` re-hydrates from DB, while a plain
    SELECT returns a stale identity-map snapshot.

    Construction:
      1. INSERT a row, commit. ORM object now lives in identity map.
      2. UPDATE the row via **raw SQL** (bypasses the ORM) so DB state
         and the cached ORM object diverge.
      3. Plain SELECT returns the cached (stale) row.
      4. ``select_fresh`` returns the freshly-written DB state.

    Disables autoflush in the no_autoflush block so SQLAlchemy doesn't
    helpfully flush an unrelated pending change between steps.
    """
    org = Organization(name="Cache Test", slug=f"cache-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    await db_session.commit()

    # Confirm the identity map holds this row.
    assert org in db_session

    # Mutate via raw SQL — neither autoflush nor ORM tracking can see
    # this change, so the cached object remains "Cache Test".
    await db_session.execute(
        text("UPDATE organizations SET name = :n WHERE id = :id"),
        {"n": "DB-ONLY-MUTATION", "id": org.id},
    )
    await db_session.commit()

    # Plain SELECT — identity-map cache wins, returns stale snapshot.
    cached = (
        await db_session.execute(
            select(Organization).where(Organization.id == org.id)
        )
    ).scalar_one()
    assert cached.name == "Cache Test", (
        "sanity check: plain SELECT must hit the identity-map cache"
    )
    assert cached is org

    # select_fresh — re-hydrates from DB. Sees the raw-SQL mutation.
    fresh = (
        await select_fresh(
            db_session, select(Organization).where(Organization.id == org.id)
        )
    ).scalar_one()
    assert fresh.name == "DB-ONLY-MUTATION", (
        "select_fresh must bypass the cache and return DB state"
    )
