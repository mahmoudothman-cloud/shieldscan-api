"""Nightly billing sweep (M12 slice 4). Run from a systemd timer:

    poetry run python scripts/billing_reconcile.py

Per org: suspend when the past-due grace window is exhausted, cancel at
period end when requested, and re-read every processor-backed
subscription from the processor (lost-webhook safety net). Same code as
POST /v1/admin/billing/reconcile.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from app.db import AsyncSessionLocal  # noqa: E402
from app.redis_client import close_redis, init_redis  # noqa: E402
from app.services.billing import get_provider  # noqa: E402
from app.services.billing.subscriptions import reconcile_all  # noqa: E402


async def main() -> None:
    redis = await init_redis()
    try:
        async with AsyncSessionLocal() as db:
            results = await reconcile_all(db, redis, get_provider())
            await db.commit()
    finally:
        await close_redis()
    acted = [r for r in results if r["action"] != "none"]
    print(json.dumps({"orgs": len(results), "actions": acted}, default=str))


if __name__ == "__main__":
    asyncio.run(main())
