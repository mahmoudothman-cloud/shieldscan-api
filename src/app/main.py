"""FastAPI app entrypoint.

Lifespan:
  startup:  init Redis client + PING (fail-closed; see RUNBOOK §11.6).
            App aborts startup if Redis is unreachable — preferred
            over serving with auth broken.
  shutdown: close Redis cleanly.

Probes:
  GET /health  — liveness. Stays green as long as the process is up.
                 Does NOT check Redis (a Redis blip must not kill pods).
  GET /ready   — readiness. 200 with {"checks": {"postgres":"ok",
                 "redis":"ok"}} when both deps respond under 500ms;
                 503 otherwise with a per-dep failure code in the body.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.config import settings
from app.db import AsyncSessionLocal
from app.redis_client import close_redis, get_redis, init_redis
from app.routes import api_keys as api_keys_routes
from app.routes import auth as auth_routes

logger = logging.getLogger(__name__)

_STARTUP_PING_TIMEOUT = 2.0
_PROBE_TIMEOUT = 0.5


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize Redis + verify reachability — fail closed (RUNBOOK §11.6).
    redis = await init_redis()
    try:
        await asyncio.wait_for(redis.ping(), timeout=_STARTUP_PING_TIMEOUT)
    except Exception as e:
        logger.critical("startup: Redis unreachable — aborting boot: %s", e)
        await close_redis()
        raise
    try:
        yield
    finally:
        await close_redis()


app = FastAPI(
    title="ShieldScan API",
    version="4.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": "4.0.0"}


async def _check_postgres() -> str:
    try:
        async with AsyncSessionLocal() as db:
            await asyncio.wait_for(db.execute(text("SELECT 1")), timeout=_PROBE_TIMEOUT)
        return "ok"
    except asyncio.TimeoutError:
        return f"timeout_{int(_PROBE_TIMEOUT * 1000)}ms"
    except Exception as e:
        return f"error:{type(e).__name__}"


async def _check_redis(redis) -> str:
    try:
        await asyncio.wait_for(redis.ping(), timeout=_PROBE_TIMEOUT)
        return "ok"
    except asyncio.TimeoutError:
        return f"timeout_{int(_PROBE_TIMEOUT * 1000)}ms"
    except Exception as e:
        return f"error:{type(e).__name__}"


@app.get("/ready")
async def ready(redis=Depends(get_redis)) -> Any:
    # Run dep checks concurrently — one slow dep shouldn't double-time the probe.
    pg_status, redis_status = await asyncio.gather(
        _check_postgres(), _check_redis(redis)
    )
    checks = {"postgres": pg_status, "redis": redis_status}
    overall_ok = pg_status == "ok" and redis_status == "ok"
    body = {"status": "ready" if overall_ok else "not_ready", "checks": checks}
    if not overall_ok:
        return JSONResponse(status_code=503, content=body)
    return body


app.include_router(auth_routes.router, prefix="/v1")
app.include_router(api_keys_routes.router, prefix="/v1")
