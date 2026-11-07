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
from app.logging_config import configure_logging
from app.redis_client import close_redis, get_redis, init_redis
from app.routes import api_keys as api_keys_routes
from app.routes import auth as auth_routes
from app.routes import compliance as compliance_routes
from app.routes import mobile as mobile_routes
from app.routes import orgs as orgs_routes
from app.routes import projects as projects_routes
from app.routes import public_scans as public_scans_routes
from app.routes import reports as reports_routes
from app.routes import scans as scans_routes
from app.routes import tools as tools_routes
from app.routes import vulnerabilities as vulnerabilities_routes
from app.services.ai.clients import init_ai_clients, shutdown_ai_clients
from app.services.ai_pipeline_consumer import AIPipelineConsumer
from app.services.completions_consumer import CompletionsConsumer

logger = logging.getLogger(__name__)

_STARTUP_PING_TIMEOUT = 2.0
_PROBE_TIMEOUT = 0.5


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Root logging FIRST — before anything that might log. Uvicorn's default
    # config attaches handlers to its own three loggers and defines no root
    # entry, so without this every app-level INFO is discarded and warnings
    # reach stderr through logging.lastResort with no timestamp or logger
    # name. See app/logging_config.py. Runs after uvicorn's own dictConfig
    # (uvicorn configures logging before importing the app), so our root
    # handler is not overwritten.
    configure_logging()

    # Initialize Redis + verify reachability — fail closed (RUNBOOK §11.6).
    redis = await init_redis()
    try:
        await asyncio.wait_for(redis.ping(), timeout=_STARTUP_PING_TIMEOUT)
    except Exception as e:
        logger.critical("startup: Redis unreachable — aborting boot: %s", e)
        await close_redis()
        raise

    # AI provider clients (ADR-029 Q7). Initialised after Redis, before the
    # consumers, so the ai-pipeline-consumer (M9.0 Stage 3 C2) can rely on
    # module-level singletons. Hard-fails if keys/URL are missing.
    await init_ai_clients(settings)

    # Completions consumer (Task 4.2). Subscribes to
    # shieldscan:completions and applies job-completion events to PG.
    # See ADR-013 — Python is the sole writer for scan state.
    completions_consumer = CompletionsConsumer(
        session_factory=AsyncSessionLocal, redis=redis
    )
    await completions_consumer.start()

    # AI pipeline consumer (ADR-029 Q1 e.ii). Drains shieldscan:ai_pipeline
    # and runs the AI pipeline per scan; started after the completions
    # consumer, stopped before it (reverse-order teardown).
    ai_pipeline_consumer = AIPipelineConsumer(
        session_factory=AsyncSessionLocal, redis=redis
    )
    await ai_pipeline_consumer.start()

    try:
        yield
    finally:
        await ai_pipeline_consumer.stop()
        await completions_consumer.stop()
        await shutdown_ai_clients()
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
app.include_router(orgs_routes.router, prefix="/v1")
app.include_router(public_scans_routes.router, prefix="/v1")
app.include_router(projects_routes.router, prefix="/v1")
app.include_router(mobile_routes.router, prefix="/v1")
app.include_router(scans_routes.project_scans_router, prefix="/v1")
app.include_router(scans_routes.scan_router, prefix="/v1")
app.include_router(vulnerabilities_routes.router, prefix="/v1")
app.include_router(vulnerabilities_routes.scan_vulns_router, prefix="/v1")
app.include_router(reports_routes.router, prefix="/v1")
app.include_router(compliance_routes.router, prefix="/v1")
app.include_router(compliance_routes.scan_compliance_router, prefix="/v1")
app.include_router(tools_routes.router, prefix="/v1")
