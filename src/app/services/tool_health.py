"""Tool-health aggregation (M10.D; Task 10.6).

Reads the engine worker-fleet liveness signal from Redis and derives a
two-state per-tool availability roll-up. NO signal is written here — the
engine's heartbeat service (``internal/worker/heartbeat.go``) publishes
``shieldscan:workers:{worker_id}`` via SETEX (60s TTL, refreshed every
20s) with a JSON payload ``{hostname, started_at, concurrency, engines,
worker_id, registered_at}``. Presence-within-TTL IS the liveness contract
(a crashed worker's key expires within 60s); we add no second staleness
threshold (M10.D Stage 1 G1.3).

Two-state honesty (G1.1): a tool is ``available`` if ≥1 live worker
advertises it (via the heartbeat ``engines`` list), ``unavailable`` if
none. We do NOT fabricate a "degraded" state — the heartbeat carries
liveness + advertised-engines, not per-tool health; a heuristic degraded
would report a state the signal cannot support (the M10.C ``not_assessed``
honesty echo). Degraded is forward-pinned to a real per-tool health signal.

Known-engine set: the union of ``SCAN_TYPE_TOOLS`` (the api's own tool
vocabulary — the tools it dispatches jobs to), reused as the single source
of truth rather than a new hardcoded list. NOTE: the api's tool names
(e.g. ``trivy-container``, ``trivy-fs``, ``zap``, ``mobsf``) do not all
string-match the engine's ``registry.Engines()`` values (e.g. ``trivy``);
the roll-up compares advertised strings against the known-set verbatim, so
cross-repo tool-name normalization is forward-pinned. Engines advertised
by a worker but absent from the known-set are still surfaced (available).
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from app.services.orchestrator import SCAN_TYPE_TOOLS

_WORKER_KEY_PATTERN = "shieldscan:workers:*"

# The api's canonical tool vocabulary — union across every ScanType's
# dispatch tuple. These are exactly the tools the api dispatches jobs to,
# so "is a live worker advertising each?" is the operational question this
# endpoint answers. Sorted for deterministic roll-up ordering.
KNOWN_ENGINES: tuple[str, ...] = tuple(
    sorted({tool for tools in SCAN_TYPE_TOOLS.values() for tool in tools})
)


async def gather_tool_health(redis) -> dict:
    """Scan the worker-fleet keys and build the health response.

    Zero live workers is a valid state (empty ``workers`` + every known
    tool ``unavailable``), not an error.
    """
    workers: list[dict] = []
    advertised: Counter[str] = Counter()

    async for key in redis.scan_iter(match=_WORKER_KEY_PATTERN):
        raw = await redis.get(key)
        if raw is None:
            continue  # key expired between scan_iter and get — treat as gone
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError):
            continue  # malformed payload — skip, don't fail the whole probe
        engines_raw = payload.get("engines")
        engines = (
            sorted(str(e) for e in engines_raw)
            if isinstance(engines_raw, list)
            else []
        )
        workers.append(
            {
                "worker_id": payload.get("worker_id"),
                "hostname": payload.get("hostname"),
                "concurrency": payload.get("concurrency"),
                "last_seen": payload.get("registered_at"),
                "engines": engines,
            }
        )
        advertised.update(engines)

    tool_names = sorted(set(KNOWN_ENGINES) | set(advertised))
    tools = [
        {
            "engine": name,
            "available": advertised[name] > 0,
            "live_worker_count": advertised[name],
        }
        for name in tool_names
    ]
    workers.sort(key=lambda w: w["worker_id"] or "")

    return {
        "workers": workers,
        "tools": tools,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
