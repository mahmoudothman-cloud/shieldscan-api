"""AI provider client singletons per ADR-029 Q7 Phase-7 (M9.0 Stage 3 C1.4).

Y-AI-CLIENTS-MODULE-SHAPE resolved (a): a single module holding all three
provider clients (OpenAI + Anthropic + Qdrant). Pattern mirrors
``app.redis_client`` singleton convention + completions_consumer module-level
access precedent.

Lifecycle (Q7):
- ``init_ai_clients`` is called once at FastAPI lifespan startup; hard-fails if
  any required key/URL is missing (configuration errors loud at deploy time).
- ``shutdown_ai_clients`` is called at lifespan shutdown.
- ``get_*_client`` are FastAPI ``Depends``-compatible (Q7 A.i).
- ``*_client`` module-level accessors are for background tasks that have no
  request scope (Q7 D.a) — e.g. the ai-pipeline-consumer.
"""

from __future__ import annotations

from anthropic import AsyncAnthropic
from openai import AsyncOpenAI
from qdrant_client import AsyncQdrantClient

from app.config import Settings

_openai_client: AsyncOpenAI | None = None
_anthropic_client: AsyncAnthropic | None = None
_qdrant_client: AsyncQdrantClient | None = None


async def init_ai_clients(settings: Settings) -> None:
    """Initialise AI provider client singletons at app lifespan startup.

    Hard-fails (Q7) if any key/URL is missing — configuration errors must be
    loud at deploy time, not silent until the first scan reaches the pipeline.
    """
    global _openai_client, _anthropic_client, _qdrant_client

    if not settings.OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY required for AI pipeline (ADR-029 Q7)")
    if not settings.ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY required for AI pipeline (ADR-029 Q7)")
    if not settings.QDRANT_URL:
        raise RuntimeError("QDRANT_URL required for AI pipeline (ADR-029 Q7)")

    _openai_client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
    _anthropic_client = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
    _qdrant_client = AsyncQdrantClient(url=settings.QDRANT_URL)


async def shutdown_ai_clients() -> None:
    """Close AI provider clients at app lifespan shutdown."""
    global _openai_client, _anthropic_client, _qdrant_client

    if _openai_client is not None:
        await _openai_client.close()
        _openai_client = None
    if _anthropic_client is not None:
        await _anthropic_client.close()
        _anthropic_client = None
    if _qdrant_client is not None:
        await _qdrant_client.close()
        _qdrant_client = None


# --- FastAPI Depends-compatible getters (Q7 A.i) ---


def get_openai_client() -> AsyncOpenAI:
    if _openai_client is None:
        raise RuntimeError("OpenAI client not initialised; call init_ai_clients at startup")
    return _openai_client


def get_anthropic_client() -> AsyncAnthropic:
    if _anthropic_client is None:
        raise RuntimeError("Anthropic client not initialised; call init_ai_clients at startup")
    return _anthropic_client


def get_qdrant_client() -> AsyncQdrantClient:
    if _qdrant_client is None:
        raise RuntimeError("Qdrant client not initialised; call init_ai_clients at startup")
    return _qdrant_client


# --- Module-level accessors for background tasks (Q7 D.a) ---


def openai_client() -> AsyncOpenAI:
    return get_openai_client()


def anthropic_client() -> AsyncAnthropic:
    return get_anthropic_client()


def qdrant_client() -> AsyncQdrantClient:
    return get_qdrant_client()
