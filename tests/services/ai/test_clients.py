"""Tests for AI provider client singletons (ADR-029 Q7; M9.0 Stage 3 C3.1).

Covers init/shutdown lifecycle, hard-fail on missing config (Q7), the
Depends-compatible getters + module-level accessors (Q7 A.i / D.a), and the
not-initialised guard. The module holds process-global singletons, so an
autouse fixture resets them around every test to prevent cross-test leakage.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.ai import clients


def _settings(**overrides):
    base = {
        "OPENAI_API_KEY": "test-openai",
        "ANTHROPIC_API_KEY": "test-anthropic",
        "QDRANT_URL": "http://localhost:6333",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture(autouse=True)
async def _reset_clients():
    """Ensure clean global state before + after each test."""
    await clients.shutdown_ai_clients()
    yield
    await clients.shutdown_ai_clients()


@pytest.mark.asyncio
async def test_init_ai_clients_creates_all_three_singletons():
    await clients.init_ai_clients(_settings())
    assert clients.get_openai_client() is not None
    assert clients.get_anthropic_client() is not None
    assert clients.get_qdrant_client() is not None


@pytest.mark.asyncio
async def test_init_ai_clients_hard_fails_on_missing_openai_key():
    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        await clients.init_ai_clients(_settings(OPENAI_API_KEY=""))


@pytest.mark.asyncio
async def test_init_ai_clients_hard_fails_on_missing_anthropic_key():
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        await clients.init_ai_clients(_settings(ANTHROPIC_API_KEY=""))


@pytest.mark.asyncio
async def test_init_ai_clients_hard_fails_on_missing_qdrant_url():
    with pytest.raises(RuntimeError, match="QDRANT_URL"):
        await clients.init_ai_clients(_settings(QDRANT_URL=""))


@pytest.mark.asyncio
async def test_get_openai_client_raises_when_not_initialized():
    with pytest.raises(RuntimeError, match="not initialised"):
        clients.get_openai_client()


@pytest.mark.asyncio
async def test_module_level_access_returns_same_singleton():
    """Module-level accessors (Q7 D.a, background tasks) return the same
    object as the Depends getters (Q7 A.i)."""
    await clients.init_ai_clients(_settings())
    assert clients.openai_client() is clients.get_openai_client()
    assert clients.anthropic_client() is clients.get_anthropic_client()
    assert clients.qdrant_client() is clients.get_qdrant_client()


@pytest.mark.asyncio
async def test_shutdown_ai_clients_resets_singletons():
    await clients.init_ai_clients(_settings())
    await clients.shutdown_ai_clients()
    with pytest.raises(RuntimeError, match="not initialised"):
        clients.get_openai_client()
    with pytest.raises(RuntimeError, match="not initialised"):
        clients.get_anthropic_client()
    with pytest.raises(RuntimeError, match="not initialised"):
        clients.get_qdrant_client()
