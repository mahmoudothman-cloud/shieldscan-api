"""Shared fixtures + helpers for M9.A AI pipeline unit tests (ADR-030).

Kept local to ``tests/services/ai/`` (not promoted to the root conftest) so the
M9.A unit surface owns its own embedding/Qdrant stubs without touching the
C1-closed ``test_m9_smoke.py`` (which carries its own local ``stub_ai_clients``).
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import httpx
import openai
import pytest
from qdrant_client import AsyncQdrantClient

from app.models.identity import Organization
from app.models.projects import Project
from app.models.raw_findings import EngineCategory, RawFinding, Severity
from app.models.scans import Scan, ScanStatus, ScanType
from app.services.ai import pipeline as pipeline_mod
from tests.conftest import use_org


# ---------------------------------------------------------------- fake clients


def make_rate_limit_error() -> openai.RateLimitError:
    """Construct a real ``openai.RateLimitError`` (needs an httpx response)."""
    request = httpx.Request("POST", "https://api.openai.com/v1/embeddings")
    response = httpx.Response(429, request=request)
    return openai.RateLimitError("rate limited", response=response, body=None)


class FakeEmbeddings:
    """Stand-in for ``client.embeddings`` with controllable vectors + faults.

    ``vector_for`` maps an input string → its 1536-dim vector (default: a
    constant vector, so any two findings cluster). Set ``raise_exc`` to make
    every ``create`` call raise (e.g. a 429 for the retry/fallback paths).
    ``calls`` records each batch's input list for batch-count assertions.
    """

    def __init__(self, *, vector_for=None, prompt_tokens=8, raise_exc=None):
        self._vector_for = vector_for or (lambda _text: [0.1] * 1536)
        self._prompt_tokens = prompt_tokens
        self._raise_exc = raise_exc
        self.calls: list[list[str]] = []

    async def create(self, *, model, input):
        self.calls.append(list(input))
        if self._raise_exc is not None:
            raise self._raise_exc
        data = [
            SimpleNamespace(embedding=list(self._vector_for(text))) for text in input
        ]
        return SimpleNamespace(
            data=data, usage=SimpleNamespace(prompt_tokens=self._prompt_tokens)
        )


def install_openai(monkeypatch, fake_embeddings: FakeEmbeddings) -> FakeEmbeddings:
    """Patch ``pipeline.get_openai_client`` to return a client wrapping ``fake``."""
    client = SimpleNamespace(embeddings=fake_embeddings)
    monkeypatch.setattr(pipeline_mod, "get_openai_client", lambda: client)
    return fake_embeddings


def install_qdrant(monkeypatch) -> AsyncQdrantClient:
    """Patch ``pipeline.get_qdrant_client`` to a fresh in-memory Qdrant (Q9 B.a)."""
    client = AsyncQdrantClient(location=":memory:")
    monkeypatch.setattr(pipeline_mod, "get_qdrant_client", lambda: client)
    return client


@pytest.fixture
def stub_qdrant(monkeypatch):
    """In-memory Qdrant patched onto the pipeline (real cosine behavior)."""
    return install_qdrant(monkeypatch)


@pytest.fixture
def stub_ai_clients(monkeypatch):
    """Happy-path OpenAI (constant vector) + in-memory Qdrant.

    Returns a namespace with ``.openai`` (FakeEmbeddings) and ``.qdrant`` so
    tests can inspect call counts / collection state.
    """
    fake = install_openai(monkeypatch, FakeEmbeddings())
    qdrant = install_qdrant(monkeypatch)
    return SimpleNamespace(openai=fake, qdrant=qdrant)


# ---------------------------------------------------------------- DB seeding


async def seed_org_project_scan(db_session, *, status=ScanStatus.ANALYZING):
    """Org (+RLS GUC) + verified web project + a scan in ``status``."""
    org = Organization(name="AI Org", slug=f"ai-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    await use_org(db_session, org.id)
    project = Project(
        organization_id=org.id,
        name="AIApp",
        target_url="https://ai.example.com",
        root_domain="example.com",
        domain_verified=True,
    )
    db_session.add(project)
    await db_session.flush()
    scan = Scan(
        organization_id=org.id,
        project_id=project.id,
        scan_type=ScanType.FULL_WEB,
        status=status,
        priority="normal",
        config={},
    )
    db_session.add(scan)
    await db_session.flush()
    return org, project, scan


def build_raw_finding(scan, org, **overrides):
    """A RawFinding with a pre-set id (usable in-memory or added to a session)."""
    fields = {
        "id": uuid4(),
        "organization_id": org.id,
        "scan_id": scan.id,
        "tool_name": "nuclei",
        "engine_category": EngineCategory.DAST,
        "title": "Reflected XSS",
        "severity": Severity.HIGH,
        "finding_type": "xss",
        "cwe_id": "CWE-79",
        "target_url": "https://ai.example.com/a",
        "description": "User input reflected without encoding.",
        "fingerprint": uuid4().hex,
    }
    fields.update(overrides)
    return RawFinding(**fields)


async def add_raw_finding(db_session, scan, org, **overrides):
    """build_raw_finding + add to the session + flush (persisted; FK-ready)."""
    finding = build_raw_finding(scan, org, **overrides)
    db_session.add(finding)
    await db_session.flush()
    return finding
