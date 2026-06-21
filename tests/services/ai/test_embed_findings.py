"""Tests for the embedding stage (ADR-030 Q2/Q3/Q8; M9.A Stage 3 C2).

Covers embedding-input construction (Q2), batch shape + hybrid 429 retry
(Q3), and per-batch cost-tracking integration (Q8). Embeddings are mocked via
``unittest.mock``-style fakes (Q9 A.b) with canned 1536-dim vectors.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.ai import AIAPICall
from app.services.ai import pipeline as pipeline_mod
from app.services.ai.pipeline import (
    _construct_embedding_input,
    _embed_batch_with_retry_and_usage,
    _embed_findings,
)
from tests.services.ai.conftest import (
    FakeEmbeddings,
    build_raw_finding,
    install_openai,
    make_rate_limit_error,
    seed_org_project_scan,
)


# ---------------------------------------------------------------- Q2 input construction


async def test_construct_embedding_input_includes_all_5_fields(db_session):
    _org, _project, scan = await seed_org_project_scan(db_session)
    finding = build_raw_finding(
        scan,
        _org,
        title="SQLi",
        finding_type="sqli",
        cwe_id="CWE-89",
        target_url="https://ai.example.com/login",
        description="Boolean-based blind SQLi.",
    )
    text = _construct_embedding_input(finding)
    assert "Title: SQLi" in text
    assert "Type: sqli" in text
    assert "CWE: CWE-89" in text
    assert "Target: https://ai.example.com/login" in text
    assert "Description: Boolean-based blind SQLi." in text


async def test_construct_embedding_input_handles_none_cwe_id(db_session):
    _org, _project, scan = await seed_org_project_scan(db_session)
    finding = build_raw_finding(scan, _org, cwe_id=None)
    assert "CWE: N/A" in _construct_embedding_input(finding)


async def test_construct_embedding_input_handles_none_description(db_session):
    _org, _project, scan = await seed_org_project_scan(db_session)
    finding = build_raw_finding(scan, _org, description=None)
    assert "Description: N/A" in _construct_embedding_input(finding)


async def test_construct_embedding_input_field_label_format(db_session):
    _org, _project, scan = await seed_org_project_scan(db_session)
    finding = build_raw_finding(scan, _org)
    lines = _construct_embedding_input(finding).split("\n")
    # One labeled "Field: value" line per field, in order (Q2 C.c).
    assert [line.split(":", 1)[0] for line in lines] == [
        "Title",
        "Type",
        "CWE",
        "Target",
        "Description",
    ]


# ---------------------------------------------------------------- Q3 batch shape


async def test_embed_findings_empty_returns_empty_dict(db_session, monkeypatch):
    _org, _project, scan = await seed_org_project_scan(db_session)
    install_openai(monkeypatch, FakeEmbeddings())
    embeddings = await _embed_findings(db=db_session, scan=scan, raw_findings=[])
    assert embeddings == {}


async def test_embed_findings_single_batch_makes_one_api_call(
    db_session, monkeypatch
):
    org, _project, scan = await seed_org_project_scan(db_session)
    fake = install_openai(monkeypatch, FakeEmbeddings())
    findings = [build_raw_finding(scan, org) for _ in range(10)]  # < 100 → 1 batch
    embeddings = await _embed_findings(
        db=db_session, scan=scan, raw_findings=findings
    )
    assert len(fake.calls) == 1
    assert len(embeddings) == 10
    assert all(len(vec) == 1536 for vec in embeddings.values())


async def test_embed_findings_multi_batch_makes_n_api_calls(db_session, monkeypatch):
    org, _project, scan = await seed_org_project_scan(db_session)
    fake = install_openai(monkeypatch, FakeEmbeddings())
    findings = [build_raw_finding(scan, org) for _ in range(150)]  # ceil(150/100)=2
    embeddings = await _embed_findings(
        db=db_session, scan=scan, raw_findings=findings
    )
    assert len(fake.calls) == 2
    assert [len(batch) for batch in fake.calls] == [100, 50]
    assert len(embeddings) == 150


# ---------------------------------------------------------------- Q8 cost tracking


async def test_embed_findings_logs_per_batch_cost_tracking(db_session, monkeypatch):
    org, _project, scan = await seed_org_project_scan(db_session)
    install_openai(monkeypatch, FakeEmbeddings(prompt_tokens=42))
    findings = [build_raw_finding(scan, org) for _ in range(150)]  # 2 batches
    await _embed_findings(db=db_session, scan=scan, raw_findings=findings)
    await db_session.flush()

    calls = (
        (await db_session.execute(select(AIAPICall).where(AIAPICall.scan_id == scan.id)))
        .scalars()
        .all()
    )
    assert len(calls) == 2  # one ai_api_calls row per batch (Q8 B.a)
    for call in calls:
        assert call.operation_type == "embedding"
        assert call.provider == "openai"
        assert call.model == "text-embedding-3-small"
        assert call.tokens_in == 42
        assert call.tokens_out is None
        assert call.cost_usd > 0


# ---------------------------------------------------------------- Q3 hybrid 429 retry


async def test_embed_batch_with_retry_429_retries_then_raises(db_session, monkeypatch):
    sleeps: list[float] = []

    async def _fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(pipeline_mod.asyncio, "sleep", _fake_sleep)
    fake = install_openai(
        monkeypatch, FakeEmbeddings(raise_exc=make_rate_limit_error())
    )

    with pytest.raises(pipeline_mod.openai.RateLimitError):
        await _embed_batch_with_retry_and_usage(["input"])

    # 4 attempts (0..3): the first three back off, the fourth re-raises.
    assert len(fake.calls) == 4


async def test_embed_batch_with_retry_429_exp_backoff_sequence(
    db_session, monkeypatch
):
    sleeps: list[float] = []

    async def _fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(pipeline_mod.asyncio, "sleep", _fake_sleep)
    install_openai(monkeypatch, FakeEmbeddings(raise_exc=make_rate_limit_error()))

    with pytest.raises(pipeline_mod.openai.RateLimitError):
        await _embed_batch_with_retry_and_usage(["input"])

    assert sleeps == [1.0, 2.0, 4.0]  # 1s/2s/4s exponential backoff (Q3 C.c)


async def test_embed_findings_429_exhaustion_degrades_and_returns_partial(
    db_session, monkeypatch
):
    org, _project, scan = await seed_org_project_scan(db_session)

    async def _fake_sleep(_delay):
        return None

    monkeypatch.setattr(pipeline_mod.asyncio, "sleep", _fake_sleep)
    install_openai(monkeypatch, FakeEmbeddings(raise_exc=make_rate_limit_error()))

    findings = [build_raw_finding(scan, org, id=uuid4()) for _ in range(3)]
    embeddings = await _embed_findings(
        db=db_session, scan=scan, raw_findings=findings
    )
    # Q3 D.b: 429-exhaustion degrades the scan + returns an empty embedding map.
    assert embeddings == {}
    assert scan.ai_pipeline_degraded is True
