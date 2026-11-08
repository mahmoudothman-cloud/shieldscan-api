"""AI analysis pipeline: embedding + deduplication (ADR-030; M9.A Stage 3 C1).

Activates the M9.0 no-op scaffold into the first real-AI pipeline stages per
ADR-030 (Y-PROMOTION-TIMING Path C + Q1-Q12 + PY1-PY4):

  [1] embed  — OpenAI text-embedding-3-small (1536-dim) per RawFinding (SPEC §8.1)
  [2] dedup  — Qdrant cosine similarity >= 0.92, per-scan filter (SPEC §8.1)
  Path C    — the first finding of each dedup cluster promotes to a Vulnerability;
              subsequent cluster matches append their raw_finding_id (evidence).

The caller (AIPipelineConsumer) sets the RLS GUC + owns the terminal status
transition + SCAN_COMPLETED audit after run() returns (DQ2 / DQ5). run() is
side-effect only (PY3): Vulnerability rows + raw_finding promotion state +
ai_api_calls rows + Qdrant points. It raises on unrecoverable errors (PY4); the
consumer catches → FAILED + ai_pipeline_degraded. The Q3 (D.b) rule-based
fingerprint fallback handles an embedding-service outage *within* run()
(degraded-but-complete) before any propagation.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone
from decimal import Decimal
from itertools import batched
from uuid import UUID

import openai
from qdrant_client import AsyncQdrantClient
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchValue,
    PointStruct,
    VectorParams,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.raw_findings import RawFinding
from app.models.scans import Scan
from app.models.vulnerabilities import Vulnerability
from app.services.vulnerability_identity import reconcile_scan_history
from app.services.ai.clients import get_openai_client, get_qdrant_client
from app.services.ai.correlation import (
    CORRELATION_THRESHOLD,
    build_route_map,
    correlation_score,
    iter_cross_engine_pairs,
    union_find_clusters,
)
from app.services.ai.cost_tracking import log_ai_call
from app.services.ai.cwe_hierarchy import get_cwe_hierarchy
from app.services.ai.fix_generation import _generate_fixes
from app.services.ai.promotion_denylist import (
    denylisted_plugin_ids,
    is_promotion_denylisted,
)
from app.services.ai.scoring import (
    _map_score_to_severity_enum,
    base_cvss_for,
    compute_corroboration_multiplier,
    compute_exploitability_multiplier,
    compute_severity_score,
)
from app.services.ai.summary import _generate_executive_summary

logger = logging.getLogger(__name__)

# --- ADR-030 module constants ---
EMBEDDING_MODEL = "text-embedding-3-small"
EMBEDDING_VECTOR_SIZE = 1536
EMBEDDING_BATCH_SIZE = 100
EMBEDDING_MAX_RETRIES_429 = 3
DEDUP_SCORE_THRESHOLD = 0.92
# Stable namespace for deterministic Qdrant point ids (uuid5 over fingerprint).
NAMESPACE_FINGERPRINT = uuid.UUID("00000000-0000-0000-0000-000000000001")

# OpenAI text-embedding-3-small: $0.02 / 1M tokens (SPEC §8.5).
_EMBEDDING_COST_PER_TOKEN = Decimal("0.00000002")
_EMBEDDING_PROVIDER = "openai"
_EMBEDDING_OPERATION = "embedding"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _collection_name(organization_id: UUID) -> str:
    """Per-org Qdrant collection (Q4-M9.0 collection-per-organization)."""
    return f"findings_{organization_id}"


def _fingerprint_to_point_id(fingerprint: str) -> str:
    """Deterministic Qdrant point id from a finding fingerprint (Q5 C.a')."""
    return str(uuid.uuid5(NAMESPACE_FINGERPRINT, fingerprint))


def _construct_embedding_input(finding: RawFinding) -> str:
    """Labeled multi-field embedding input (Q2 A.b + B.c + C.c).

    target_url inclusion prevents conflating same-type findings at different
    endpoints; "N/A" markers keep nullable fields dimensionally stable.
    """
    return (
        f"Title: {finding.title}\n"
        f"Type: {finding.finding_type}\n"
        f"CWE: {finding.cwe_id or 'N/A'}\n"
        f"Target: {finding.target_url or 'N/A'}\n"
        f"Description: {finding.description or 'N/A'}"
    )


async def _embed_batch_with_retry_and_usage(inputs: list[str]):
    """One embeddings.create call with hybrid retry (Q3 C.c).

    AsyncOpenAI absorbs transient errors (its own max_retries); we add manual
    exponential backoff (1s/2s/4s) for 429 RateLimitError, then re-raise after
    EMBEDDING_MAX_RETRIES_429 so the caller can fall back (Q3 D.b).
    """
    client = get_openai_client()
    delay = 1.0
    for attempt in range(EMBEDDING_MAX_RETRIES_429 + 1):
        try:
            return await client.embeddings.create(model=EMBEDDING_MODEL, input=inputs)
        except openai.RateLimitError:
            if attempt == EMBEDDING_MAX_RETRIES_429:
                raise
            await asyncio.sleep(delay)
            delay *= 2
    # Unreachable (loop either returns or raises), but satisfies the type checker.
    raise RuntimeError("unreachable: embedding retry loop exited")


async def _embed_findings(
    *, db: AsyncSession, scan: Scan, raw_findings: Sequence[RawFinding]
) -> dict[UUID, list[float]]:
    """Embed all findings in batches; returns {finding_id: vector} (Q3 + Q8).

    Per-batch ``log_ai_call`` records cost post-call (Q8 B.a; embeddings are
    low-cost → no pre-call budget check). On 429-exhaustion, degrades to the
    rule-based fingerprint fallback (Q3 D.b): the scan is marked degraded and
    the partial map is returned — unembedded findings are deduped by exact
    fingerprint downstream rather than by vector similarity.
    """
    embeddings: dict[UUID, list[float]] = {}
    for batch in batched(raw_findings, EMBEDDING_BATCH_SIZE):
        inputs = [_construct_embedding_input(f) for f in batch]
        try:
            response = await _embed_batch_with_retry_and_usage(inputs)
        except openai.RateLimitError:
            logger.warning(
                "embedding 429-exhausted for scan_id=%s — degrading to rule-based "
                "fingerprint fallback (Q3 D.b)",
                scan.id,
            )
            scan.ai_pipeline_degraded = True
            return embeddings
        for finding, item in zip(batch, response.data, strict=True):
            embeddings[finding.id] = item.embedding
        tokens_in = response.usage.prompt_tokens
        await log_ai_call(
            db=db,
            organization_id=scan.organization_id,
            scan_id=scan.id,
            provider=_EMBEDDING_PROVIDER,
            model=EMBEDDING_MODEL,
            operation_type=_EMBEDDING_OPERATION,
            tokens_in=tokens_in,
            tokens_out=None,
            cost_usd=Decimal(tokens_in) * _EMBEDDING_COST_PER_TOKEN,
        )
    return embeddings


async def _ensure_collection_exists(
    client: AsyncQdrantClient, collection: str
) -> None:
    """Lazily create the per-org collection (Q5 A.c)."""
    if not await client.collection_exists(collection):
        await client.create_collection(
            collection_name=collection,
            vectors_config=VectorParams(
                size=EMBEDDING_VECTOR_SIZE, distance=Distance.COSINE
            ),
        )


async def _search_similar(
    client: AsyncQdrantClient, collection: str, scan_id: UUID, vector: list[float]
):
    """Top-1 cosine match within the current scan, >= 0.92 (Q6 + Q5 V-QQC).

    Uses ``query_points`` — the ``search`` method is absent in qdrant-client
    ^1.12 (V-QQC). Per-scan filter honors the M9.0 Q5 per-scan-dedup lock.
    Returns the matched point (with payload) or None.
    """
    response = await client.query_points(
        collection_name=collection,
        query=vector,
        query_filter=Filter(
            must=[FieldCondition(key="scan_id", match=MatchValue(value=str(scan_id)))]
        ),
        limit=1,
        score_threshold=DEDUP_SCORE_THRESHOLD,
        with_payload=True,
    )
    points = response.points
    return points[0] if points else None


async def _upsert_finding(
    client: AsyncQdrantClient,
    collection: str,
    point_id: str,
    vector: list[float],
    scan: Scan,
    finding: RawFinding,
    vulnerability: Vulnerability,
) -> None:
    """Upsert the cluster representative's point with an extended payload (Q5 D.b).

    ``vulnerability_id`` in the payload lets a later cluster-hit resolve the
    existing Vulnerability without a PG round-trip.
    """
    await client.upsert(
        collection_name=collection,
        points=[
            PointStruct(
                id=point_id,
                vector=vector,
                payload={
                    "raw_finding_id": str(finding.id),
                    "scan_id": str(scan.id),
                    "organization_id": str(scan.organization_id),
                    "cwe_id": finding.cwe_id,
                    "target_url": finding.target_url,
                    "fingerprint": finding.fingerprint,
                    "vulnerability_id": str(vulnerability.id),
                },
            )
        ],
    )


async def _create_vulnerability_from_finding(
    *, db: AsyncSession, scan: Scan, finding: RawFinding, point_id: UUID | None
) -> Vulnerability:
    """Promote a finding to a new Vulnerability (Path C + PY2 + Resolution γ).

    project_id is derived from the Scan (RawFinding has no project_id; V-NNE).
    The Vulnerability id is pre-generated (Resolution γ) so the Qdrant payload
    can reference it without round-tripping the DB.

    C1 D-deviation #1: the Vulnerability INSERT is flushed here, before linking
    the finding's FK. The Q7/Resolution-γ "no intermediate flush" assumption
    does not survive contact with the ``raw_findings.vulnerability_id`` →
    ``vulnerabilities.id`` FK: with no ORM ``relationship()`` between the two
    mappers, the unit-of-work cannot infer that the raw_finding UPDATE depends
    on the Vulnerability INSERT and would emit the UPDATE first (FK violation).
    The flush stays inside the consumer's single transaction (no mid-pipeline
    commit), so the atomicity intent of Q7 holds.
    """
    vuln = Vulnerability(
        id=uuid.uuid4(),  # Resolution γ: pre-generated (Qdrant payload reference)
        organization_id=scan.organization_id,
        project_id=scan.project_id,  # PY2 / V-NNE: derived from Scan
        scan_id=scan.id,
        title=finding.title,
        severity=finding.severity,
        finding_type=finding.finding_type,
        engine_category=finding.engine_category,
        target_url=finding.target_url,
        cwe_id=finding.cwe_id,
        fingerprint=finding.fingerprint,
        qdrant_point_id=point_id,
        raw_finding_ids=[finding.id],
    )
    db.add(vuln)
    await db.flush()  # persist the INSERT so the raw_finding FK resolves
    finding.promoted_at = _utcnow()
    finding.vulnerability_id = vuln.id
    return vuln


async def _merge_evidence(
    *, db: AsyncSession, vulnerability: Vulnerability, raw_finding: RawFinding
) -> None:
    """Append a finding's evidence to an existing Vulnerability (Q7).

    Append-only; reassignment forces the SQLAlchemy dirty flag (an in-place
    ``.append`` would not). Idempotent on re-delivery.
    """
    existing = vulnerability.raw_finding_ids or []
    if raw_finding.id in existing:
        return
    vulnerability.raw_finding_ids = [*existing, raw_finding.id]
    raw_finding.promoted_at = _utcnow()
    raw_finding.vulnerability_id = vulnerability.id


async def _dedup_and_promote(
    *,
    db: AsyncSession,
    scan: Scan,
    raw_findings: Sequence[RawFinding],
    embeddings: dict[UUID, list[float]],
) -> None:
    """Per-scan vector dedup + Path C promotion (Q5 + Q6 + Q7).

    For each finding in emission order:
      - embedded + a >= 0.92 cluster hit  → append evidence (_merge_evidence)
      - embedded, no hit                  → promote (new Vuln) + upsert point
      - unembedded (degraded fallback)    → exact-fingerprint dedup + promote

    Findings whose ``tool_metadata->>'plugin_id'`` is on the configured promotion
    denylist are skipped entirely (no Vulnerability, no Qdrant point, no
    promotion state). The filter is applied HERE and nowhere earlier:
    ``raw_findings`` is the 90-day audit record (SPEC §5.4) and stays complete.
    """
    client = get_qdrant_client()
    collection = _collection_name(scan.organization_id)
    if embeddings:
        await _ensure_collection_exists(client, collection)

    # Representatives created this run, keyed by their (pre-generated) vuln id —
    # every per-scan cluster hit resolves here, so no mid-loop PG round-trip.
    representatives: dict[str, Vulnerability] = {}
    # Degraded fallback: exact fingerprint → Vulnerability (Q3 D.b).
    fallback_by_fingerprint: dict[str, Vulnerability] = {}

    denylist = denylisted_plugin_ids()  # resolved once per scan
    skipped_denylisted = 0

    for finding in raw_findings:
        if is_promotion_denylisted(finding, denylist):
            skipped_denylisted += 1
            continue

        vector = embeddings.get(finding.id)

        if vector is None:
            # Rule-based fingerprint fallback (no vector available).
            existing = fallback_by_fingerprint.get(finding.fingerprint)
            if existing is not None:
                await _merge_evidence(
                    db=db, vulnerability=existing, raw_finding=finding
                )
            else:
                vuln = await _create_vulnerability_from_finding(
                    db=db, scan=scan, finding=finding, point_id=None
                )
                fallback_by_fingerprint[finding.fingerprint] = vuln
            continue

        match = await _search_similar(client, collection, scan.id, vector)
        if match is not None:
            vuln = representatives.get(match.payload["vulnerability_id"])
            if vuln is not None:
                await _merge_evidence(db=db, vulnerability=vuln, raw_finding=finding)
                continue

        # New cluster representative → promote, then upsert its point.
        point_id = _fingerprint_to_point_id(finding.fingerprint)
        vuln = await _create_vulnerability_from_finding(
            db=db, scan=scan, finding=finding, point_id=UUID(point_id)
        )
        representatives[str(vuln.id)] = vuln
        await _upsert_finding(client, collection, point_id, vector, scan, finding, vuln)

    if skipped_denylisted:
        logger.info(
            "ai-pipeline: scan %s skipped %d denylisted raw_findings at promotion "
            "(plugin ids %s); they remain in raw_findings",
            scan.id,
            skipped_denylisted,
            sorted(denylist),
        )


async def _correlate_vulnerabilities(*, db: AsyncSession, scan_id: UUID) -> None:
    """Cross-layer correlation pass (ADR-031 Q1-Q8 + Q12; SPEC §8.2).

    Scores cross-engine Vulnerability pairs, clusters threshold-crossing pairs via
    union-find (Path B link — no row deletion), and writes correlation_cluster_id +
    corroborated_count (engine-distinct within the cluster). Defensive skip when the
    scan has <2 distinct engine_categories (no cross-engine pair is possible).
    """
    vulnerabilities = (
        (await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id)))
        .scalars()
        .all()
    )
    if len({v.engine_category for v in vulnerabilities}) < 2:
        return  # Q13 C defensive skip

    # Q1 hybrid: correlate over each vuln's representative raw_finding, which
    # carries the §8.2 evidence fields (parameter / code_file / target_url /
    # code_snippet). The promoted Vulnerability row does not denormalise those at
    # M9.A, so reading them off the raw_finding is required; fall back to the
    # Vulnerability row itself when a finding is unavailable.
    rep_ids = {v.raw_finding_ids[0] for v in vulnerabilities if v.raw_finding_ids}
    findings_by_id: dict[UUID, RawFinding] = {}
    if rep_ids:
        rows = (
            (await db.execute(select(RawFinding).where(RawFinding.id.in_(rep_ids))))
            .scalars()
            .all()
        )
        findings_by_id = {r.id: r for r in rows}

    reps = {
        v.id: (findings_by_id.get(v.raw_finding_ids[0]) if v.raw_finding_ids else None)
        for v in vulnerabilities
    }
    evidence = {v.id: (reps[v.id] or v) for v in vulnerabilities}
    snippets = {
        v.id: (reps[v.id].code_snippet if reps[v.id] is not None else None)
        for v in vulnerabilities
    }

    cwe_hierarchy = get_cwe_hierarchy()
    route_map = build_route_map(evidence.values())
    correlated_pairs: list[tuple[Vulnerability, Vulnerability]] = []
    for vuln_a, vuln_b in iter_cross_engine_pairs(vulnerabilities):
        score = correlation_score(
            evidence[vuln_a.id],
            evidence[vuln_b.id],
            route_map=route_map,
            cwe_hierarchy=cwe_hierarchy,
            snippet_a=snippets[vuln_a.id],
            snippet_b=snippets[vuln_b.id],
        )
        if score >= CORRELATION_THRESHOLD:
            correlated_pairs.append((vuln_a, vuln_b))

    if not correlated_pairs:
        return
    for _cluster_id, members in union_find_clusters(
        vulnerabilities, correlated_pairs
    ).items():
        engine_count = len({v.engine_category for v in members})
        for vuln in members:
            vuln.correlation_cluster_id = _cluster_id
            vuln.corroborated_count = engine_count


async def _score_vulnerabilities(*, db: AsyncSession, scan_id: UUID) -> None:
    """Severity scoring pass (ADR-031 Q9-Q11; SPEC §8.3).

    Computes final_score = base_cvss × corroboration × exploitability per
    Vulnerability and writes severity_score + the mapped severity enum. Reads
    corroborated_count set by the correlation pass (Q12) for the corroboration
    multiplier; derives exploitability from the contributing raw_findings'
    tool_name (Q10 PoC-derivation).

    The base is resolved via ``base_cvss_for`` from the tool's ASSERTED severity
    (captured below BEFORE the overwrite) whenever no real CVSS is present —
    scanners almost never emit one, and a flat default collapsed every scored
    Vulnerability onto MEDIUM. Overwriting ``vuln.severity`` with the scored enum
    stays intentional (SPEC §8.3: the scored severity is the corroboration- and
    exploitability-adjusted one); it just needs a correct base.
    """
    vulnerabilities = (
        (await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id)))
        .scalars()
        .all()
    )
    if not vulnerabilities:
        return

    finding_ids = {
        fid for v in vulnerabilities if v.raw_finding_ids for fid in v.raw_finding_ids
    }
    tool_by_finding: dict[UUID, str] = {}
    if finding_ids:
        rows = (
            (await db.execute(select(RawFinding).where(RawFinding.id.in_(finding_ids))))
            .scalars()
            .all()
        )
        tool_by_finding = {r.id: r.tool_name for r in rows}

    for vuln in vulnerabilities:
        tool_names = [
            tool_by_finding[fid]
            for fid in (vuln.raw_finding_ids or [])
            if fid in tool_by_finding
        ]
        corroboration = compute_corroboration_multiplier(vuln.corroborated_count)
        exploitability = compute_exploitability_multiplier(tool_names)
        # Capture the tool's asserted severity BEFORE the overwrite below — it is
        # the scoring base whenever the tool emitted no CVSS vector.
        asserted_severity = vuln.severity
        score = compute_severity_score(
            base_cvss=base_cvss_for(vuln.cvss_score, asserted_severity),
            corroboration_multiplier=corroboration,
            exploitability_multiplier=exploitability,
        )
        vuln.severity_score = score
        vuln.severity = _map_score_to_severity_enum(score)


async def run(*, db: AsyncSession, scan_id: UUID) -> None:
    """Execute the AI pipeline for one scan: embed + dedup (M9.A ADR-030) →
    correlate + score (M9.B ADR-031) → fix-gen + executive summary (M9.C ADR-032).

    Side-effect only (PY3): Vulnerability rows + raw_finding promotion state +
    ai_api_calls + Qdrant points + correlation_cluster_id / corroborated_count /
    severity_score updates + ai_fix_text / executive_summary, with a single atomic
    flush at the end (Q7 B.a). The consumer commits + drives the terminal
    transition. Raises on unrecoverable errors (PY4).
    """
    scan = await db.get(Scan, scan_id)
    if scan is None:
        logger.warning("ai-pipeline: scan %s vanished; skipping", scan_id)
        return

    raw_findings = (
        (await db.execute(select(RawFinding).where(RawFinding.scan_id == scan_id)))
        .scalars()
        .all()
    )

    if not raw_findings:
        # Empty-findings short-circuit (PY4 / DQ3 alignment): nothing to embed.
        logger.info("ai-pipeline: scan %s has no raw_findings; no AI work", scan_id)
        return

    logger.info(
        "ai-pipeline: scan %s embedding+dedup over %d raw_findings",
        scan_id,
        len(raw_findings),
    )
    embeddings = await _embed_findings(db=db, scan=scan, raw_findings=raw_findings)
    await _dedup_and_promote(
        db=db, scan=scan, raw_findings=raw_findings, embeddings=embeddings
    )
    # M9.B (ADR-031 Q13): correlate cross-engine Vulnerabilities, then score.
    # Sequential composition; both operate on the Vulnerabilities promoted above.
    await _correlate_vulnerabilities(db=db, scan_id=scan_id)
    await _score_vulnerabilities(db=db, scan_id=scan_id)
    # M11: link to the project's history — carry triage status forward,
    # supersede older copies, flag regressions, auto-resolve what this scan
    # proves fixed. Before fix-gen so a carried false positive is not paid for.
    await reconcile_scan_history(db, scan)
    # M9.C (ADR-032 Q13): generate per-vuln AI fixes (Path A), then the scan
    # executive summary. Sequential; both read the scored Vulnerabilities above and
    # write ai_fix_text / executive_summary within this same transaction.
    await _generate_fixes(db=db, scan_id=scan_id)
    await _generate_executive_summary(db=db, scan_id=scan_id)
    # Q7 B.a: final flush of the raw_finding link UPDATEs. Vulnerability INSERTs
    # are flushed eagerly per-create (FK ordering; D-deviation #1) but all within
    # this one transaction — the consumer owns the single commit.
    await db.flush()
