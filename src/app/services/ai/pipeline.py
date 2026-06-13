"""AI analysis pipeline orchestrator per ADR-029 (M9.0 Stage 3 C2.4).

Y-NO-OP-PIPELINE-SHAPE resolved (a): immediate-return-no-op for M9.0 closure.
The real pipeline (embed → dedup → correlate → score → fix-gen → summary, SPEC
§8.1) is deferred to the sub-milestones per Q11: M9.A (embed/dedup) → M9.B
(correlate/score) → M9.C (fix-gen/summary) → M9.D (orchestrator composition).

M9.0 scope: exercise the architectural pipes only — completions_consumer →
orchestrator.dispatch_ai_pipeline → shieldscan:ai_pipeline queue →
AIPipelineConsumer → run_no_op → consumer-driven terminal transition. Zero AI
provider calls (Q11 C.c-lite smoke-test scope).
"""

from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


async def run_no_op(*, db: AsyncSession, scan_id: UUID) -> None:
    """No-op AI pipeline execution (M9.0 Q11 C.c-lite smoke-test scope).

    Intentionally performs no AI work. Replaced by the real pipeline stages at
    M9.A+. The caller (AIPipelineConsumer) owns the terminal status transition
    + SCAN_COMPLETED audit after this returns (DQ2 / DQ5).
    """
    logger.info("ai_pipeline_no_op_execution scan_id=%s", scan_id)
