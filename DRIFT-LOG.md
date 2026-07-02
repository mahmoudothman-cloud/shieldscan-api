# shieldscan-api — DRIFT-LOG

API-side design decisions, deferred work, and implementation deviations.
Newest entries on top.

For cross-cutting decisions affecting both `shieldscan-api` and
`shieldscan-engine`, see `../shieldscan-docs/DRIFT-LOG.md`. For
engine-specific entries, see `../shieldscan-engine/DRIFT-LOG.md`.

---

### 2026-07-02 — M9.D Sub-Milestone CLOSED + 🔒 MILESTONE 9 ENTIRELY CLOSED — Cumulative Drift Count Preserved at 66 (no Drift #67)

M9.D (AI Pipeline: Orchestrator; ADR-033) closed its entire lifecycle with **zero catalogue increments** — and with it **MILESTONE 9 (AI Analysis Pipeline) closes ENTIRELY**. This is a closure note, **not** a drift entry — Drift #66 (M9.A C1; the 2026-06-23 entry below) remains the latest catalogued drift. Docs closure at `2777ad4`; ADR-033 canonical at SPEC §13 `1583f27`.

**M9.D chain (all outcomes γ):** Stage 1 design `988326e` (compressed; absorbs Stage 2 per Q5; 8 locks via Mode 2 brainstorming; adaptive Path δ SMALL classification via V-AA) + Stage 3 C0 ADR-033 `1583f27` (closure-by-composition; 4th consecutive C0 at 0 drifts) + C1 terminal-metadata wiring `5c092df` (completed_at at COMPLETED/PARTIAL/FAILED + error_message FAILED str(exc) via `_fail_scan(*, error)` threading + PARTIAL "N of M" summary) + C2 e2e smoke `2f155f0` (4 tests green first-run; suite 751 ZERO regressions) + Stage 4 P5.A (`2777ad4` docs + this api entry + the engine cross-ref).

**🔒 MILESTONE 9 ENTIRELY CLOSED:** M9.0 (foundation; ADR-029) + M9.A (embed/dedup; ADR-030) + M9.B (correlate/score; ADR-031) + M9.C (fix-gen/summary; ADR-032; FIRST real Anthropic integration) + M9.D (orchestrator; ADR-033). Pipeline operational end-to-end: completions-event → dispatch → embed → dedup → correlate → score → fix-gen → summary → terminal metadata. 751 tests green; cost-tracking operational per Gotcha 5.

**Why no Drift #67 — the mitigations that held the line:**
- **V-AA adaptive pre-verification (SMALL classification).** Established the orchestration chain operational since M9.0 C2 / Task 4.2 — preventing a `run_ai_pipeline` duplication and an ADR-013 sole-writer violation; Task 9.7 pseudo-code superseded per the INFORMATIONAL-not-BINDING header.
- **V-EE pre-C1 cascade.** The highest-value pre-grounded item (V-EEC) surfaced exactly as predicted — `_process` used a bare `except Exception:` (exception unbound) and `_fail_scan(scan_id, org_uuid)` didn't receive it; resolved within-lock pre-commit via an additive-safe keyword-only `error` param. 8th averted-prediction catch.
- **Gate-2 discipline.** The M9.C Gate-1 fix-gen-throttle forward-pin honored through M9.D; fix_generation.py untouched; no closed artifact reopened.
- **V-FF assertion-grounding.** C2 assertions grounded on C1's actual write-sites (exact PARTIAL f-string asserted verbatim) — 4 tests green first-run, zero test-authoring iterations.

**8-instance averted-prediction lineage:** V-IIB + V-JJC + V-MM + V-NNE + V-UUE + V-VV/V-WW/V-XX/V-YY + V-BB 4-catch + V-CCF + **V-EEC (M9.D)**. **3-instance test-gate-within-lock pattern** — NOT incremented at M9.D (no test-gate catches).

**Forward-pins on record:** webhooks → Task 12.5; CANCELED completed_at → routes-touch task; fix-gen throttle → production-readiness; autouse-anthropic-stub → production-readiness; stream-key TTL → OPS. ⇒ **M10 trigger: "Begin M10 — Report Architecture"**.

### 2026-07-02 — M9.C Sub-Milestone CLOSED — Cumulative Drift Count Preserved at 66 (no Drift #67)

M9.C (AI Pipeline: Fix Generation + Executive Summary; ADR-032) closed its entire lifecycle with **zero catalogue increments**. This is a closure note, **not** a drift entry — Drift #66 (M9.A C1; the 2026-06-23 entry below) remains the latest catalogued drift. Logged here at M9.C Stage 4 P5.A per the M8.1β.2 V-CC reconciliation precedent (api+engine DRIFT-LOG sync at P5.A). Docs closure at `0a829cb`; ADR-032 canonical at SPEC §13 `e8fbd8c`. M9.C is the FIRST real Anthropic Claude API integration in the ShieldScan AI Pipeline; cost-tracking transitioned from architectural-readiness to operational-load per CLAUDE.md Gotcha 5.

**M9.C 9-commit chain (all outcomes γ):** Stage 1 design `261cf10` (18 architectural locks: Gate-1 Path A per-vuln + Gate-2 circuit-breaker forward-pin + Q1-Q16; V-AB DEFERRED-EMPIRICAL §9) + Stage 2 plan `f86a7b0` (PY1-PY8; 3-commit decomposition per V-AAH/I no-migration) + Stage 3 C0 ADR-032 `e8fbd8c` + C1 modules/integration `a0522a1` (fix_generation.py + summary.py NEW + pipeline.run() extension; 0 catalogued drifts at the novel-territory strongest-risk commit) + C2 tests/smoke `6eff189` (36 new tests; suite 747 ZERO regressions) + Stage 4 P5.A (`0a829cb` docs + this api entry + the engine cross-ref).

**Why no Drift #67 — the mitigations that held the line:**
- **PY5 (V-AB DEFERRED-EMPIRICAL pre-grounding, operationalized at V-BB pre-C1 + V-CC pre-C2 per PY1).** V-ABE SDK Message construction + V-ABF monkeypatch attachment + V-ABG cost_usd Decimal (Numeric(10,6)) + V-ABH Severity enum + V-ABI EngineCategory branching — all empirically confirmed before the code that depends on them.
- **PY6 (no-migration territory per V-AAH/I).** `Vulnerability.ai_fix_text` + `Scan.executive_summary` were scaffolded at M9.0 C1; standalone columns, no cross-table FK — the Drift #66 ORM-vs-DB FK-ordering class is not applicable at M9.C.
- **PY7 (test-fixture ordering discipline).** conftest `stub_anthropic` + `make_anthropic_response` landed before their consumer test files; `test_m9c_smoke.py` (tests/integration/) imports plain helpers cross-directory (`install_anthropic` mirrors `install_openai`) per the M9.B C3 fixture-scoping lesson.
- **Test-gate discipline (3rd test-gate-within-lock instance, C1 `a0522a1`, Option A ratified).** `test_run_429_rule_based_fingerprint_fallback` asserted `logged == 0` over *all* AIAPICall rows — a pre-M9.C invariant legitimately broken by M9.C's Q13 A.a unconditional sequential composition + Q5 C.b cost_usd=0 failure-marker rows. Assertion narrowed to `operation_type == "embedding"`, preserving the M9.A embedding-invariant. Follows M9.B C2 `6c9e270` Q1 evidence-loading + M9.B C3 `f82c38a` fixture-scoping; within-lock under-implementation correction; not a Y-lock deviation; not a catalogue increment.

**7-instance averted-prediction lineage at M9.C P5.A:** V-IIB (M9.0 C1) + V-JJC (M9.0 C2) + V-MM (M9.A Stage 1) + V-NNE (M9.A Stage 1 §9) + V-UUE (M9.B Stage 1 §9) + V-VV/V-WW/V-XX/V-YY (M9.B Stages 2-3 cascade) + **V-BB 4-catch + V-CCF (M9.C)**: check_budget returns bool (not raises) + `BudgetExceededError` name + `raw_finding_ids` is an array column (not an ORM relationship; representative-query per M9.B `6c9e270`) + anthropic response shape (`message.content[0].text` / `message.usage.input_tokens`/`output_tokens`) + `get_anthropic_client` name-bound only in `fix_generation.py` (single monkeypatch target covers fix-gen + summary).

**Classification clarity — test-authoring TDD refinement at C2 (not the test-gate-within-lock class):** 3 miswritten new-test assertions + the asyncio marking convention (`pytestmark` under `asyncio_mode=auto`) were caught at the targeted pre-commit run and corrected; source untouched. Normal test-writing workflow — the test-gate-within-lock class is *source* under-implementation caught by a test gate.

**Non-blocking observation (C1-introduced; forward-pinned):** pre-existing full-`run()` tests outside M9.C scope traverse the fix-gen/summary path unstubbed and incur real retry-backoff sleeps (suite ~300s). Autouse anthropic stub forward-pinned to production-readiness. Also noted: C1 landed 668 net LoC vs the Q15 >500 forward-pin threshold (fired empirically; work atomic + coherent + green; single-commit landing per direction with transparency flag).

### 2026-06-29 — M9.B Sub-Milestone CLOSED — Cumulative Drift Count Preserved at 66 (no Drift #67)

M9.B (AI Pipeline: Correlation + Scoring; ADR-031) closed its entire lifecycle with **zero catalogue increments**. This is a closure note, **not** a drift entry — Drift #66 (M9.A C1; the 2026-06-23 entry below) remains the latest catalogued drift. Logged here at M9.B Stage 4 P5.A per the M8.1β.2 V-CC reconciliation precedent (api+engine DRIFT-LOG sync at P5.A). Docs closure at `42259cf`; ADR-031 canonical at SPEC §13 `fb4b07e`.

**M9.B 9-commit chain (all outcomes γ):** Stage 1 design `d10be51` + Stage 2 plan `a172fd1` + Stage 3 C0 ADR-031 `fb4b07e` + C1 schema/modules `5dee684` + C2 pipeline integration `6c9e270` + C3 tests/smoke `f82c38a` + Stage 4 P5.A (`42259cf` docs + this api entry + the engine cross-ref).

**Why no Drift #67 — the three mitigations that held the line:**
- **PY5 (V-UUE tool_name DEFERRED-EMPIRICAL pre-grounding).** Stage 1 §9 pre-grounded that `RawFinding` has `tool_name`, not `engine_name`; carried into `scoring.py` `POC_PROVEN_TOOL_NAMES` at C1. Averted a Drift #61-class concrete-field catch at execution (mirrors V-NNE project_id at M9.A).
- **PY6 (Drift #66-class lower-risk assessment).** `correlation_cluster_id` + `severity_score` are standalone columns with no cross-table FK, so the M9.A C1 ORM-vs-DB FK-ordering hazard (Drift #66) cannot recur. Validated empirically at V-WWI; the migration is a clean `ALTER TABLE ADD COLUMN`.
- **Test-gate discipline (within-lock under-implementation classification).** Two in-flight implementation gaps were caught by the commit-gate tests and corrected pre-commit, each *within* an existing Y-lock — neither a Y-lock deviation, neither a catalogue increment:
  1. **C2 Q1 evidence-loading** (`6c9e270`): the first pass read correlation evidence (parameter/code_file) off the promoted Vulnerability rows, which M9.A leaves null. The e2e test caught the resulting non-correlation; corrected to load the representative `RawFinding` evidence (with a fall-back to the Vulnerability row) — exactly what Q1 already mandates ("loads raw_finding fields via raw_finding_ids join").
  2. **C3 fixture-scoping** (`f82c38a`): the `cross_engine_vulnerabilities` / `single_engine_vulnerabilities` fixtures were first placed in `tests/services/ai/conftest.py`, but their consumer `test_m9b_smoke.py` is in `tests/integration/` — pytest fixtures don't cross sibling conftest directories. The collection gate caught it; corrected by relocating the fixtures into the smoke file (built on the importable conftest helpers). Q15 B.a fixtures still delivered + consumed.

  These establish a **2-instance test-gate-within-lock pattern**: pre-commit test catches that surface implementation gaps *within* existing Y-locks are corrected and reported transparently, but are **not** framing-drift increments (distinct from Drift #66, which was a design-lock assumption — Resolution γ — failing against the DB).

**6-instance averted-prediction lineage:** V-IIB (M9.0 C1 config UPPERCASE) + V-JJC (M9.0 C2 DQ3 test-impact) + V-MM (M9.A Stage 1 merge_evidence) + V-NNE (M9.A Stage 1 §9 project_id) + V-UUE (M9.B Stage 1 §9 tool_name) + V-VV/V-WW/V-XX/V-YY (M9.B Stages 2-3 pre-verification cascade).

**Cumulative session-tail framing-drift count: 66** (Drift #58-#66; Drift #66 NOVEL ORM-vs-DB layer assumption mismatch from M9.A C1; unchanged through the entire M9.B lifecycle).

**Cross-references:** shieldscan-docs `d10be51` + `a172fd1` + `fb4b07e` + `42259cf` (M9.B P5.A docs); shieldscan-api `f82c38a` + `6c9e270` + `5dee684` + `cee75bf` (M9.A P5.A api DRIFT-LOG precedent); shieldscan-engine `99f04e7` (M9.A P5.A engine DRIFT-LOG; M9.B cross-ref at the forthcoming P5.A engine commit); SPEC §13 ADR-031 (M9.B architectural authority).

### 2026-06-23 — Drift #66 RESOLVED (M9.A Stage 3 C1; Resolution γ FK-ordering — ORM-vs-DB layer assumption mismatch; NOVEL catch-class)

Persistent-catalogue sync for the M9.A lifecycle, landed here at M9.A Stage 4 P5.A per the M8.1β.2 V-CC reconciliation precedent (catalogue → persistent DRIFT-LOG at P5.A). M9.A closure documented at docs `c9130db` (IMPLEMENTATION-PLAN M9.A blockquote + Tasks 9.1/9.2 + design/plan Status frontmatter); ADR-030 canonical at SPEC §13 `d408b2c`.

**Drift #66 — Resolution γ FK-ordering — ORM-vs-DB layer assumption mismatch (NOVEL catch-class; first instance in arc).** Surfaced at M9.A Stage 3 C1 (`91ec273`) test execution: an `asyncpg ForeignKeyViolationError` on the `raw_findings.vulnerability_id` → `vulnerabilities.id` FK.

- **Root cause.** ADR-030 Q7 Resolution γ pre-generates the Vulnerability id via `uuid.uuid4()` to avoid an ORM-level flush-for-id round-trip. That removes the *ORM* need to flush — but the *DB-level* FK constraint still requires the Vulnerability row to be persisted **before** the `raw_finding` UPDATE that sets `vulnerability_id` is emitted. SQLAlchemy's unit-of-work cannot infer the UPDATE-depends-on-INSERT ordering without a `relationship()` bridging the two mappers; it emitted the raw_finding UPDATE first → FK violation.
- **Resolution.** Intermediate `await db.flush()` inside `_create_vulnerability_from_finding` (`src/app/services/ai/pipeline.py`) before linking `raw_finding.vulnerability_id`. The Vulnerability INSERT persists; the FK resolves at the deferred final flush. The flush stays inside the consumer's single transaction (no mid-pipeline commit), so the Q7 atomic-same-flush intent holds at the outer transaction boundary (the AIPipelineConsumer owns the commit).
- **Regression-guard.** `test_drift_66_fk_ordering_regression_guard` (`tests/services/ai/test_dedup_and_promote.py`, commit `251960a`) asserts the Vulnerability is queryable immediately after `_create_vulnerability_from_finding` (proving the intermediate flush) and that the raw_finding FK resolves at the final flush. A refactor reverting the fix fails this test.
- **Catch-class lineage.** NOVEL — distinct from #59 (architectural-seam), #60 (model+spec orphan), #61 (DEFERRED-EMPIRICAL field naming), #62 (deferred-empirical conditional), #63 (test-impact-surface), #64 (ai_api_calls absence), #65 (Scan.executive_summary absence). All prior catches are *static* (field/contract/scope mismatches surfaced pre-execution or at predictable seams); #66 is the first *layer-assumption* catch — an ORM abstraction that is locally correct but violates a DB-level invariant only an execution-time flush reveals.
- **Forward-pin extension.** When pre-generating UUIDs to avoid an intermediate flush, verify FK constraints across tables that require persisted-parent-before-child ordering: a `relationship()` bridge lets the unit-of-work infer order, but manual FK-column linking requires an explicit flush. Empirically grounded by Drift #66 at M9.A C1.

**Disambiguation — "#66-averted lineage" vs Drift #66.** Prior arc-references to "#66-averted lineage" (V-JJC predicted-then-averted at M9.0 C2 + DQ3 design-choice-averted; V-MM/V-NNE averted at M9.A Stage 1; see the 2026-06-16 entry below) were documentation-shorthand for the **averted-prediction discipline lineage** — they used "#66" as a would-be-next-number placeholder and explicitly did **not** increment the count (it stayed 65). The #66 catalogue number is assigned **here** to the FK-ordering catch — the first real increment past 65. Future references should distinguish: "averted-prediction discipline lineage" (predicted-then-averted via design choices; no increment) vs "Drift #66" (catalogued NOVEL ORM-vs-DB layer assumption mismatch).

**Cumulative session-tail framing-drift count: 66** (Drift #58-#66; +1 since M9.0 close — the FK-ordering catch is the first real increment past the 65 that held through M9.0).

**Cross-references:** shieldscan-docs `aaf7ea0` (Stage 1 design) + `a8ad52c` (Stage 2 plan) + `d408b2c` (ADR-030 SPEC §13) + `c9130db` (M9.A P5.A docs annotations); shieldscan-api `91ec273` (C1 impl; Drift #66 surfaced + resolved) + `251960a` (C2 tests + regression-guard) + `4616672` (M9.0 P5.A api DRIFT-LOG #64/#65 precedent); shieldscan-engine `6254849` (M9.0 P5.A engine DRIFT-LOG; #66 cross-ref at the forthcoming P5.A engine commit); SPEC §13 ADR-030 (M9.A architectural authority).

### 2026-06-16 — Drift #64 + #65 RESOLVED + #66-averted (M9.0 AI Pipeline Foundation; ADR-029)

Persistent-catalogue sync for the M9.0 lifecycle (closure documented at Stage 1 design doc `a46fedd` §9 + ADR-029 SPEC §13 `45dcabe`; resolving code at api `51b26ea`). Lands here at M9.0 Stage 4 P5.A per the M8.1β.2 V-CC reconciliation precedent (catalogue → persistent DRIFT-LOG at P5.A).

**Drift #64 — `ai_api_calls` absence (Drift #60 catch-class 4th-instance: stored-design-intent-with-unimplemented-mechanism).** CLAUDE.md Gotcha 5 mandates per-call AI cost logging to an `ai_api_calls` table + per-scan budget + circuit breaker; V-EE (M9.0 entry) surfaced zero infrastructure. **Resolution:** M9.0 Stage 3 C1 (`51b26ea`) — `ai_api_calls` table (TenantMixin RLS; registered in `app.db.policies.TENANT_TABLES`) + `AIAPICall` model + `app.services.ai.cost_tracking` (per-scan SUM aggregate + hybrid pre/post-call budget check + hardcoded SPEC §8.5 ScanType budgets). Catch-class lineage: #54 (source-ingest) + #58 (AttackSurface consumer) + #60 (SCAN_TYPE_TOOLS orphans) + #64 (this).

**Drift #65 — `Scan.executive_summary` absence (Drift #61 catch-class 5th-instance: concrete-empirical-field absence; sub-category 2nd-instance).** M9.7 plan-literal pseudo-code referenced `scan.executive_summary`; V-EE confirmed the field did not exist. **Resolution:** M9.0 Stage 3 C1 (`51b26ea`) — `Scan.executive_summary` Text nullable column (ADR-029 Q3 Hybrid; full Report architecture forward-pinned to M10). Sub-category lineage: #61 (`Scan.created_by_user_id`) + #65 (this).

**Drift #66-averted — V-JJC predicted test-impact, DQ3 design choice averted (NO catalogue increment).** V-JJC pre-verification (M9.0 C2) predicted a Path β/γ test-impact-surface (Drift #63 catch-class extension) from the `_maybe_complete_scan` COMPLETED→ANALYZING interposition. The ratified DQ3 empty-raw_findings short-circuit preserved the old inline behavior for findings-free scans → **0 existing tests broke, 0 updates needed**. Per the averted-prediction discipline established at V-IIB/C1 (config field-name mismatch predicted + pseudo-code-grounding averted; no increment), no #66 catalogue increment. Documents the arc discipline-tier: pre-verification + ratification + design-choice → zero-execution-drift.

**Cumulative session-tail framing-drift count: 65** (unchanged through M9.0 lifecycle; #64 + #65 were catalogued at M9.0 Stage 1, resolved in code at C1, synced here; #66 averted-not-incremented).

**Cross-references:** shieldscan-docs `a46fedd` (design §9) + `45dcabe` (ADR-029) + `62499a3` (M9.0 P5.A docs annotations); shieldscan-api `51b26ea` (C1 resolution) + `1c98330` (C2; DQ3) + `8410df4` (C3 tests); CLAUDE.md Gotcha 5 (Drift #64 driver) + Gotcha 3 (ai_api_calls RLS).

### 2026-05-03 — Findings-ingest task closes (ADR-024 §3.2 + ADR-017 Task 5.5)

**Two carry-forward concerns closed by this commit:**

1. **ADR-024 §3.2 "Python ingest scope deferred" columns-ready posture closed.** Phase 2 of M6-close-followup (commit `938ae80`) landed the four SPEC §7.3 schema-extension columns (`references`, `tags`, `cvss_vector`, `additional_cwes`) on `raw_findings`, but `CompletionsConsumer` did not yet read them. This commit lands the consumer.

2. **ADR-017 Task 5.5 cross-repo scope closed.** ADR-017 line 1452 anticipated Python-side ingest at "Task 5.5 cross-repo" scope; only the engine-side wire format landed at M5 close. This commit closes the long-standing cross-repo gap — overdue work since M5.

**M9 prerequisite met:** `raw_findings` table now populates end-to-end; SPEC §8.1 AI Analysis Pipeline has the data it needs to operate. M9 implementation engineers can plan against a populated table rather than scoping ingest as part of M9 work.

### 2026-05-03 — ADR-025 lands (project corpus's 4th asymmetric-cost ADR)

**ADR-025 (CompletionsConsumer findings-ingest path — Pydantic schema + sequenced accumulator + RLS atomic ingest)** drafted in `shieldscan-docs/plans/2026-05-03-findings-ingest-design.md` §6; full ADR text lands in `shieldscan-docs/SPECIFICATION.md` §13 separately (post-implementation per Mahmoud's handling — ADR-025 §3.2 + §4.1 need revision to match the actual implemented schema before landing; see Deviation 7 in the consolidated entry below).

**4th asymmetric-cost ADR** in the project corpus after:
- ADR-022 (recon-as-pre-scan-helpers; M6.3)
- ADR-023 (NativeRunner OutputFile mode; M6.7)
- ADR-024 (RawFinding schema extension; M6-close-followup)

The shared meta-principle continues to hold: **architectural commitments are made when the alternative is operationally worse, not when a generic threshold is met.** Extension cost (~9h) is asymmetrically smaller than alternative cost (M9 prerequisite missing; ADR-017 forcing-function contract unmet for over a milestone; columns-ready posture indefinitely open).

**Trigger to promote to DEVELOPMENT-PATTERNS:** if a 5th+ ADR invokes the same meta-principle, document the reasoning shape explicitly (when to invoke vs when to defer to threshold-based promotion). 4 instances is now well above the 3-instance threshold; the meta-principle is project corpus norm and a DEVELOPMENT-PATTERNS entry is warranted at the next architectural-decision opportunity.

### 2026-05-03 — ADR-017 forcing-function compliance (`test_consumer_aggregates_sequenced_findings`)

**Pin (load-bearing).** The ADR-017 forcing-function test pin specified by name at ADR-017 line 1474-1475 has been honored for the first time in the project corpus. `test_consumer_aggregates_sequenced_findings` in `tests/services/test_completions_consumer_findings_ingest.py` synthesizes the canonical sequencing roundtrip:

- 3 events × 833 + 833 + 834 findings = 2500 total
- Events 1, 2 (intermediate, status=`partial_findings`): accumulator grows to 833, then 1666; **0 raw_findings rows**; ScanJob.status remains `running`
- Event 3 (terminal, status=`completed`, finding_count=2500 authoritative per ADR-017 line 822): single-transaction commit produces **2500 raw_findings rows**; ScanJob.status updates to `completed`; ScanJob.finding_count = 2500; accumulator key `(scan_id, job_id)` cleared

The test passes (Phase 3 verification). Future regressions surface immediately at this test name; future engineers reading the ADR-017 line 1474-1475 contract reference can search for `test_consumer_aggregates_sequenced_findings` and find the pin.

### 2026-05-03 — Pydantic schema strictness decision (extra="forbid"; cross-repo schema-drift regression guard)

**Pin.** `app.schemas.raw_findings.RawFindingCreate` uses `model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, populate_by_name=True)`.

`extra="forbid"` mirrors the engine-side `DisallowUnknownFields` discipline at `shieldscan-engine/internal/events/events.go` line 12-13. **Cross-repo schema-drift regression guard:** if the engine adds a field to `RawFinding` without a synchronized Pydantic schema update, ingest will reject the payload at the CompletionsConsumer layer. Same shape as ADR-024's synchronized extension workflow (Engine struct → Python schema → Alembic migration); same forcing-function discipline transferred from M4 Pydantic `extra="forbid"`.

`populate_by_name=True` enables the mobile-field aliasing (engine wire `permission` → Python `mobile_permission`; engine wire `component_name` → Python `mobile_component_name`) without breaking direct-field-name construction in tests.

**Forward-pin:** future engine wire-format changes (additional categorical fields, evidence map, structured references) need synchronized Pydantic + Alembic + ADR work. The cross-repo workflow is now established and inheritable.

### 2026-05-03 — Service-class accumulator pattern (1st instance; track for promotion)

**Pin (track-only).** `CompletionsConsumer._accumulator: dict[tuple[UUID, UUID], list[dict]]` guarded by `asyncio.Lock`, populated in `_handle_intermediate_event`, drained + cleared in `_handle_terminal_event` after successful commit.

**1st instance** of the service-class accumulator pattern in the project corpus. Pattern shape:
- Stateful service class (DI-friendly via constructor)
- Async-loop-safe via `asyncio.Lock` (single-process; no cross-process coordination)
- Process-local lifetime (cleared on process restart; ghost-queued janitor at OPS milestone handles ScanJob orphans)
- Capture-and-clear-only-after-commit semantics (commit failure → accumulator retained for retry-via-redelivery)

Track for promotion to DEVELOPMENT-PATTERNS at 3rd instance. Likely candidates for future instances: M9 cross-layer correlation accumulator (per-scan vulnerability dedup state); M11 dashboard fan-out aggregator (per-org real-time stream consolidation).

### 2026-05-03 — Findings-ingest implementation deviations (consolidated; 9 deviations across Phases 0-3)

**Pin (load-bearing for future-implementer reference).** Phase 0 (verification) + Phase 1 (Pydantic schema) + Phase 2 (CompletionsConsumer extension) + Phase 3 (integration tests + ADR-017 forcing-function pin) surfaced **nine factual/mechanical deviations** from the design doc's pre-verification expectations. All auto-corrected with documentation per the "factual deviations: auto-correct + document" protocol established during M6-close-followup work; **zero architectural deviations** required pause/re-approval.

**Deviation 1 — `RawFinding.job_id` column does NOT exist (Phase 0).** Lean A: drop `job_id` from `finding_dicts`; per-engine attribution preserved through `tool_name`. Design doc §3.3.1 + §4.4 + §3.3.3 assumed `job_id` column. Resolution: `_build_finding_dicts` strips per-finding `scan_id` + `org_id`; `_persist` overrides with `scan_job.scan_id` + validated `org_uuid`.

**Deviation 2 — Existing `_handle` filter rejects `partial_findings` event_type (Phase 0).** Auto-adapt: extended filter from `== "job_completed"` to `in ("job_completed", "partial_findings")`. Without this, sequenced intermediate events would be silently dropped → ADR-017 accumulator pattern broken. Behavioral pin: `test_handle_event_routes_partial_findings_event_type` locks the extension against future "tightening" regressions.

**Deviation 3 — `SET LOCAL` vs `SET` for RLS preamble (Phase 0; revised at Phase 2 by Deviation 9).** Lean A: use `SET app.current_org_id = '<uuid>'` (no LOCAL); matches existing project pattern at `db/__init__.py:38`, pre-extension `completions_consumer.py:177`, `identity.py`, `audit.py`, `db/policies.py`. Revised at Phase 2 because parameterized form fails — see Deviation 9.

**Deviation 4 — Multi-process accumulator + N>1 worker damage (Phase 0).** Accept-and-document. With N>1 uvicorn workers, each process accumulates independently and commits its own subset → duplicates AND/OR partial subsets. Mitigation: terminal-event path includes ScanJob-already-terminal short-circuit BEFORE bulk insert (`_persist` lines 387-401). Bounds damage at MVP scale; does not eliminate. **Genuine fix at scale: ADR-018 Streams + consumer-groups (deferred).** Revisit trigger: **first deployment with N>1 uvicorn workers**.

**Deviation 5 — Mobile field name mismatch engine ↔ model (Phase 1).** Engine wire emits `permission` + `component_name`; Python model has `mobile_permission` + `mobile_component_name`. Auto-adapt: Pydantic `Field(alias=...)` + `populate_by_name=True`; `model_dump(by_alias=False)` in `_build_finding_dicts` ensures SQLAlchemy column names land in the dict (wire aliases would fail with unknown-column errors).

**Deviation 6 — `engine_category` Literal has 13 values, not 11 (Phase 1).** Design doc §3.2 listed 11 (`dast` through `container`); actual SQLAlchemy `EngineCategory` enum has 13 (adds `spa` + `discovery` per SPEC §5.3 + ADDENDUM-TOOLS-5). Auto-adapt: Pydantic Literal mirrors the 13-value set. Test `test_engine_category_has_thirteen_values_including_spa_and_discovery` (in `tests/models/test_findings.py`) pins this behaviorally.

**Deviation 7 — ADR-025 §3.2 / §4.1 Pydantic schema mismatches (Phase 1; deferred to ADR-025 followup).** Design doc §3.2's example Pydantic schema has 4 mismatch shapes vs the actual model: (a) missing `title`/`description`/`owasp`/`cvss_score`/`parameter`/`payload`/`raw_output_ref`; (b) wrong SSL field names (`ssl_cipher_suite`/`ssl_cert_subject` vs actual `cipher_suite`/`cert_subject`); (c) wrong mobile field names (no aliases); (d) missing `spa`+`discovery` enum values. **Out of scope for this commit.** Mahmoud handles the design-doc revision + ADR-025 final text in `shieldscan-docs` separately post-implementation.

**Deviation 8 — `ScanJob.completed_at` column does NOT exist (Phase 2).** Only `Scan` has `completed_at`; ScanJob does not. Design doc §3.3.1 line 352 (`scan_job.completed_at = datetime.fromisoformat(event["timestamp"])`) would fail at SQLAlchemy time. Auto-adapt: dropped `completed_at` updates from all paths; preserved existing handler's behavior at pre-extension lines 204-207.

**Deviation 9 — PostgreSQL `SET` admin command rejects bind parameters (Phase 2).** asyncpg surfaces this as `syntax error at or near "$1"`; `SET` is a Postgres admin command, not regular SQL. Resolution: validate `organization_id` as `UUID()` first (raises on anything that isn't 36 hex+hyphen chars), then f-string interpolate. **Strictly better than the existing project pattern** at `completions_consumer.py:177` (which f-string-interpolates without UUID validation) — this implementation adds defense-in-depth in passing while matching established f-string posture. Revises Phase 0 Deviation 3 lean (parameterized form was incorrect).

**Pattern observation:** all 9 deviations are factual/mechanical (assumed-state vs actual-state mismatches); zero architectural deviations needed pause/re-approval. The "verify-then-adapt-then-document" discipline established during M6-close-followup work continued to operate cleanly. Pre-implementation guidance is generated against general-purpose semantics; verification catches actual-behavior gaps. This is the third project-corpus task where the pattern has held (M6.3 httpx stdin, M6-followup head-vs-root, findings-ingest 9-deviation set) — the discipline is project corpus norm.

### 2026-05-03 — `_scanjob_already_terminal` removal (honest code over misleading helper; refactor during Phase 3)

**Pin.** A late-Phase-2 / pre-Phase-3 verification check (per the user's pre-Phase-3 verification request) surfaced that the `_scanjob_already_terminal(event)` helper introduced in Phase 2 always returned `True` unconditionally — its docstring acknowledged this as a "future hook if more nuanced returns from `_persist` surface later." The method NAME suggested state-checking that the implementation didn't perform.

**Subtle bug shape avoided:** if a future engineer "fixes" the method to actually re-fetch ScanJob.status but reads cached state (e.g., from the event payload, or a stale ORM identity-map entry) instead of DB-fresh, the persist-short-circuit case leaks accumulator entries. The misleading helper was a future-engineer trap.

**Resolution (refactor during Phase 3 before integration tests started):** removed `_scanjob_already_terminal` entirely; replaced the conditional cleanup with a straightforward try/except pattern in `_handle_terminal_event`:

- `_persist` raises → propagates → accumulator retained for retry-via-redelivery (Phase-0 Deviation 5 cleanup ordering preserved)
- `_persist` returns (True or False) → reach the cleanup block → clear unconditionally

Same observable behavior (all existing unit tests still pass after refactor; 24/24 at the Phase 3 boundary); honest code; future-engineer trap eliminated. Engineering principle reinforced: **method names should reflect what the implementation does, not what we hope it might do.**

---
