# shieldscan-api — DRIFT-LOG

API-side design decisions, deferred work, and implementation deviations.
Newest entries on top.

For cross-cutting decisions affecting both `shieldscan-api` and
`shieldscan-engine`, see `../shieldscan-docs/DRIFT-LOG.md`. For
engine-specific entries, see `../shieldscan-engine/DRIFT-LOG.md`.

---

### 2026-08-20 — API half of engine Drift #70: reclaimed jobs get a writer, and `scan_jobs.error_message` finally holds something — no catalogue increment

**Not a drift entry.** The catalogue increment is engine-side (`shieldscan-engine/DRIFT-LOG.md` Drift #70, 69 → 70). This records what the api had to change for it, because three of the four changes are in files a reader would otherwise expect to be untouched.

**Context in one line.** The engine used to destroy a job's payload the instant it was popped, so a worker death lost the job permanently; ADR-013 makes Python the sole writer, so no event meant no write and the row stayed `queued` forever. The engine now checks jobs out into a per-worker processing list and recovers them by publishing the terminal event the dead worker never sent.

**1. `scan_jobs.error_message` is now persisted.** The column has existed since the first scans migration and was NULL for all 198 rows in production — including all 7 failed and canceled ones. It stops being cosmetic here: recovery's whole diagnostic payload is the reason string, and a log line is not queryable. Two lines in `_persist`, assigned only when the event carries a message so a re-delivered success can never blank a stored reason. **Closes `task_c7113785`.**

**2. A terminal job can no longer be moved off its status.** `_persist`'s short-circuit used to require the incoming status to *match* the stored one, which was sufficient while every event came from the worker that ran the job. The reclaimer breaks that: it can lose a race with an acknowledgement and publish `failed` for a job that completed, and under the old rule that event would have overwritten a job whose findings were ingested and whose scan had aggregated. It now fires on any terminal status, and logs at WARNING when the statuses differ — the interesting case. Side effect, and the right one: job-level behaviour now matches the scan-level cancel-wins policy from Task 4.5 H.2.

**3. `CompletionsConsumer.apply_event` — a public door onto `_handle`.** The backfill replays the events dead workers never sent. Making it go through the live routing/persistence/aggregation path, rather than reimplementing those writes, is what stops the two from drifting. Exceptions propagate, unlike the consume loop's `_handle_safely`: a backfill wants to know what failed.

**4. `services/stranded_jobs.py` + `scripts/backfill_stranded_jobs.py`.** One-shot recovery for jobs stranded before the engine fix.

The **ghost test** lives here and nowhere else: a job is stranded only if it is non-terminal in PostgreSQL AND its payload is absent from Redis — from the four priority queues *and* from every worker's processing list. Status alone would fail live work: a job legitimately waiting its turn also reads `queued`, and one a worker is running right now reads `queued` too, because nothing sets `running`. Missing the processing-list half is the dangerous direction — it would mark every actively running job stranded and fail it underneath a live worker.

Two deliberate properties. The stranded set is **re-derived on every run**, never taken from a snapshot; a list captured during an investigation goes stale the moment a scan finishes. And the `error_message` is **distinct**, so these stay separable from genuine tool failures — without that the recovery would be indistinguishable from the thing it recovers from.

**Why this is recovery and not tidying.** Fifteen stranded jobs block twelve parent scans from ever aggregating, and `_maybe_complete_scan` is what dispatches the AI pipeline. **1,422 raw findings** already collected and already paid for in compute have never been analysed, purely because a sibling job never reported. The cost of stranding was never a wrong status field; it was discarded work.

**ADR-013 is intact, and says so explicitly now.** Nothing added here writes scan state outside the consumer. The engine's sweep reads only Redis and emits events. The backfill *does* compare Redis to PostgreSQL, which is one line away from the "periodic reconciliation jobs" anti-pattern in ADR-013 — so a scope note now records that it is deliberately one-shot, and that if it ever acquires a schedule the right response is to find out why jobs are still being stranded.

Cross-references: `shieldscan-engine/DRIFT-LOG.md` Drift #70 (the catalogue entry) and Drift #69 (the defect); `src/app/services/stranded_jobs.py`, `scripts/backfill_stranded_jobs.py`, `src/app/services/completions_consumer.py`; `tests/services/test_stranded_jobs.py`; SPEC §7.1 checkout contract, §7.5 claim release, ADR-013 correction + scope note; Drift #68 (the `job_completed` line that now carries `error_message` to a column as well as a log).

---

### 2026-08-16 — Drift #68: The API never had a logging configuration — every `info` line discarded, every `warning`/`error` unattributable, for the life of the project — Cumulative Drift Count 67 → 68

**The drift.** `shieldscan-api` has never configured logging. There is no `basicConfig`, no `dictConfig`, no `--log-config` on the uvicorn launch. Uvicorn's default `LOGGING_CONFIG` attaches handlers to exactly three loggers — `uvicorn`, `uvicorn.error`, `uvicorn.access` — and defines **no `root` entry**. Every `app.*` logger therefore had no handler anywhere on its propagation chain. Consequences, in force since M1:

1. **`logger.info` and `logger.debug` produced no output at all.** All 15 `info` and 2 `debug` call sites in `src/` have been dead since they were written. Not throttled, not filtered — never emitted.
2. **`warning` / `error` / `exception` were emitted only by `logging.lastResort`**, the stdlib's WARNING-level fallback. That handler prints the bare message to stderr with **no timestamp, no level, no logger name**, and honours no formatter. Every API log line in the project's history is unattributable to a module or a point in time.

**Evidence, not inference.** Applying uvicorn's own `LOGGING_CONFIG` and then logging INFO and WARNING through an `app.services.*` logger emits the WARNING and drops the INFO — reproduced in a subprocess and pinned by `tests/test_logging_config.py`. Independent corroboration from this project's own artifacts: `/tmp/api.log` during the #67 outage contains

```
fix-gen: Claude call failed for vuln 935d28de-…; fallback
```

with no timestamp, no level and no logger name — the visual signature of `lastResort` output, sitting directly beneath uvicorn's own properly-formatted `INFO:` lines for contrast.

**Relationship to #67.** #67 is the incident that exposed this; it is not the same defect. #67 was scoped to the AI pipeline: a billing state plus four observability layers that could not distinguish working from degraded. **This entry is wider and older** — it is the substrate all of those layers were logging *into*. #67's failure 1 ("the cause was discarded") describes code that threw away the exception detail; this entry describes the fact that even a perfect log line would have gone nowhere if written at `info`, and would have printed without timestamp or origin if written at `warning`.

**Why the earlier diagnoses were as hard as they were.** The nmap silent-loss investigation (14 consecutive runs reporting success and persisting nothing) and the `tool_metadata` investigation were both reconstructed from database queries, because the log could not answer them. Specifically, `_build_finding_dicts` logged the per-finding rejection reason — *which validator, which field, which tool* — at **`logger.debug`**. That is the single line that would have named the cause in both investigations, and it has never produced output at any level in the process's life. The aggregate sat at `warning`, so it reached `lastResort` as a bare, timeless string.

**Fix.** New `src/app/logging_config.py`: one `StreamHandler` on root, formatter carrying timestamp / level / logger name / message, level from a new `LOG_LEVEL` setting (default `INFO`), called from the FastAPI lifespan before anything can log. Idempotent, so a repeat call replaces its handler rather than doubling every line. Uvicorn's own records are unaffected — `uvicorn` and `uvicorn.access` set `propagate=False` and `uvicorn.error` propagates only to its `uvicorn` parent, so nothing double-emits (asserted, not assumed). Back-out is deleting one call in `main.py`.

Rejection logging raised in the same change: per-finding detail `debug → warning` (capped at the first 3, since a schema mismatch rejects every finding in a batch identically), aggregate `warning → error` with the total-loss case — `rejected == total`, the nmap shape — called out explicitly on the line.

**Volume verified empirically before trusting INFO as the default.** A root handler at INFO unmasks third-party loggers, so this was measured rather than estimated:

- **SQLAlchemy is not unmasked.** `sqlalchemy/log.py` sets its own root logger to `WARNING` at import when unset, so `root=INFO` does **not** enable statement echo. 11 real statements → **0 records**. This was the one library that could have produced thousands of lines per scan.
- **Redis: 0 records** across 25 pub/sub messages round-tripped on the consumer's actual transport path plus 10 pings. `from_url` negotiates **RESP2**, so `_parsers/resp3.py`'s per-message `"Push response:"` INFO line — the one library site that would scale with scan size — is not on the path.
- **Qdrant: 0** across 5 calls (its only `logging.info` sites are in `parallel_processor.py`, the bulk-upload workers, which we do not use). **asyncpg: 0** INFO sites. **httpcore: 0** INFO sites. **urllib3:** redirects only. **asyncio:** all 10 sites debug-mode-gated or exceptional; measured 0. **httpx** is pinned to WARNING in `logging_config.py` (it logs one line per outbound request, which would narrate every AI call).
- **anthropic / openai:** 2 INFO sites each, both `"Retrying request to %s in %f seconds"` — SDK-internal retry only, zero on success. Worth noting for #67: these would have been a genuine library-level signal during a *retryable* outage, but the credit failure was a `400`, which the SDK does not retry, so even that line would not have appeared.

Composed against real scan `cf4a8504` (7 jobs, 642 raw findings, 34 vulnerabilities, 18 AI calls, 0 errors): **~9 app INFO lines per scan** — 7 `job_completed` (one per job) plus 2 pipeline lines — with **0 library lines**, against 4 process-lifetime start/stop lines and 2 per SSE client session. The signal is not buried. End-to-end confirmation is deferred to the first API restart carrying this change, since the process that produced the numbers above predates it.

**Forward-pin, found while writing the failure line, not fixed here.** `scan_jobs.error_message` **has never been populated**: 198 rows, 7 of them `failed`/`canceled`, **0 non-NULL**. The Go worker sends `error_message` on failed `job_completed` events and `_persist` writes `status`, `finding_count` and `duration_ms` while discarding it. The new log line is therefore the *only* place a failed job's reason survives at all. Persisting it to the column is a separate change.

**Root-cause class.** The #67 class was "a check that passes for a reason unrelated to what it claims to verify". This one is its complement: **a signal written correctly and delivered nowhere**. Every `logger.info` in this codebase was, until now, a comment with runtime cost.

Cross-references: Drift #67 (the incident that exposed this); `src/app/logging_config.py`, `src/app/main.py` (lifespan call), `src/app/config.py` (`LOG_LEVEL`); `tests/test_logging_config.py` (forcing function — fails if uvicorn ever ships a `root` entry, at which point the module should be deleted rather than left as ceremony); `src/app/services/completions_consumer.py` (`job_completed` line + rejection levels); `tests/services/test_completions_consumer_logging.py`.


### 2026-08-15 — Drift #67: Anthropic credit exhaustion degraded 9 scans to placeholder fixes for 34 hours, undetected — Cumulative Drift Count 66 → 67

**The drift.** The Anthropic account's credit balance ran out at **2026-08-14 ~01:18Z**. Every `fix_generation` and `executive_summary` call has returned `400 invalid_request_error` ("Your credit balance is too low") since. The pipeline behaved correctly — it fell back to `_fallback_fix_template` and set `Scan.ai_pipeline_degraded` every time — but **nothing surfaced it for 34 hours across 9 scans**. Diagnosed only because a log dump pasted during an unrelated investigation happened to show 9 `fix-gen: ... fallback` lines plus 1 `summary: ... fallback`.

**Blast radius (audited).** 134 placeholder / 219 real / 185 NULL (INFO, correctly excluded) across 538 vulnerabilities. Scan `c1f8e490` (Aug 14 01:04) caught the balance crossing zero mid-run: **8 placeholder / 28 real**. Every scan after it is 100% placeholder — `aa329fb2` (39), `62a4cb22` (2), `87c13e8c` (11), `a8406909` (10), `92b48b50` (9), `46212b17` (9), `d6bfd80a` (9), `27b6b561` (11), `91ca9d3f` (9). **Reports: no PDF was generated during the outage** (newest is Aug 10), so no persisted customer artifact embeds these. `9ed6a1ab` (Aug 4) does contain 9 placeholders, from the *budget-cap* era — see below. JSON/SARIF render on demand and are never stored, so a download during the outage would carry placeholders with no record.

**Why it stayed invisible — four separate failures, none of them the fallback itself.**

1. **The cause was discarded.** `generate_fix` caught broad `Exception` and logged one `warning` summary line naming neither the exception type nor the status. The API returned an unambiguous, fully-diagnostic billing error on every call and the code threw it away. The fallback is correct behaviour; discarding *why* is not.
2. **`ai_pipeline_degraded` was correct and unread.** The flag was `true` on all 9 scans the whole time. The signal existed; nothing consumed it. Verification instead used `ai_fix_text IS NOT NULL`, which `_fallback_fix_template` also satisfies — so the check could not distinguish a real fix from the placeholder and reported 9/9 healthy.
3. **Cost metrics read a broken pipeline as a cheap one.** The failure path logs `tokens_in=0, tokens_out=0, cost_usd=0`. A 100%-degraded pipeline is therefore indistinguishable from an inexpensive one; the spend graph looked *healthier* precisely because nothing was working.
4. **Every failure was retried three times.** `_call_claude_with_retry` treated all exceptions uniformly, so a 400 that can never succeed burned 3 attempts × 10 calls = **30 doomed requests per scan**, tripling latency before the fallback appeared.

**One template, two causes — why text-matching was the wrong audit tool.** The audit above had to match `ai_fix_text LIKE '%temporarily unavailable%'`. That predicate breaks silently if the template wording ever changes, and it cannot separate the two distinct causes that emit it: **budget exhaustion** (`check_budget` refusing the call — scans `a70e1711` Aug 4 and `bada2318` Aug 2, before `9ef8027` raised the caps) and **API failure** (this outage). Both look identical in the column.

**Fix (`e4b8c2a71f36` + code).** Log the cause at **error** with exception type, status, provider error type and `exc_info`, in both `fix_generation` and `summary`. Classify retries — retry 429 and 5xx, fail fast on other 4xx, keep retrying status-less connection/timeout errors. Add **`ai_api_calls.error_type`** (NULL = success; otherwise the provider's error type) so a failed call is not shaped like a free one. Add **`vulnerabilities.ai_fix_is_fallback`**, set by a single `_use_fallback()` helper that writes text and flag together so they cannot drift, used by *both* fallback paths and cleared on success — the per-vulnerability counterpart to the scan-level `ai_pipeline_degraded`.

**Not backfilled, deliberately.** `ai_fix_is_fallback` defaults to `false`, so the 134 historical placeholders read as non-fallback. Backfilling by text match would bake the exact fragile predicate the column exists to replace into a permanent migration, and the historical answer is recorded in this entry. Rows written from now on are accurate.

**Root-cause class.** Not a code defect — a billing state. What *was* defective is that four independent observability layers each failed to distinguish "working" from "degraded". This is the session's recurring shape: a check that passes for a reason unrelated to the thing it claims to verify.

**Counters.** Cumulative drift count **66 → 67**. Forward-pinned, not done here: the Claude model string + hardcoded Sonnet pricing constants + `ESTIMATED_FIX_COST_USD` + the anthropic SDK pin, which must move together or cost tracking silently reports wrong numbers.

Cross-references: `e4b8c2a71f36` (migration); `src/app/services/ai/fix_generation.py`, `summary.py`, `cost_tracking.py`; `9ef8027` (the earlier budget-cap raise whose fallbacks share the template); ADR-032 (M9.C fix generation).


### 2026-07-31 — M10.D Sub-Milestone CLOSED + M10 REPORT ARCHITECTURE MILESTONE ENTIRELY CLOSED (4 of 4) — Cumulative Drift Count Preserved at 66

Closure entry for the fourth + final M10 sub-milestone (Task 10.6) **and** the milestone-level M10 closure. **Not a drift entry — no Drift #67**: M10.D landed **0 catalogued drifts**, and M10 as a whole landed 0 across all four sub-milestones. Structural precedent: the M10.C closure entry `08aa94a` (a closure summary, not a catalogue increment).

**M10.D chain — all γ, no C0 / no migration / no ADR** (Redis-read-only over an existing signal — the leanest sub-milestone shape in the arc). Stage 1 lock-record `74f0688` (Mode-2 compressed; Gate-1 / 5 locks) + C1 `3d94c42` (the single implementation commit) + P5.A docs annotations `93c16e9` + this api DRIFT-LOG closure + engine cross-ref forthcoming.

**M10.D delivered.** `GET /orgs/{org_id}/tools/health` — **two-state per-tool availability** (`available` if ≥1 live worker advertises the tool via the heartbeat `engines` list, else `unavailable`; **NO fabricated "degraded"** — the heartbeat carries liveness + engines-list, not per-tool health; the direct echo of M10.C's `not_assessed` honesty) derived from the **existing** engine heartbeat fleet signal (`shieldscan:workers:*` via the first `scan_iter` in the api — no engine change, no signal written). Liveness = SETEX-TTL presence; org-scoped/membership-gated but GLOBAL fleet data (the M10.C global-behind-org-path shape); distinct from `/ready` (API-pod infra vs worker-fleet). Suite **834 passed / 1 skipped** (intentional drain forward-pin) / 0 failed.

**M10.D mitigations (why 0 catalogued drifts):** the entry-probe confirmed minimality (the health signal EXISTS — no engine change) and surfaced the signal-shape-vs-plan-literal-three-state finding **before** design; **V-MMD** grounded drain-status as **NOT a live signal** (the `HSET worker:$id status "draining"` is ops-runbook-only, not written by worker code — availability derived from heartbeat presence only, drain-awareness forward-pinned, the test **skipped-and-noted** rather than silently dropped); the **13th averted-prediction** — a cross-repo tool-name mismatch (engine `registry.Engines()` vs the api's `SCAN_TYPE_TOOLS` vocabulary) resolved by reusing `orchestrator.py`'s `SCAN_TYPE_TOOLS` as the single-source known-set, with normalization forward-pinned; two-state honesty held (no invented `degraded`).

**Lineage / counters.** 13-instance averted-prediction lineage (the cross-repo tool-name grounding is the 13th). The 3-instance test-gate-within-lock pattern is **NOT incremented**. **Drift #66** (M9.A C1 ORM-vs-DB) remains the latest catalogue entry. Both auth-route infra flakes (rate-limiter IP-counter + `/ready` dep-timeout) were **ABSENT** across the C1 run — the hardening pass (`c128e60`) is holding through M10.D. Cumulative session-tail framing-drift count: **66**.

**🏁 M10 REPORT ARCHITECTURE — ENTIRELY CLOSED (4 of 4).** All four sub-milestones CLOSED: **M10.A** vulnerability endpoints + **M10.B** report generation/delivery (ADR-034) + **M10.C** compliance mapping + **M10.D** tool health. M10 as a whole landed **0 catalogued drifts** (cumulative held at 66 across the entire milestone). The decomposition mini-chain **DQ1-DQ5** (`41ad3e6`) is complete/exhausted. M10 delivered the **customer-facing surface over the M9 pipeline**: vulnerability triage + downloadable PDF/JSON/SARIF reports + compliance posture + worker-fleet health.

**M10-level forward-pins (consolidated).** tier-gating → billing (**4 instances**: /fix + report-endpoints + compliance + tools); eager-PDF + unique-constraint(scan_id,format) + per-download-expiry → production-readiness; white-label → Enterprise; full-OASIS SARIF 2.1.0 schema swap → hardening; auth-route infra-probe test-isolation (/ready resolved; rate-limiter unreproduced-monitored) → production-readiness; PCI framework seed → Enterprise; exhaustive compliance control/CWE coverage → post-launch; ISO 27001:2022 renumber → future migration; degraded tool-state → a real per-tool health signal; cross-repo tool-name normalization → follow-up; drain-status → fold-in-if-live.

**⇒ M10 complete — no further M10 trigger.** The next milestone is the subsequent roadmap item (a fresh planning entry; NOT begun here).

Cross-references: shieldscan-docs `93c16e9` + `74f0688` + `41ad3e6`; shieldscan-api `3d94c42` + `08aa94a` (M10.C P5.A precedent) + `orchestrator.py` (`SCAN_TYPE_TOOLS` known-set); shieldscan-engine `5fcc06a` (Commit 3 target) + `internal/worker/heartbeat.go` (signal source); SPEC §6 line 567 + §7 heartbeat contract.

---

### 2026-07-31 — M10.C Sub-Milestone CLOSED (third M10 sub-milestone; Compliance Mapping) — Cumulative Drift Count Preserved at 66

Closure entry for the third M10 sub-milestone (Task 10.5; SPEC §DB + §6 + §9). **Not a drift entry — no Drift #67**: M10.C landed **0 catalogued drifts**. Structural precedent: the M10.B closure entry `6b75278` (a closure summary, not a catalogue increment).

**Chain — all γ, no C0.** Stage 1 lock-record `bee52c6` (light Mode-2, 2 gates / ~9 locks) + C1 `edea03a` + C2 `40b8243` + P5.A docs annotations `10b4502` + this api DRIFT-LOG closure + engine cross-ref forthcoming. **No C0 / no ADR** — data-model + seed over existing patterns (like M10.A; ADR-034 was reserved for M10.B). But unlike M10.A this **carried a migration** (schema + a first-of-kind seed/data migration `a7c3e9f04b21`), so *C0-less ≠ migration-less* here.

**Delivered.** Compliance mapping end-to-end (scan findings → `Vulnerability.cwe_id` → control → three-state posture; per-scan × framework primitive + org-wide worst-state aggregate). 3 **GLOBAL** reference tables (`compliance_frameworks` → `compliance_controls` → `cwe_control_mappings`). SOC2 (CC-series) + ISO 27001:2013 Annex A seed. 3 org-scoped GET endpoints (frameworks list · per-scan posture · org posture). Suite **828, ZERO regressions**.

**Mitigations (why 0 catalogued drifts):**
- **Entry-probe grounding before design** resolved two would-be drifts empirically: the **3-vs-2-table scope-delta** (decomposition/plan-literal omit `compliance_controls`) → resolved in **SPEC-canon's favor** (lines 331-333; echoes M10.A 7-vs-4 + M10.B 5-vs-4); and the **GLOBAL-vs-tenant determination** → SPEC **line 345's explicit enumeration** of these 3 tables as non-tenant-scoped (grounded, not inferred).
- **Test-enforced global-data decision:** the **not-in-TENANT_TABLES ∅ assertion** (`{frameworks,controls,mappings} ∩ TENANT_TABLES == ∅`) makes the global-reference-data call a test invariant — the deliberate **mirror-image inverse of M10.B Catch-1** (where `reports` had to be *added* to TENANT_TABLES or its cross-tenant test would false-pass; here the tables must be *kept out* or the global-data decision is undefended).
- **create_all-vs-migration seed-split** surfaced + resolved: the test harness builds schema via `create_all`, not migrations, so the migration's `op.bulk_insert` seed is absent in tests → added a runtime `seed_compliance_data()` helper in `services/compliance/frameworks.py`. Same harness-gap class as M10.B Catch-1 (there on RLS reaching the test DB; here on seed data) — an **averted-prediction-class grounding refinement**.
- **Three-state posture honesty:** `NOT_ASSESSED` verified genuine against SOC2 **CC7.2 / CC8.1** (controls with no CWE mapping) — the artifact never overclaims a control as `pass` when it simply can't assess it.
- **`op.bulk_insert` first-of-kind** (no seed-migration precedent in the repo) landed clean with an **inline-literal seed** (UUIDs generated at upgrade-time, threaded through FKs) rather than importing app code into the migration — migration import-stability across schema evolution.

**Lineage / counters.** 12-instance averted-prediction lineage (the seed-split refinement is in-class). The 3-instance **test-gate-within-lock** pattern is **NOT incremented**: the C1 + C2 test-authoring iterations were malformed-query fixes (an explicit `.select_from()` disambiguation) — *test source touched, product source untouched* — normal authoring workflow, not the class. **Drift #66** (M9.A C1 ORM-vs-DB) remains the latest catalogue entry. Cumulative session-tail framing-drift count: **66**.

**Infra-flake status.** BOTH auth-route infra flakes (rate-limiter IP-counter + `/ready` dep-timeout) were **ABSENT** across the C1 (818) and C2 (828) full-suite runs — the preceding hardening pass (`c128e60`: Flake-2 monkeypatch fix + Flake-1 corrected-record) is holding; the clean-green baseline is restored.

**Forward-pins carried out of M10.C.** tier-gating → billing (**3rd instance**: /fix + report-endpoints + compliance); PCI framework seed → Enterprise tier; exhaustive control/CWE coverage → post-launch expansion; ISO 27001:2022 renumber → future migration; $49 compliance-PDF add-on → M10.B report territory.

**⇒ Next per DQ5:** *"Begin M10.D — Tool Health"* (Task 10.6; minimal shape per DQ4 — the **final** M10 sub-milestone; closes M10 entirely).

Cross-references: shieldscan-docs `10b4502` + `bee52c6` + `41ad3e6`; shieldscan-api `40b8243` + `edea03a` + `6b75278` (M10.B P5.A precedent); shieldscan-engine `7941df6` (Commit 3 target); SPEC §DB + §6 + §9 + line 345.

---

### 2026-07-27 — Auth-Route Infra-Flake Hardening: /ready determinism FIXED + rate-limiter flake analysis CORRECTED — Cumulative Drift Count Preserved at 66

Resolves the prioritized auth-route test-isolation hardening forward-pin carried through M10.B. Not a drift entry — a test-determinism fix + a **correction of a previously-recorded root cause** (the 12th averted-prediction class: correcting a committed belief).

**Flake 2 (`test_ready_returns_200_when_deps_healthy`) — FIXED.** Mechanism confirmed at probe: `_PROBE_TIMEOUT = 0.5` (a module constant at `main.py:46`) wraps the real postgres/redis round-trips in `asyncio.wait_for`; under ~350s full-suite CPU contention a real dep round-trip exceeds 500ms → `timeout_500ms` → 503 → the 200-assert flaked (surfaced at M10.B C3 `9b2724e`). Fix (test-only, C-B): monkeypatch both `_check_postgres` + `_check_redis` to healthy in this test — mirroring the sibling `test_ready_returns_503_when_redis_unreachable`, which already monkeypatches `_check_redis` — so the test deterministically proves the readiness-aggregation-returns-200 logic (its actual point) without gating on real-infra latency (an ops concern, not this unit's). Assertion preserved (still 200 + `{"postgres":"ok","redis":"ok"}`). No prod-surface change. Also removed a pre-existing unused `from app.config import settings` import (F401) in the same file to keep it ruff-clean (incidental in-file hygiene).

**Flake 1 (`test_login_rate_limited_by_ip_after_5_attempts`) — ANALYSIS CORRECTED, NOT fixed (12th averted-prediction).** The C1-recorded root cause ("Redis IP-attempt-counter state not reset between tests"; surfaced at M10.B C1 `ac91e62`) is **REFUTED by the fixtures**: `fake_redis` is fresh-per-test with `flushall()` teardown (conftest:149-160), `client` overrides `get_redis` to that same fresh instance (conftest:251-252) → no cross-test leakage possible; the test uses a unique IP (`198.51.100.77`); fakeredis is in-memory (no latency); the `login_ip` window is 900s so a sub-second straddle is ~0.1%. Static analysis says the test should be deterministic. A **reproduction pass — 6 isolation runs + 3 full-suite runs (810 passed each, 0 failures) — did NOT surface the failure.** Per the no-blind-fix guardrail, NO speculative code fix was applied (a `time.time` clock-pin would mask, not resolve, an unconfirmed mechanism). Grounded residual hypotheses for monitoring: a load-induced dropped/slow request within the 5-attempt loop (fewer than 5 increments land → 6th allowed), or the ~0.1% window-boundary straddle.

**Forward-pin narrowed:** the auth-route infra-probe hardening pin is now closed for /ready (fixed) and reclassified for the rate-limiter as *"unreproduced under 9 exposures; C1 cause refuted; monitor — reopen only if it recurs with captured evidence."*

Cumulative session-tail framing-drift count: **66** preserved (Drift #66 remains latest catalogued drift). 12-instance averted-prediction lineage (the refuted C1 cause is the 12th — a correction to a previously-committed belief). Cross-references: shieldscan-api `9b2724e` (/ready flake) + `ac91e62` (rate-limiter flake) + the two M10.B DRIFT-LOG closure entries that carried the prioritized pin.

---

### 2026-07-26 — M10.B Sub-Milestone CLOSED (second M10 sub-milestone; Report Generation + Delivery) — Cumulative Drift Count Preserved at 66

M10.B (Report Generation + Delivery; Tasks 10.2/10.3/10.4; ADR-034) closed its entire lifecycle with **zero catalogue increments** — the second M10 sub-milestone. This is a closure note, **not** a drift entry — Drift #66 (M9.A C1) remains the latest catalogued drift. Docs closure at `397df21`; ADR-034 canonical at SPEC §13 `f099a5c`.

**M10.B chain (all outcomes γ; 5 code + 2 docs micro-commits):** Stage 1 design `92fe1c7` (Mode-1 full; 5 gates / 17 locks) + C0 ADR-034 `f099a5c` + C1 `ac91e62` (reports table + Report/ReportFormat + RLS migration parent `ecfed70e05e4` + TENANT_TABLES registration + jsonschema 4.26.0 + bundled SARIF 2.1.0 schema) + C1-docs `67f0676` (jsonschema VERSIONS.md) + C2 `c383b06` (ReportContext seam + JSON + SARIF generators) + C3 `9b2724e` (WeasyPrint PDF service + pydyf constraint fix) + C3-docs `a50898f` (pydyf VERSIONS.md) + C4 `0d7e5e5` (5 SPEC §6 endpoints) + P5.A-1 `397df21` (docs) + this api entry + the engine cross-ref forthcoming.

**Delivered:** the report pipeline reachable end-to-end (scan → M9 analysis → ReportContext seam → PDF/JSON/SARIF/executive → customer download); reports table + RLS (Gotcha 3); 5 SPEC §6 scan-scoped endpoints; SARIF **2.1.0** jsonschema-conformance-validated; PDF via WeasyPrint lazy-generate → R2 → reports-row (idempotent, generate-or-reuse).

**Mitigations that prevented Drift #67:** V-AA LARGE-classification + decomposition scoped M10.B as a bounded sub-milestone (not the whole milestone); Mode-1 5-gate brainstorming pre-resolved the ~17 locks incl. the two escalation-class items (jsonschema dependency + base-`/report` scope-delta) BEFORE implementation; the V-JJ pre-C cascade caught the **10th averted-prediction** (RLS reaches the test DB via `TENANT_TABLES` + `create_all`, NOT via migrations — without registering `reports` the cross-tenant test would have false-passed) + the **11th** (scan target lives on `Project`, not `Scan`); the pydyf blocker diagnosed to root cause (WeasyPrint 62.3's under-ceilinged `pydyf>=0.10.0` metadata → poetry pulled the API-breaking 0.12.1; latent since before M9 as no render path had exercised it) + fixed via a metadata-grounded pin `>=0.10.0,<0.11`, escalated per Rule 4 not worked around; V-JJH resolved empirically as **not-needed** (report endpoints are all GETs; this codebase audits state changes, not reads). Both dependency escalations VERSIONS.md-locked in-session.

**Two pre-existing auth-route infra-flakes surfaced under load** (rate-limiter IP-counter at C1; `/ready` dep-timeout at C3) — each classified via isolation re-run + orthogonality argument, note-and-proceeded. These are **NOT test-gate-within-lock** (that class is source-under-implementation; C1-C4 source/tests were clean and green) — they are harness timing/isolation fragility. Prioritized forward-pin for a hardening pass so the suite regains a trustworthy clean-green baseline.

**Lineages:** 11-instance averted-prediction lineage (10th TENANT_TABLES dual-mechanism + 11th target-on-Project this sub-milestone); 3-instance test-gate-within-lock pattern NOT incremented at M10.B.

**Forward-pins carried:** auth-route infra-probe test-isolation hardening (2 flakes, prioritized) · full-OASIS SARIF 2.1.0 schema swap → hardening · eager-PDF + unique-constraint `(scan_id, format)` + per-download-deadline expiry → production-readiness · white-label branding → Enterprise · report-endpoint tier-gating → billing · SARIF `application/sarif+json` content-type → if a consumer requires it · SARIF → GitHub Code Scanning upload → Task 12.

⇒ Next per DQ5: ***"Begin M10.C — Compliance Mapping"*** (Task 10.5; 2-table migration + SOC2/ISO-27001 seed; compressed shape per DQ4).

---

### 2026-07-06 — M10.A Sub-Milestone CLOSED (first M10 sub-milestone) — Cumulative Drift Count Preserved at 66

M10.A (Vulnerability Endpoints; Task 10.1) closed its entire lifecycle with **zero catalogue increments** — the first M10 sub-milestone, and the **first C0-less sub-milestone** in the arc (no ADR per DQ2 decomposition lock + no SPEC edit + no migration; VulnerabilityStatus + VulnerabilityHistory tables pre-existed scaffolded-unwired). This is a closure note, **not** a drift entry — Drift #66 (M9.A C1) remains the latest catalogued drift. Docs closure at `a4cca91`; lock-record at `df68e69`.

**M10.A chain (all outcomes γ):** Stage 1 lock-record `df68e69` (10-lock light record per Q10; Mode-2 compressed) + Stage 3 C1 `5cc968a` (routes + schemas + registration) + C2 `0251ee7` (24 tests) + Stage 4 P5.A (`a4cca91` docs + this api entry + the engine cross-ref forthcoming).

**Delivered:** all 7 SPEC §6 vulnerability operations tenancy-enforced (per-scan list + org-wide list + detail + PATCH + /evidence + /fix + /history; ADR-012 cross-tenant-404) + 24 tests (**777 total, ZERO regressions**); **FIRST VulnerabilityHistory write-site** at the PATCH handler (Q5); **ai_fix_text customer-reachable via /fix** — the M9 pipeline's fix output now has a demo-path endpoint; NEW **VulnerabilityAction** audit enum per the per-domain discipline.

**Mitigations that prevented Drift #67:** the entry probe caught the Q1 scope delta (SPEC-canon 7 endpoints vs plan-literal 4) AND the Q2 engine_category/tool_name concrete-field ambiguity BEFORE design (V-UUE catch-class; resolved at lock time, not at implementation); the V-HH pre-C1 cascade resolved V-HHD exactly as pre-grounded (per-domain action-enum discipline → NEW VulnerabilityAction, not a ScanAction stretch; **9th averted-prediction catch**); V-II pre-C2 assertion-grounding on landed C1 artifacts; the RLS GUC seeding catch (Gotcha 12: `other_org_headers` flips the session-local `app.current_org_id`) resolved pre-commit as normal authoring workflow (NOT test-gate-within-lock class; source untouched).

**Lineages:** 9-instance averted-prediction lineage (V-IIB → … → V-HHD VulnerabilityAction); 3-instance test-gate-within-lock pattern NOT incremented at M10.A (no test-gate catches).

**Forward-pins carried:** tool-level engine filter (RawFinding join, on customer need); /fix tier-gating → billing milestone (SPEC §9: AI fix generation ✗ at Free); restricted status-transition graph → on business need; eager-PDF + reports-table territory ahead at M10.B per DQ3 (Y-REPORT-PERSISTENCE).

⇒ Next per DQ5: ***"Begin M10.B — Report Generation + Delivery"*** (ADR-034 territory; Mode-1 full treatment).

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
