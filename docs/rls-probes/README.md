# RLS probe scripts

One-off demonstration scripts, not tests. They are the evidence behind
ADR-035's five decisions; each is referenced by name there.

Not collected by pytest and not run in CI. They connect to a live
database and create/drop throwaway roles and tables in
`shieldscan_test`. Read one before running it.

| Script | Established |
|---|---|
| rls_pool_probe.py | A committed non-LOCAL SET leaks to the next request on the same pooled connection (D1: connect-as-role over SET ROLE) |
| rls_guc_repr_probe.py | Once touched, clearing the GUC leaves `''` not NULL, and `''::uuid` raises (D2: the NULLIF predicate) |
| rls_reset_probe.py | SET/RESET are themselves transactional, so the reset handler must ROLLBACK first (D3) |
| rls_rebind_probe.py | after_begin re-apply is needed because commit clears SET LOCAL (D4) |
| rls_consumer_probe.py | The GUC survives the AI pipeline's per-vulnerability flush sequence (D4) |
| rls_guard_probe.py | A guard trusting session.info alone can be fooled by drift; intent AND applied AND match is required (D5) |
| rls_coupling_probe.py | The guard is sound without the reset handler, but the handler is what survives the guard being switched off — hence the guard-scoped kill-switch |
| rls_update_delete_probe.py | ORM UPDATE raises StaleDataError with no context; ORM DELETE reports success while deleting nothing (the one silent path) |
