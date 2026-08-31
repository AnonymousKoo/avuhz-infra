# Current Build State

`CURRENT_PHASE`: Architecture correction and Sekinfra extraction; full separation certification pending.

`CURRENT_HEAD`: `HEAD` (`refactor: rebaseline provider-neutral avuhz persistence`)

`CURRENT_BRANCH`: `main`

`LAST_GREEN_MILESTONE`: Avuhz local persistence and migrations rebaselined to the provider-neutral current tree while preserving generic PostgreSQL/UnitOfWork infrastructure, command-service RLS, tenant isolation, idempotency, concurrency, lifecycle events, transactional outbox, ImplementationHandoff, and Phase 5D governance through QAResult.

`COMPLETED`:

- Avuhz active runtime and contracts contain zero Sekinfra/OIA implementation dependencies.
- The active migration directory contains one clean current-tree baseline with 12 provider-neutral Avuhz tables and no extracted-domain tables.
- Historical mixed migration provenance remains recoverable in Git history; repository evidence confirms Phase 5A-5D mixed migrations were local-only and absent from the recorded remote migration history.
- ImplementationHandoff and all completed Phase 5D records preserve exact ID/version/digest bindings, immutable history, bounded optimistic transitions, idempotency, events, and atomic outbox writes.
- Every current authoritative table has command-service tenant RLS; `public`, `anon`, and `authenticated` have no direct table authority.
- Fresh disposable PostgreSQL replay, RLS isolation, bounded grants, exact handoff round-trip, immutable history, idempotency conflict/transition, and atomic rollback certification are green.
- Focused runtime, schema, migration, security, Semgrep, credential, and baseline checks are green. Python adapter integration tests remain cleanly skipped because no psycopg driver is installed; live Docker/psql certification covers the database baseline.

`IN_PROGRESS`: None. The local persistence/migration rebaseline milestone is complete.

`NEXT_TASK`: Certify Avuhz/Sekinfra separation end to end using independent repository suites and the cross-repository ImplementationHandoff flow; do not resume Phase 5D-D3 ClientAcceptance until separation is certified.

`DO_NOT_START_YET`: Phase 5D-D3 ClientAcceptance, DeploymentAuthorization runtime, deployment execution, production changes, or later roadmap work.

`KNOWN_DIRTY/PARTIAL_WORK`: None after the persistence rebaseline commit. The ignored local Supabase link metadata is stale read-only inventory context and is not active migration lineage; do not contact it.

`REMOTE_AUTHORIZATION`: No Avuhz push. No remote Supabase or other infrastructure mutation. Any later Sekinfra feature-branch push requires explicit current authorization and green certification; never force push.

`RECOVERY_RULE`: `INSPECT -> PRESERVE -> COMPLETE -> VALIDATE -> COMMIT`. Never destroy valid interrupted work.

## FUTURE_AGENT_WORKFLOW

1. Read the canonical agent rules.
2. Read `CURRENT_BUILD_STATE`.
3. Read architecture and security only when `NEXT_TASK` requires them.
4. Complete `NEXT_TASK` only.
5. Run focused tests.
6. Update `CURRENT_BUILD_STATE`.
7. Commit only the completed milestone if green.
8. Do not push unless explicitly authorized.
9. Stop after the milestone.
