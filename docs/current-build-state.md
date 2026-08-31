# Current Build State

`CURRENT_PHASE`: Avuhz/Sekinfra separation certified; Phase 5D-D3 ClientAcceptance is next and has not started.

`CURRENT_HEAD`: `HEAD` (`test: certify avuhz sekinfra separation`)

`CURRENT_BRANCH`: `main`

`LAST_GREEN_MILESTONE`: End-to-end Avuhz/Sekinfra separation certification, including independent runtime and persistence suites plus the provider-neutral Sekinfra -> ImplementationHandoff -> Avuhz -> ImplementationBrief flow.

`COMPLETED`:

- Avuhz active runtime and contracts contain zero Sekinfra/OIA implementation dependencies.
- The active migration directory contains one clean current-tree baseline with 12 provider-neutral Avuhz tables and no extracted-domain tables.
- Historical mixed migration provenance remains recoverable in Git history; repository evidence confirms Phase 5A-5D mixed migrations were local-only and absent from the recorded remote migration history.
- ImplementationHandoff and all completed Phase 5D records preserve exact ID/version/digest bindings, immutable history, bounded optimistic transitions, idempotency, events, and atomic outbox writes.
- Every current authoritative table has command-service tenant RLS; `public`, `anon`, and `authenticated` have no direct table authority.
- Fresh disposable PostgreSQL replay, RLS isolation, bounded grants, exact handoff round-trip, immutable history, idempotency conflict/transition, and atomic rollback certification are green.
- Focused runtime, schema, migration, security, Semgrep, credential, and baseline checks are green.
- Avuhz runs with zero active Sekinfra/OIA runtime references and has no dependency on Sekinfra implementation internals.
- Sekinfra owns and runs OIA independently without importing Avuhz internal modules or requiring a shared database.
- The cross-repository handoff contract is deterministic, versioned, digest-bound, tenant-bound, and green through ImplementationBrief creation.
- Full Avuhz and Sekinfra runtime, contract, migration, persistence, RLS/security, separation, and cross-repository certification suites are green against disposable local PostgreSQL where applicable.

`IN_PROGRESS`: None. Separation certification is complete.

`NEXT_TASK`: Resume Phase 5D-D3 ClientAcceptance runtime and local persistence only, following the frozen Phase 5D architecture and authority boundaries.

`DO_NOT_START_YET`: DeploymentAuthorization runtime, deployment execution, production changes, or later roadmap work.

`KNOWN_DIRTY/PARTIAL_WORK`: None after the separation certification commits. Disposable local PostgreSQL databases are test artifacts only. The ignored local Supabase link metadata is stale read-only inventory context and is not active migration lineage; do not contact it.

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
