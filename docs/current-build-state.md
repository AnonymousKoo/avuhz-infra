# Current Build State

`CURRENT_PHASE`: Phase 5D-D4 DeploymentAuthorization runtime and local persistence complete; DeploymentExecution architecture/contracts are next and have not started.

`CURRENT_HEAD`: `HEAD` (`feat: add phase5d deployment authorization runtime`)

`CURRENT_BRANCH`: `main`

`LAST_GREEN_MILESTONE`: Phase 5D-D4 explicit, attributable, versioned, immutable DeploymentAuthorization runtime and local PostgreSQL persistence over exact accepted ClientAcceptance and complete upstream authority-chain bindings.

`COMPLETED`:

- Avuhz active runtime and contracts contain zero Sekinfra/OIA implementation dependencies.
- The active migration directory contains one clean current-tree baseline with 14 provider-neutral Avuhz tables and no extracted-domain tables.
- Historical mixed migration provenance remains recoverable in Git history; repository evidence confirms Phase 5A-5D mixed migrations were local-only and absent from the recorded remote migration history.
- ImplementationHandoff and all completed Phase 5D records preserve exact ID/version/digest bindings, immutable history, bounded optimistic transitions, idempotency, events, and atomic outbox writes.
- Every current authoritative table has command-service tenant RLS; `public`, `anon`, and `authenticated` have no direct table authority.
- Fresh disposable PostgreSQL replay, RLS isolation, bounded grants, exact handoff round-trip, immutable history, idempotency conflict/transition, and atomic rollback certification are green.
- Focused runtime, schema, migration, security, Semgrep, credential, and baseline checks are green.
- Avuhz runs with zero active Sekinfra/OIA runtime references and has no dependency on Sekinfra implementation internals.
- Sekinfra owns and runs OIA independently without importing Avuhz internal modules or requiring a shared database.
- The cross-repository handoff contract is deterministic, versioned, digest-bound, tenant-bound, and green through ImplementationBrief creation.
- Full Avuhz and Sekinfra runtime, contract, migration, persistence, RLS/security, separation, and cross-repository certification suites are green against disposable local PostgreSQL where applicable.
- ClientAcceptance requires trusted `CLIENT_ACCEPTANCE_AUTHORITY` human context, exact upstream identities/versions/digests, and an exact build artifact; workload or payload claims cannot establish acceptance.
- ClientAcceptance decision history is immutable and supersession-explicit, and each accepted command atomically persists the decision, idempotency result, schema-valid lifecycle event, and pending outbox intent.
- Client acceptance creates no DeploymentAuthorization or deployment authority. The D3 runtime, frozen-contract, security, fresh-migration, RLS, restart-durability, history, concurrency, idempotency, and rollback suites are green.
- DeploymentAuthorization requires exact accepted ClientAcceptance, passing QAResult, successful BuildExecutionResult, released CodexBuildPackage, and active ImplementationAuthorization identity/version/digest bindings; no mutable-latest shortcut can establish authority.
- Deployment authority requires separate attributable CLIENT and SEKINFRA human approvals, remains exact to the approved artifact, environment, targets, actions, prohibited actions, and validity window, and cannot be established by workload or payload claims.
- DeploymentAuthorization proposal, activation, revision, revocation, expiry, immutable-history, tenant-RLS, concurrency, idempotency, lifecycle-event, transactional-outbox, restart-durability, and rollback behavior is green against disposable local PostgreSQL.
- DeploymentAuthorization creates authorization only. No DeploymentExecution resource, persistence table, command, production deployment, or remote infrastructure mutation was introduced.

`IN_PROGRESS`: None. Phase 5D-D4 is complete.

`NEXT_TASK`: Define Phase 5D-D5 DeploymentExecution and deployment-verification architecture/contracts only; do not implement runtime or perform deployment.

`DO_NOT_START_YET`: DeploymentExecution runtime, production changes, remote infrastructure mutation, or later roadmap work.

`KNOWN_DIRTY/PARTIAL_WORK`: None after the D4 milestone commit. Disposable local PostgreSQL databases are test artifacts only. The ignored local Supabase link metadata is stale read-only inventory context and is not active migration lineage; do not contact it.

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
