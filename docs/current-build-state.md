# Current Build State

`CURRENT_PHASE`: Owner-approved non-secret development/staging AUTH/DATA project selections recorded in the canonical environment registry; the baseline remains unconnected and production remains unconfigured.

`CURRENT_HEAD`: `HEAD` (`docs: record owner-approved environment registry`)

`CURRENT_BRANCH`: `main`

`LAST_GREEN_MILESTONE`: Canonical development/staging environment project selection registry recorded without credentials, connection, remote mutation, or production configuration.

`COMPLETED`:

- Avuhz active runtime and contracts contain zero Sekinfra/OIA implementation dependencies.
- The active migration directory contains one clean current-tree baseline with 16 provider-neutral Avuhz tables and no extracted-domain tables.
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
- Deployment authority requires separate attributable CLIENT and PROVIDER human approvals, remains exact to the approved artifact, environment, targets, actions, prohibited actions, and validity window, and cannot be established by workload or payload claims.
- DeploymentAuthorization proposal, activation, revision, revocation, expiry, immutable-history, tenant-RLS, concurrency, idempotency, lifecycle-event, transactional-outbox, restart-durability, and rollback behavior is green against disposable local PostgreSQL.
- DeploymentAuthorization creates authorization only; a separate exact valid authorization is required to start DeploymentExecution.
- D5 freezes distinct DeploymentExecution operation-attempt truth and DeploymentVerification target-state truth; a started or `SUCCEEDED` attempt never establishes verified deployment.
- D5 defines two resources, three commands, three capabilities, three lifecycle events, and two read models with exact authority-chain IDs/versions/digests, immutable attempt history, deterministic outcome derivation, and fail-closed rollback requirements.
- D5 contracts are provider-neutral across roofing/home services, security staffing, and medical-office operations, reject generic success/verification claims and secret-bearing fields, and govern trusted attribution, exact predecessor versions, idempotency, concurrency, event/outbox, and tenant boundaries in the active runtime.
- D5a activates only `StartDeploymentExecution` and `CompleteDeploymentExecution`, the DeploymentExecution resource/read view, repository port, UnitOfWork wiring, and local `avuhz_deployment_executions` table. Attempts remain immutable and operation `SUCCEEDED` leaves `deployment_verified=false`.
- D5a derives `SUCCEEDED`, `FAILED`, `PARTIAL`, or `BLOCKED` solely from exact per-target outcomes and trusted evidence provenance; no caller success field, workload claim, or secret-bearing payload can establish truth.
- Fresh disposable PostgreSQL migration replay, 15-table RLS/policy certification, static persistence checks, focused runtime/history/idempotency/concurrency/atomicity tests, D5 contract validators, Semgrep, credential scanning, and baseline checks are green. The psycopg adapter suite is present but skipped in this interpreter because the pinned dependency is not installed; no remote dependency fetch was attempted.
- D5b activates only `RecordDeploymentVerification`, the DeploymentVerification resource/read view, immutable repository port/UnitOfWork wiring, and local `avuhz_deployment_verifications` table.
- Verification binds the exact terminal DeploymentExecution version/digest and repeated authority chain, covers every authorized target once, validates observed artifact truth and trusted provenance, and derives `VERIFIED`, `FAILED`, `PARTIAL`, or `BLOCKED`; only `VERIFIED` sets `deployment_verified=true`.
- Retests create exact superseding immutable verification attempts. Failed, partial, and blocked history cannot be rewritten, and every non-verified disposition derives `rollback_required=true` without performing rollback.
- Fresh disposable PostgreSQL replay certifies 16 tables, tenant RLS/policies, bounded service grants, immutable verification history, and the existing atomicity/security baseline. The psycopg adapter suite is present but skipped in this interpreter because the pinned dependency is not installed; no remote dependency fetch was attempted.
- The complete frozen D5 execution/verification runtime boundary is active. No provider deployment operation, rollback operation, production change, remote mutation, Phase 6 work, or Avuhz push occurred.
- Phase 5 freeze certification validates the complete ten-record chain from ImplementationHandoff through DeploymentVerification with exact identity/version/digest bindings, schema-valid authoritative records, one tenant/engagement boundary, immutable history, bounded evidence/provenance, and attributable protected human authority.
- The active command registry, migration binding guard, and D5 architecture status are reconciled to the complete D5a/D5b runtime. The provider-neutral migration remains one 16-table local baseline with complete tenant RLS and no extracted-domain tables.
- Full runtime, architecture/separation, cross-repository, Sekinfra boundary/producer, contract, schema, static migration, disposable PostgreSQL replay, atomicity, RLS, Semgrep, credential, forbidden-path, compilation, and diff checks are green. Optional psycopg adapter tests remain skipped because no local driver is installed; no dependency or remote access was attempted.
- Active Avuhz runtime/contract references to Sekinfra/OIA remain zero. Phase 5 is frozen; later work must preserve this baseline and may not infer real deployment or production authority.
- Avuhz platform production is explicitly separate from client-system deployment. The minimum API/worker/data/auth/identity/secrets/migration/observability/backup/CI/CD/environment/rollback architecture and owner-authorized registry are defined in canonical architecture/security documentation.
- Codex/Claude remain untrusted engineering workloads: they may build, test, scan, and draft evidence but cannot approve, merge, select production targets, access production secrets, migrate, deploy, or establish success. The local build/test/evidence portion of the dry run is implemented; connected staging, deployment, verification, and rollback steps remain unimplemented.
- The local service is a real buildable wheel/console artifact with a framework-neutral WSGI application, loopback-only memory composition, one governed command route, nine allowlisted read-only query types, explicit `engagement:read` access, fixed non-human trusted identity, request limits, and sanitized error handling.
- `GET /health/startup`, `/health/live`, and `/health/ready` are bounded and non-sensitive. Readiness checks required local data/identity dependencies, returns `503` on unavailable/exceptional probes, and never returns connection details or stack traces.
- The local outbox worker consumes only existing committed outbox intents, requires tenant-bound `INTERNAL_SERVICE` context plus `event:publish_internal`, and cannot commit domain collections. The fake sink is bounded, local, and idempotent; no provider integration or remote delivery exists.
- Claims use lease tokens, record versions, and PostgreSQL `FOR UPDATE SKIP LOCKED`; failures retain the immutable event, schedule bounded exponential retry, or enter explicit `FAILED_TERMINAL`. Attempt history records worker provenance and timestamps without error messages, responses, credentials, or provider payloads.
- Restart, expired-lease recovery, post-sink commit interruption, concurrent exclusion, idempotent replay, missing-event terminal handling, tenant/trusted-worker denial, schema, migration, and frozen Phase 5 compatibility tests are green. The opt-in PostgreSQL adapter test is present but skipped here because no local DSN or psycopg driver is available.
- The fixed local engineering pipeline builds the unified service/worker wheel offline, runs runtime/service/worker/architecture/engineering tests, frozen Phase 5 contract validators, static/local migration checks, and the canonical security baseline, then verifies embedded package identity and exact artifact digest.
- The canonical evidence schema records only bounded source, tool, command-catalog, check-count, digest, timestamp, artifact, dependency-inventory, review, and readiness facts. It excludes command output, environment values, provider payloads, credentials, and secrets; evidence and artifacts are written once outside Git and made read-only.
- Evidence validation fails closed for missing, expired, source-stale, artifact-stale, command-catalog-stale, internally inconsistent, or secret-bearing records. The review gate binds every required step digest.
- The autonomous dry run requires an explicit simulated reviewer decision. Automation cannot establish human approval, deployment authority, production readiness, or production truth; all production/deployment/mutation flags are permanently false. No deploy path or provider integration exists.
- Platform production remains `NOT_READY`: the locally packaged service/worker artifact is not a certified production deployable and there is still no production AUTH/DATA registry, trusted issuer integration, production outbox identity/provider sink, secret manager/service identities, GitHub workflows/branch/environment protections, protected CI provenance/SBOM publication, observability/alerting, measured capacity/SLOs, approved production migration lineage, backup/PITR RPO/RTO and restore proof, or deployment/rollback rehearsal.
- Development project `pwlhruwutoitnieactol` and staging project `gnuqaefotwgkwurjpyik` are owner-approved non-secret AUTH/DATA selections with the exact `TrustedExecutionContext.tenant_id -> avuhz.tenant_id` bridge. They were not contacted, changed, migrated, or certified.
- Production is unconfigured, its project does not exist, and no remote mutation is authorized. The current PostgreSQL migration baseline remains local/disposable only.


`PLATFORM_PRODUCTION_READINESS`: `NOT_READY`. Architecture and gates are defined; the listed implementation, owner-configuration, staging-evidence, and recovery blockers remain.

`READY_FOR_PHASE6`: `NO`. Resolve and certify platform production-readiness implementation milestones before beginning Phase 6.

`IN_PROGRESS`: None. The environment registry documentation milestone is complete.

`NEXT_TASK`: Define the remaining owner-approved development/staging identity, issuer/audience, RLS, secret-manager, observability, backup/recovery, runtime, artifact-registry, network, and approval-owner references required before connected implementation. Do not connect to or mutate either registered project without separate explicit authorization.

`DO_NOT_START_YET`: Remote event/provider delivery, CI/CD, remote AUTH/DATA configuration, production or client-system deployment, remote migration, production identities/secrets, observability/backup integrations, Phase 6, or later roadmap work.

`KNOWN_DIRTY/PARTIAL_WORK`: None after the environment registry documentation milestone commit. Generated evidence and wheel files remain disposable local artifacts outside the repository. Local Supabase link metadata is read-only historical inventory and is not connection or migration authority; do not contact either registered project.

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
