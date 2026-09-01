# Phase 4 PostgreSQL adapter

`avuhz_runtime.postgres` is the provider-neutral adapter behind the repository ports. A caller injects a connection factory; connection details remain runtime-only and never enter source, state, logs, or fixtures.

The current local baseline persists generic acquisition and engagement, approved `ImplementationHandoff` history, attributable human approvals, idempotency, lifecycle events, transactional outbox intents, and frozen Phase 5D governance through `DeploymentVerification`. It contains no Sekinfra/OIA persistence and performs no provider deployment operation.

Each PostgreSQL UnitOfWork owns one non-autocommit connection. Repositories share that transaction, expected-version updates are bounded, events append immutably, and the matching `PENDING` outbox intent commits atomically with authoritative state and idempotency completion.

Every authoritative table enables RLS. `avuhz_command_service` is the only application database role with bounded table privileges, and every policy binds `TrustedExecutionContext.tenant_id` through the transaction-local `avuhz.tenant_id` setting. `public`, `anon`, and `authenticated` have no direct authoritative-table privileges.

The migration chain begins with the hardened provider-neutral candidate canonical initial migration and may be extended only by later unique, timestamp-ordered, transaction-enclosed migrations. The initial preflight fails closed on unknown Avuhz schema state and unsafe command-service role attributes; its clean and injected-failure paths are certified against disposable local PostgreSQL. Historical mixed migrations remain recoverable in Git history and are not part of this current canonical chain.

Remote application remains unauthorized by default. Before any future DEVELOPMENT application, a separately authorized read-only target inventory must prove the target is empty of Avuhz state, followed by exact owner authorization for the reviewed migration digest and target. Failed application is transactionally reversible; successful initial-schema removal is destructive and has no standing rollback authority.
