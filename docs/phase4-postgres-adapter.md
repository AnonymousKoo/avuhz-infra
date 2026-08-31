# Phase 4 PostgreSQL adapter

`avuhz_runtime.postgres` is the provider-neutral adapter behind the repository ports. A caller injects a connection factory; connection details remain runtime-only and never enter source, state, logs, or fixtures.

The current local baseline persists generic acquisition and engagement, approved `ImplementationHandoff` history, attributable human approvals, idempotency, lifecycle events, transactional outbox intents, and completed Phase 5D governance through `ClientAcceptance`. It contains no Sekinfra/OIA persistence and no `DeploymentAuthorization` runtime.

Each PostgreSQL UnitOfWork owns one non-autocommit connection. Repositories share that transaction, expected-version updates are bounded, events append immutably, and the matching `PENDING` outbox intent commits atomically with authoritative state and idempotency completion.

Every authoritative table enables RLS. `avuhz_command_service` is the only application database role with bounded table privileges, and every policy binds `TrustedExecutionContext.tenant_id` through the transaction-local `avuhz.tenant_id` setting. `public`, `anon`, and `authenticated` have no direct authoritative-table privileges.

The migration chain is a clean current-tree baseline for disposable local PostgreSQL only. Historical mixed migrations remain recoverable in Git history and must never be pushed blindly or treated as remote migration lineage.
