# Phase 4 PostgreSQL adapter

`avuhz_runtime.postgres` is an adapter behind the existing repository ports. A caller injects a connection factory; `connection_factory_from_environment` reads only a runtime environment variable and keeps connection details out of source control.

Each Postgres UnitOfWork owns one non-autocommit psycopg connection. Repositories share it, do not commit independently, and the executor rolls it back on bounded failures. The adapter maps handoffs, engagements, scopes, approvals, idempotency, lifecycle events, and outbox intents to the parallel `avuhz_*` tables.

Idempotency uses the table's tenant/principal/command/subject/key uniqueness with `INSERT ... ON CONFLICT`, so concurrent requests cannot reserve twice. Scope updates use tenant and record-version guards. Events append only; the PENDING outbox record is inserted in the same transaction and derives its tenant from the event.

Local integration tests inject the local DSN at execution time and clean only `avuhz_*` tables. The in-memory UnitOfWork remains the unit-test default. No remote Supabase action is part of this adapter; RLS and grants remain Batch C work.
