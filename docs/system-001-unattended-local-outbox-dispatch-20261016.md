# System #001 — shared unattended LOCAL/TEST outbox dispatch loop

**Source-only change; not a service activation.** Scope: `AnonymousKoo/avuhz-infra`, LOCAL/TEST shared worker. Hosted Supabase AUTH `pwlhruwutoitnieactol` is distinct from DATA `gnuqaefotwgkwurjpyik`. Neither project, the installed local n8n instance on loopback `127.0.0.1:5678`, any credential, real customer or production resource is changed or contacted by this implementation/test run.

## Why it exists

The October 16 authorized LOCAL System #001 certification passed a connected fictional acquisition/outbox → **real local n8n** → private durable receipt → disposable PostgreSQL Work Item, due-review and handoff journey. However, the certification **used exactly one manually invoked n8n QA parent**. No independently running shared outbox polling worker exists yet, and the installed source child is deliberately **inactive**.

This addition introduces `src/avuhz_worker/local_unattended_n8n_dispatch.py`, a small bounded loop over **the existing** `OutboxWorker.run_once()`. It provides repeatable autonomous polling within a LOCAL process, rather than recreating authentication, queue storage, retry policy, tenant isolation, billing, event envelopes, or n8n workflows.

## Exact shared-core responsibilities

- **OutboxWorker owns** tenant-scoped database claims, leases, retry-after timestamps, idempotency and terminal failure. It checks a trusted INTERNAL_SERVICE identity with `event:publish_internal` before each cycle.
- **N8nOutboxSink owns** schema validation, HTTPS destination restrictions, transport/auth injection, and projection to eight PII-free lifecycle event fields. An n8n acknowledgment/receipt does *not* grant access to a tenant, owner, Work Item or API command.
- **LocalN8nOutboxDispatcher owns only cadence**: polls at 1–300-second intervals, repeatedly up to an explicit maximum of 1–17,280 cycles, wakes on a thread-safe stop Event, and returns fixed aggregate counters. It rejects a hosted context, a mismatched tenant or non-n8n sink, and refuses unexpected worker errors instead of hiding them with an infinite retry loop.
- The loop does not create a new event ledger, hold credentials, open an HTTP listener, instantiate a database connection, create an n8n workflow, authorize owner proof, or start a background process. A future authorized process supervisor may wire the canonical tenant-bound PostgreSQL store and a reviewed TLS/no-redirect n8n transport to this **same** shared worker. The currently installed inactive n8n child has no ready listener. This addition does not secretly activate it.

## Evidence

Offline tests under `tests/worker/test_local_unattended_n8n_dispatch.py` exercise the actual shared synthetic acquisition WSGI/writer event, existing outbox worker, and existing n8n sink with an in-memory receiver. They prove:

- A fictional acquisition *arriving after* the unattended polling loop has started is delivered automatically without an operator calling a worker cycle.
- A lost receiver acknowledgment is retried only after the outbox's stored backoff, and the receiver retains exactly one receipt.
- Invalid receiver credentials terminate delivery without retries or impersonated owner authority.
- Stop requests, tenant mismatch, hosted execution, wrong sink, invalid limits and unexpected worker exceptions fail closed; logs/summary contain aggregate counters only.
- Only sanitized, eight-field event data reaches the injected receiver; no names, email, diagnostic description, secret or raw metadata are forwarded.

The opt-in `tests/integration/test_local_unattended_n8n_dispatch_postgres.py` uses a **disposable local PostgreSQL 17 schema** and the existing tenant-RLS-scoped PostgresStore/UnitOfWork with the same n8n sink, but a fake in-memory receiving transport. It is skipped without an explicit disposable-DB DSN. **Skipping is not a certification**. It does not connect to installed n8n or hosted AUTH/DATA.

## Remaining gap to genuinely unattended installed LOCAL n8n

1. An approved running receiver/bridge and n8n HTTPS transport/credential binding. Today the installed n8n child is **inactive**; the sink has no built-in network transport on purpose.
2. An authorized, persistent, tenant-bound real source data connection under the existing restricted DATA role. Synthetic local HTTP events and mock owners cannot act as live owner verification.
3. An independently authorized runner/supervisor configuration (lifecycle, startup, shutdown, health, restart/backoff and private receipt durability), plus real n8n receipt and PostgreSQL acceptance evidence. **Do not** use CLI manual-parent execution as a substitute for this.
4. Separately reviewed durable due/escalation *actions* and shared communication/booking adapters. A due-review observation alone never sends a customer notification. Shared Stripe billing remains a separate core feature.

No tenant enrollment, company/brand owner proof, or paid pilot is established here.

## Next action

Merge the scoped source once exact-head CI and disposable-PG opt-in checks pass; next **independently approve LOCAL receiver/dispatcher composition**, using the existing n8n and a restricted isolated QA database. Do not activate workflows or register customers until the exact resource and environment are confirmed. Continue OIA/discovery and consented sales conversations in parallel—more automation work is not itself a paying customer.
