# System #001 — Offline Prospect Walkthrough

This is a **LOCAL/TEST-only** operational proof, not an activated hosted
integration, production service, customer account, or durable database.
It reuses Avuhz's existing shared work-intake reducer, event schema,
outbox worker and n8n sink contract. The injected transport captures
an event notification locally; **no webhook call occurs**.

## Run from repository root

```bash
python3 scripts/demo_system_001_offline.py
python3 scripts/demo_system_001_offline.py --json
```

This shows a synthetic service request moving from OPEN through offered and
accepted ownership handoff, BLOCKED, RESUMED and RESOLVED. It checks denial of
cross-tenant and former-owner reads and suppression of a repeated command's
event. Six schema-valid local events are staged in an in-memory test outbox;
the existing worker publishes six to a stub, then publishes zero more on
a second **idle** invocation because the rows were already marked PUBLISHED.
This does not establish exactly-once delivery or consumer deduplication:
at-least-once workers may redeliver after a crash before the published mark.

## Safe way to present

"The work lifecycle and security controls have a working offline prototype.
We are demonstrating the workflow design, **not claiming your data or
systems are connected**. Before any live use, we would agree the exact
assessment scope and validate the secure hosted integration."

Do not imply that Mid-State is a customer, has a tenant, approved OIA access,
or supplied customer data. Do not collect or paste prospect records into
this demonstration.

## What this does not establish

- A hosted work-item table installation or an atomic authoritative
  work-item/event/outbox commit.
- Real Supabase owner registration or tenant authorization.
- A hosted n8n receipt, enabled workflow or external communications provider.
- Production readiness, onboarding authority, implementation approval or
  a completed customer assessment.

For the hosted Work Item table, obtain a **fresh exact DEVELOPMENT DATA**
approval naming the current main commit and wrapper SHA before any migration.
The next Work Item command-idempotency vocabulary is a separate gate.
