# Shared Receiver v2 — guarded LOCAL native test-webhook send

**Scope confirmation:** repository `AnonymousKoo/avuhz-infra`, DefNet **LOCAL** n8n Docker 1.103.2 bound to loopback `127.0.0.1:5678`, existing inactive shared receiver `0068feb4c96bdb5f`. Shared Avuhz automation only, fictional QA tenant `a4730000-0000-4000-8000-000000000001`. The two DEVELOPMENT Supabase projects (**AUTH** `pwlhruwutoitnieactol`; **DATA** `gnuqaefotwgkwurjpyik`) are distinct and **not touched**. No production, real customer, vertical-specific infrastructure, billing or authorization changes.

## What actual n8n 1.103.2 supports

Read-only source inspection on DefNet verified `/usr/local/lib/node_modules/n8n/dist/webhooks/test-webhooks.js` and `test-webhook-registrations.service.js`. The native **temporary test webhook** mechanism registers a test listener and removes it after an event or a timeout; current version constants specify a 2-minute timeout plus 30-second registration buffer. The CLI `n8n execute --id` cannot inject webhook request body data. Use n8n editor's **Listen for test event** on the existing shared receiver; do not activate the production webhook route or import a synthetic manual parent.

The expected native LOCAL test route is **candidate** `http://127.0.0.1:5678/webhook-test/avuhz-events`. A test listener is **not currently registered or verified**. Do not treat merely finding this route in source as proof that the endpoint is accepting requests. The test route must be observed in the LOCAL n8n UI before a subsequent send. A test-listener registration is a separately approved ephemeral n8n resource change.

## New read-only source gate

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. AVUHZ_ENVIRONMENT=LOCAL \
python3 scripts/prepare_shared_n8n_v2_local_test_webhook_sender.py \
 --target LOCAL_DEVELOPMENT_N8N_5678
```

This verifies exact inactive receiver source, encrypted inbound/outbound n8n credential **metadata references**, protected private receipt service process and endpoint, zero existing QA receipts, the pinned fictional fixture, and event SHA-256. It makes no network request, reads no credential, registers no webhook, starts no listener, changes no workflow, and sends no events.

The candidate synthetic test body is only eight allowlisted event fields: fictional tenant, event ID, correlation ID, canonical event type, QA-only timestamp, acquisition-intake reference, version 1 and an idempotency key. The fixed event's canonical digest is **printed by the read-only preflight**, not a customer credential. It is a transport-only fixture, not a committed authoritative acquisition event or human authorization.

## Future one-POST route: not authorized by merging this PR

An exact new operator approval must identify the merged source commit, `LOCAL_DEVELOPMENT_N8N_5678`, receiver ID `0068feb4c96bdb5f`, canonical receiver source `sha256:fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f`, the exact observed **test-only** URL, the currently verified private receipt endpoint (ephemeral port), and canonical fictional event SHA-256. Approval may permit **one HTTP POST only**, never a replay or activation. A separate exact authorization is required for starting the temporary n8n editor test-listener; this cannot be silently combined with posting the event.

**Critical inbound secret blocker:** n8n stores the inbound `Avuhz Shared Receiver v2 LOCAL inbound header` credential encrypted, but the source repo **does not establish an approved private issuer from which the test sender can read the same token**. Never export/decrypt the n8n credential, create a new token, retrieve private files, paste a token into chat, write it to disk, put it in environment variables/arguments/logs or silently reissue it. The one-event sender accepts that *existing* matching secret only from an **independently approved anonymous inherited file descriptor** (`--token-fd N`); its own code cannot provision or discover the credential. If no matching private source is recoverable, stop, reconcile the credential lifecycle and seek an independent exact credential-rotation authorization.

Once the human n8n test listener and existing matching private sender token source are independently approved, the future opt-in flags are: `--send-one --approved-receiver-id <exact-id> --approved-test-url <exact-test-url> --approved-receipt-endpoint <observed-private-url> --approved-source-sha256 <canonical-sha> --approved-source-commit <reviewed-commit> --approved-event-digest <read-only-digest> --token-fd <private-inherited-fd>` plus standard target. **These flags are not authority by themselves.**

The script rechecks the bound inactive receiver and empty store **twice before consuming the private FD**, performs at most one loopback POST to native `/webhook-test/avuhz-events` with the protected inbound header and exact delivery key, requires an HTTP 202 with exact JSON `{"accepted":true}`, then independently checks one exact tenant/key/event/digest row in owner-only SQLite. No automatic retries on timeouts, failed responses or postcondition ambiguity; even a timed-out POST may have committed a receipt. Only sanitized PASS/BLOCKED output is allowed. The callback does not activate workflows or create DATA Work Items.

The one-post success would establish **only** an actual n8n test-webhook-to-private-durable-receipt path. A persisted receipt alone is not proof of n8n execution; combine the actual HTTP response with receipt evidence. Duplicate/redelivery, invalid auth, cross-tenant, malformed payload and backend-failure tests all need later separately scoped delivery authorizations. Actual Work Item ownership requires authoritative server-owned acquisition lookup, strong owner authentication, current tenant membership and shared command/RLS checks. The fictional QA tenant can never authorize real customer work.

**Security / Infrastructure / Automation / Business:** protects existing encrypted credential and event privacy; reuses one LOCAL n8n/shared receipt service; prepares one controlled native test without an extra vertical runtime; does not substitute for prospect acquisition or real-client onboarding.

**Next action:** merge this source-only PR after exact-head CI passes. Then verify an **approved matching inbound token issuer** (without reading the value or exposing a secret) and separately authorize the brief n8n UI test-listener registration. Only afterward authorize exactly one native test-webhook POST, with read-only postchecks. Keep the private receipt-service terminal running until the test or a separately authorized shutdown.
