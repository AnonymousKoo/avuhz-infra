# Shared Avuhz → n8n authenticated receiver — LOCAL/TEST candidate v1

**Status: repository-only design + synthetic round-trip test, NOT an installed or
activated n8n workflow.** This is a shared Avuhz orchestration adapter, not a
Sekinfra-specific workflow engine. The installed n8n version, node features,
network ingress, credential bindings and durable receipt backend have not been
verified. Do not import the previously uploaded legacy workflows as-is.

## Exact scope and authority

- Repository: `AnonymousKoo/avuhz-infra`, shared automation responsibility.
- Execution: `LOCAL` and `TEST` only; no hosted outbound n8n sink is authorized.
- DEVELOPMENT AUTH is `pwlhruwutoitnieactol`; DEVELOPMENT DATA is
  `gnuqaefotwgkwurjpyik`. This change accesses **neither** project.
- No n8n provider changes, workflow activation, DNS, credentials, database
  migrations, SaaS billing, public intake or production changes.
- Baseline: `src/avuhz_worker/n8n_event_sink.py`, already merged through
  PR #633, emits a minimal Avuhz lifecycle-event notification using injected
  HTTPS transport and encrypted credential provider. It does **not** emit
  acquisition-intake events and does not define an HTTP client.

## Receiver workflow specification (not deployed)

Use one **shared** n8n workflow with the following ordered boundaries once its
DEVELOPMENT destination and provider features have been independently verified.

1. **Webhook**: native n8n Webhook node, POST
   `/webhook/avuhz-events`, configured with n8n **Header Auth** credentials.
   Header name is `X-Avuhz-Webhook-Token`. The secret value must be provisioned
   in **n8n encrypted credentials** and the Avuhz environment-scoped secret
   manager. Never embed a token in a node parameter, URL, workflow export, code,
   fixture or log. The n8n webhook URL is not presumed reachable; verify TLS
   and the exact approved host before binding it. Use the equivalent supported
   authentication mechanism if the installed n8n version differs.
2. **Validate**: reject requests that are not JSON objects, have extra/missing
   properties, exceed the approved 4096-byte JSON envelope, or contain invalid
   types. Require exactly these fields:
   `event_id`, `event_type`, `tenant_id`, `correlation_id`, `occurred_at`,
   `authoritative_subject_reference`, `authoritative_subject_version`,
   `delivery_idempotency_key`. Validate UUIDs and bounded delivery key;
   require the `X-Avuhz-Delivery-Key` header to equal the JSON delivery key.
   Do not accept any proposed authority, payment status, tenant selection,
   customer PII, or raw workflow instructions in the request.
3. **Authorize**: apply a trusted server-configured allowlist of accepted
   tenant/destination and event types. The initial fake receiver permits only
   `engagement.opened`. A caller-provided tenant ID is data, **not**
   authorization. The authenticating header alone is not a license to act on
   other tenants or to accept an unrecognized event.
4. **Durable idempotent receipt**: before acknowledging, persist a receipt in an
   **approved shared automation receipt store** using a unique key comprising
   trusted tenant identity + delivery key. Store only bounded event references,
   correlation, digest and receipt status. A repeat with the same exact event
   must not create another downstream action; the same key with different event
   content is a conflict. n8n Data Tables, PostgreSQL or another product must
   **not** be assumed or provisioned without inventory and explicit approval.
   Never write Avuhz authoritative tables directly or use a service-role key.
5. **Respond to Webhook**: only after the durable receipt commits, return
   `202` for a newly accepted or identical previously accepted delivery. Return
   fail-closed `401` for missing/invalid native auth, `400/403/409` for
   invalid/unauthorized/conflicting messages, `429` under approved rate
   controls, and `503` when receipt storage is unavailable. No `2xx` on an
   in-memory, unverified, or failed receipt. Map errors to safe codes; never
   return upstream payloads, credentials or stack traces.
6. **Downstream routing**: notification receipts are **not authoritative
   business state**. n8n must call Avuhz's governed API for any subsequent
   privileged action with separately issued, least-privileged service
   authorization; it must never assume a signature/receipt permits deployment,
   charges, outbound client communication or ownership changes. Maintain
   event-type allowlisting and customer consent requirements.

## Sender/receiver delivery semantics

- Avuhz already owns retry, backoff, dead-letter, lease and publication state
  through `OutboxWorker`. An unavailable n8n receiver must produce a retryable
  safe outcome; a denied request produces a terminal safe outcome.
- n8n must deduplicate before effects. If receipt was committed but `202`
  was lost in transit, Avuhz retries; the receiver recognizes the same delivery
  key and does not process the event twice.
- Outbound transport must check an explicit approved hostname, certificate,
  block redirects and unsafe destinations, and not log HTTP headers/body.
  The existing sink only **requires** an injected compliant transport; it does
  not implement these deployment controls.

## Evidence / test scope

`tests/integration/test_n8n_authenticated_receiver_round_trip.py` exercises
the merged `N8nOutboxSink` through the existing `OutboxWorker` and an
in-memory **fake** authenticated receiver. It proves only local contract
behavior: minimal PII-free projection; successful publication; retry after a
lost acknowledgement without a duplicate fake receipt; wrong-auth denial;
cross-tenant denial; and semantic collision denial.

It does **not** certify a hosted webhook, n8n's credential handling, durable
provider-side deduplication, any live Avuhz runtime worker, or OIA onboarding.
Run focused unit/integration tests and the canonical `./scripts/check-baseline.sh`
gate before merge. No provider permission is inferred from successful CI.

## Business milestone still outstanding

The Sekinfra public `/api/diagnostic-intake` still intentionally returns
`503 INTAKE_NOT_CONNECTED` for POST. The shared acquisition writer is dormant;
it records an intake **without creating an outbox lifecycle event**. The
canonical lifecycle-event schema currently does not include
`acquisition.intake.received` or `acquisition.qualified`. Therefore even a
working `engagement.opened` → n8n receiver is **not** an end-to-end OIA
qualification pipeline.

The first-client path needs separately scoped and proven: receiving business
authority, server-authenticated website intake, a governed intake/qualification
event, approved durable n8n receiver, consent-based acknowledgment/booking,
and a synthetic website → Avuhz → n8n test before real prospect data.

**Next action:** independently review and merge this LOCAL/TEST contract only
after CI passes. Then choose and approve exactly one n8n DEVELOPMENT receiver
and durable receipt backend for an isolated synthetic deployment test. No
production or live customer intake should be enabled from this document.
