# System #001 — verified HTTPS boundary for shared unattended n8n delivery

**Source-only LOCAL/TEST scope:** `AnonymousKoo/avuhz-infra`. No runtime deployment, workflow import/activation, public webhook, credential, background daemon, Supabase migration, customer record or provider mutation was made. DEVELOPMENT AUTH `pwlhruwutoitnieactol` and DATA `gnuqaefotwgkwurjpyik` are separate and untouched.

## Grounded current state

- PR #715 merged the tenant-bound `LocalN8nOutboxDispatcher` that automatically polls the existing canonical `OutboxWorker`, with retry and lease semantics owned by the shared outbox and strict PII-free event projection in `N8nOutboxSink`.
- On October 16, 2026, read-only LOCAL n8n preflight confirms the five-node System #001 receipt-gated child exists at loopback HTTP port 5678, **inactive**, with no inbound durable receiver, no bound header credentials and no active local workflow. The shared event receiver source template v1 always returns 503 `RECEIVER_NOT_READY`, deliberately.
- The existing `N8nOutboxSink` accepts an *injected* POST transport but requires a pre-approved HTTPS hostname. It correctly rejects plain HTTP and an arbitrary `127.0.0.1:5678` URL. Therefore attaching the new dispatcher directly to installed n8n with raw HTTP, skipping TLS, using a fake header or turning on the deliberately rejecting receiver would be incorrect.

## What this change adds

`src/avuhz_worker/local_n8n_https_transport.py` defines `LocalN8nHttpsTransport`: a strictly bounded, **dormant** `post(url, headers, body) -> status` callable for the EXISTING sink.

It has no default endpoint or secret. A separately authorized local composition provides an approved hostname, exact TLS 1.2+ client context with hostname and chain verification, and approved timeout. Calling the transport enforces the same canonical HTTPS host and webhook-path policy as the sink, exactly three headers (including the injected credential and delivery key), and the existing eight-field, maximum 4,096-byte event shape. It uses Python's standard-library HTTPSConnection for one POST with no redirects, no automatic retries or cookie/proxy discovery, never reads a response body, and closes the connection after success or failure.

Transport errors are surfaced only through existing `N8nOutboxSink` delivery classifications, without returning exception/credential/PII details. The sink continues to own event validation and tenant scoping; the shared `OutboxWorker` still owns retry, terminal rejection, durable state and idempotence. A successful HTTP response is a delivery acknowledgment, **not** business-owner or Work Item authorization.

This is a building block. **It cannot reach today's installed n8n directly:** the existing `127.0.0.1:5678` HTTP endpoint has no verified HTTPS frontend, active credential-bound receiver or configured durable receipt bridge. Do not activate the current fail-closed receiver.

## Proof

`tests/worker/test_local_n8n_https_transport.py` tests the transport with a mocked HTTPSConnection (NO network), including real shared synthetic acquisition HTTP writer → committed outbox → existing worker → bounded unattended dispatcher → existing n8n sink → eight-field verified-TLS POST, with exactly one emitted request and an authoritative committed intake ID. Separate tests cover HTTPS/host/header/body/TLS fail-closed validation, forbidden redirects, 4xx/429/5xx classifications, connection cleanup and raw-provider-exception suppression.

The test uses generated dummy credentials held only in process memory; none are committed, sent to the network or printed. Passing mocked transport tests is **not** installed n8n certification.

## Required next separately authorized LOCAL boundary

1. Confirm the exact LOCAL n8n instance and the approved, **verified HTTPS** ingress route for the shared receiver, with TLS termination, origin access restrictions and credentials stored in n8n's encrypted credential store / approved Vault (not source/env dumps). No direct plaintext delivery to localhost is permitted as a shortcut.
2. Bind and independently verify the existing native header-auth receiver plus a private, tenant-bound **durable receipt-before-ACK** service. The current v1 source receiver returns 503; it cannot be enabled as-is. Do not grant n8n DATA service-role access or owner authority.
3. Independently confirm a least-privilege, tenant-RLS-bound source connection for the shared worker (using the existing role). Confirm exact namespace, source identity and retry controls before starting a LOCAL process.
4. With fresh owner-approved exact LOCAL/TEST scope, test one fictional intake while the dispatcher is already running: persisted source → autonomous claim → HTTPS → n8n → durable receipt → Work Item. Verify no PII, no duplicates, restored inactive state and audit/cleanup. This is **not yet done**.

No production, live customer onboarding, shared customer communications, booking or billing is enabled. Business-lane OIA and prospect discovery can continue while these integration gates are prepared; engineering work does not itself convert prospects into paying customers.

**Next action:** exact-head repository CI/merge of this source-only HTTPS transport, followed by a separately authorized LOCAL verified-HTTPS receiver composition. Do not reuse the prior single-execution QA approval.
