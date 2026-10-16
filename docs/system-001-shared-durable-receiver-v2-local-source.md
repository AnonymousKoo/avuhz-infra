# Shared Event Receiver v2 — inactive LOCAL durable-receipt gate

**Resource/environment confirmation:** `AnonymousKoo/avuhz-infra` LOCAL/TEST **repository source only**, 2026-10-16. No installed n8n workflow, permission, credential, public endpoint, owner enrollment, customer data, Supabase migration or external provider resource is touched. DEVELOPMENT AUTH `pwlhruwutoitnieactol` and DATA `gnuqaefotwgkwurjpyik` are different projects and must never be conflated.

## Verified starting point

- The installed LOCAL n8n 5678 System #001 five-node durable-receipt child passed read-only inactive preflight on October 16: zero execution rows, no bound credential, no configured receipt endpoint, no owner lookup and no active workflow.
- The source-only shared receiver v1 at `contracts/templates/n8n/avuhz-shared-event-receiver-inactive-v1.json` is **deliberately a 503 stub** and must stay as historical fail-closed source; it cannot receive accepted traffic.
- The shared receipt store and private authenticated HTTP facade already exist in `src/avuhz_worker/local_n8n_receipt_store.py`, `local_n8n_receipt_http.py` and `local_n8n_receipt_dev_runner.py`. They independently bind tenant, enforce a verified source IP and secret, deduplicate the opaque delivery key, and commit to private local SQLite before acknowledging 202. Their local launch requires separately approved exact resource and token_fd; never put a token into repo, arguments, logs, fixture or terminal output.
- The shared `N8nOutboxSink` and PR #716's verified HTTPS transport remain responsible for TLS, hostname, header credential injection, and the PII-free eight-field outgoing envelope; the bounded dispatcher from PR #715 keeps outbox retry/lease authority outside n8n.

## This source-only receiver candidate

New `contracts/templates/n8n/avuhz-shared-event-receiver-durable-inactive-v2.json` is an **inactive**, unbound five-node shared n8n workflow. It does **not** provide or activate a credential, source the tenant, expose HTTP, or bypass the existing private bridge.

1. **Native n8n Header Auth** webhook, same shared `POST /webhook/avuhz-events` path as the sink; a dedicated environment-scoped encrypted n8n credential must be bound by separate exact LOCAL approval.
2. **Validate and drop untrusted fields:** code checks one inbound item, exactly eight approved event fields, canonical UUID syntax, UTC timestamp, event type `acquisition.intake.received` and authoritative subject `ACQUISITION_INTAKE` version 1, and matches the delivery-key request header. Unknown contact details, full headers, tenant-owner claims and raw metadata never pass downstream. This is a shape check, NOT independent tenant authority.
3. **Private durable receipt request**: inherited approved source shape from the existing receipt child, with second encrypted n8n Header Auth credential and `X-Avuhz-Delivery-Key` forwarded. The URL remains a deliberately unreachable fail-closed `http://127.0.0.1:1/v1/avuhz/local-n8n-receipts` placeholder. Before any LOCAL execution it must be replaced with the exact separately reviewed private gateway/port, with source-network restrictions, and tested before routing a webhook. This private HTTP leg stays on a Docker bridge and uses an independent secret; it must not be made externally routable. The **external Avuhz → n8n** hop still requires verified HTTPS.
4. **Receipt confirmation**: only the exact private backend reply HTTP 202 and `{"accepted":true,"duplicate":boolean}` may advance. A missing backend, invalid credential, redirect, rejection, timeout or 503 cannot pass.
5. **Static 202 ACK** only after the preceding receipt confirmation. Response body contains only `{"accepted":true}`—no PII, tenant ID, request headers, backend body or customer details. Accepted duplicates are harmless; retry/idempotency are still governed by the existing outbox/receipt store.

All execution-save flags remain OFF. No Supabase queries, outgoing customer communications, Work Item writes, billing or owner verification are present in the source n8n workflow.

## What has and has not been proved

Ten focused tests in `tests/worker/test_shared_n8n_durable_receiver_source_v2.py` confirm graph topology, native auth, no credentials/activation, immutable failure gate, shared receipt request exact shape, and fixed ACK. The tests execute the actual Code-node JavaScript in a local Node VM with fictional envelopes and verify invalid shapes, extra fields, bad delivery keys and invalid 200/201/503 backend replies are denied. This does **not** prove the workflow has been imported or executed in the installed local n8n version. A separate, approved LOCAL implementation/test is still required.

**Critically:** a valid inbound `tenant_id` is *never* proof of tenant membership or owner authority. The private receipt server's independent trusted-tenant source checks the value. A committed receipt **does not** authorize a business Work Item write; that requires the existing separate server-owned identity/tenant authorization and writer path. This template alone does **not** make System #001 fully unattended.

## Next separately authorized LOCAL resource steps

- Confirm the exact installed local n8n container/project and existing inactive workflow IDs. Review the approved TLS termination hostname and ingress restrictions before enabling the native shared receiver. Do not enable the v1 503 stub.
- Provide the native webhook credential and independent receipt bridge credential through encrypted n8n credentials only; an owner-approved private receipt service must be bound using the existing token-fd API, explicit trusted tenant and verified Docker source-network boundary. No service-role or direct n8n writes to DATA.
- In a narrow authorized LOCAL/TEST run, install v2 as inactive, verify node/credential/path/posture, then separately approve exactly one fictional authenticated request and activation window. The webhook must respond 202 only for a durable receipt. Verify wrong-token, cross-tenant, duplicate and backend-unavailable behavior, and restore inactive state afterward.
- After receiver evidence, compose the existing dispatcher and restricted DATA source with the server-owned Work Item writer so the receipt results in governed work. Authorize and test *that* distinct resource step separately. A pending receipt is not equivalent to an operational completed Work Item.

No production deployment, real customer, external email/SMS, booking confirmation, or billing is enabled. Continue consented OIA/business discovery in parallel; test readiness is not a substitute for signing a customer.

**Next action:** Review and merge exact-head LOCAL source CI, then request fresh authorization for one exact installed n8n receiver v2 inactive import and private receipt bridge binding (without activation yet).
