# Avuhz shared n8n local receipt bridge — inactive source child v1

**Status:** Repository-only LOCAL/TEST automation candidate. This is not an
activated n8n workflow, public webhook, new datastore, enabled connector,
or permission to act on behalf of any tenant. Its canonical base is
Avuhz main commit 41d51d8e80a4273434d6ad690d9020b96160f4db.

## Scope and evidence

- The single JSON source file
  contracts/templates/n8n/avuhz-shared-local-receipt-bridge-child-inactive-v1.json
  is one **inactive child workflow**, NOT another inbound webhook. Its
  Execute Workflow Trigger passes sanitized data to a shape gate and then
  an HTTP Request node and a **strict durable-receipt response gate**. It is
  not connected to any existing receiver.
- The Code node validates exactly one eight-field
  acquisition.intake.received projection, an ACQUISITION_INTAKE
  reference/version 1, bounded identifiers, valid UTC timestamp (zero to six fractional digits, at most 27
  characters) and no
  extra contact fields. Invalid inputs throw one generic error without
  reflecting any input or logging customer information.
- The outbound HTTP Request requires a separately issued, encrypted
  n8n native Header Auth credential. **No credential is bound.**
  Its placeholder URL is http://127.0.0.1:1/v1/avuhz/local-n8n-receipts.
  This is an intentionally unreachable port INSIDE the n8n container,
  not a verified host Docker gateway or a deployed bridge address.
  Redirects are disabled, timeout is limited to 1000 milliseconds,
  and the HTTP node is configured to expose the full JSON response and status
  to a final Code gate, without considering ordinary HTTP 200/204 success.
  Do not turn the child on or manually execute real data.
- The final Code node accepts ONLY HTTP 202 with the exact JSON receipt
  body {accepted: true, duplicate: boolean}. A valid new receipt produces
  NEW_DURABLE_RECEIPT, and an identical duplicate produces
  DUPLICATE_RECEIPT_NO_EFFECT. Both outputs contain only a constant marker
  and booleans. Every other response (including HTTP 200, 204, 302,
  malformed HTTP 202, extra response fields, storage failures) throws a
  generic error and never echoes backend headers, identifiers or PII.
  **These child markers are not business authority or a webhook ACK.**
- The HTTP JSON body consists only of the validated eight-field projection;
  the X-Avuhz-Delivery-Key header is derived from that bounded key. The
  separately required receipt-bridge authentication token belongs in the
  approved n8n encrypted credential, never in a Git file or Code node.
- The existing atomic LocalN8nReceiptStore and private local-only
  LocalN8nReceiptHTTPServer remain in src/avuhz_worker. Their synthetic
  tests cover durable commit before HTTP 202, duplicate receipts without
  double insertion, same-key conflicts (409), credential/tenant denials
  (401/403), storage failures (503), oversized payloads and safe error
  outputs. **This new child is NOT connected to that server.**
  Its incoming tenant_id is ONLY shape checked; the local server must
  independently enforce a trusted tenant binding and event allowlist.
- Local n8n on 127.0.0.1:5678 has three inactive workflows: an unrelated
  AI Auto Marketing Check, the earlier Avuhz local test receiver, and a
  separately approved imported System #001 candidate. The new child is
  source-only and has NOT been imported. Its owner login is recovered.
  Hosted n8n.sekinfra.com is PRODUCTION and is not in scope.
- DEVELOPMENT AUTH pwlhruwutoitnieactol and DEVELOPMENT DATA
  gnuqaefotwgkwurjpyik must never be conflated. Neither was accessed.
  n8n may not write authoritative Avuhz DATA, authorize owners or tenants,
  charge a customer, or replace the shared Avuhz command service.

## Required proof and independent approvals

1. Verify the exact approved LOCAL Docker network, route, gateway and
   trusted n8n source address. The receipt service must use its existing
   private-address and client-identity gates. Never bind to public internet
   interfaces, invent a production destination, or guess host.docker.internal.
2. Separately approve one resource change at a time: receipt server
   execution, private credential binding, inactive child import and
   wiring to the existing shared Header Auth receiver. No automatic activation.
3. The upstream receiver must authenticate source credentials, reject
   cross-tenant claims and allowlist event types; the local receipt store
   must commit an atomic unique tenant-bound record before any 202 can be
   sent to the Avuhz outbox publisher. This child has no webhook response node and cannot ACK an outbox sender;
   its private marker is not an external acknowledgment or approval to act.
4. Use synthetic n8n integration tests for denied auth, cross-tenant
   attempts, extra PII, replay, collisions, lost acknowledgement, storage
   failure, unapproved tenant, duplicate effects and outbound failures.
   Retain no raw contact PII or authorization headers in execution logs.
5. Only then may another separately approved Avuhz command/API path
   resolve the true System #001 Work Item owner, next action, consent and
   follow-up SLA. Booking, onboarding, operations and retention reuse this
   same shared automation backbone; Sekinfra OIA stays consulting-specific.

## Known gaps

No live bridge URL, credential, installed child, running receipt-bridge server,
or connection to the existing fail-closed receiver is authorized or deployed.
A durable receipt is NOT a durable obligation to perform a later side effect:
a trusted command/outbox service must separately recover failed work after
a receipt commit, including lost-ACK cases and duplicate redelivery.
Successful disposable import proves structural compatibility only, not
runtime service operation, tenant authorization or production readiness.

**Source-only verification completed:** five focused regression tests,
the full Avuhz repository baseline, and an import into disposable,
network-disabled n8n 1.103.2 passed on this template. The imported copy
was confirmed inactive with four nodes, no credentials, a bounded timestamp,
and the exact-202 gate; the disposable container/database were destroyed.
Independent Codex security review passed following corrections to the
response and input-size gates. These results do not constitute a live
bridge or any permission to process real customer data.

**Next action:** Open one source-only pull request and require its exact-head
GitHub gate. Later seek distinct approval for a private receipt-server
runtime and any inactive import into the existing local n8n. Do not
change local n8n or production resources under this PR.
