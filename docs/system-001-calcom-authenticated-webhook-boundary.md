# System #001 — Cal.com webhook authentication boundary

**Status: repository-local security primitive ONLY.** The existing Cal.com
`cal-booking` subscription was turned off by the user. No Cal.com
credential, event, webhook or setting was read or modified from this repo,
and no provider integration has been activated.

## Existing assets and responsibilities

- Cal.com hosted account already advertises the public Sekinfra event
  `https://cal.com/sekinfra/booking`; the operator states its duration
  was adjusted to 30 minutes (not independently validated from public HTML).
  Cal.com handles availability and booking reservation.
- Sekinfra [website PR #50] is a source-only optional public link guarded by
  `SEKINFRA_CALCOM_DISCOVERY_URL`. It has not been merged or configured on
  production; `/api/diagnostic-intake` must remain fail-closed.
- An older **deleted** `Call Booking Sync` workflow JSON exists outside the
  canonical repository; its unauthenticated webhook and lead/email actions
  are NOT authoritative evidence of the live n8n workflow. Do not restore or
  activate it by default.
- Avuhz core owns tenant identity, shared acquisition ingress, Work Item
  authorization, idempotency, lifecycle events and outbox. Sekinfra OIA is
  consulting-specific, not a reusable booking prerequisite.

## What the new Python code does

`src/avuhz_service/shared_calcom_webhook_signature.py` verifies Cal.com's
documented `X-Cal-Signature-256` HMAC-SHA256 of the **original raw request
body**, with constant-time comparison against secret material supplied
strictly through a future approved secret boundary. It rejects absent or
malformed signatures, altered payloads, weak/missing secret material,
non-byte payloads and oversized bodies.

This module has NO HTTP server, tenant lookup, event parsing, booking-status
decision, database access, contact field, credential storage, webhook
configuration, replay memory, outbox delivery or n8n workflow activation.

Cal.com documentation: https://github.com/calcom/help/blob/main/webhooks.mdx
(check supported signature header encoding against a sanitized provider test
before production cutover).

## Mandatory next gates — not implemented or approved

1. **Confirm target**: exact Avuhz DEVELOPMENT runtime namespace, AUTH
   `pwlhruwutoitnieactol` vs DATA `gnuqaefotwgkwurjpyik`. A merge
   does NOT authorize deployment or provider credentials.
2. **Provision secret** using approved Vault/server secret manager or
   encrypted n8n credentials; never commit to Git, emit to a log or expose to
   the browser. Keep Cal.com webhook OFF until receiver is proven.
3. **Bounded server HTTP ingress**: accept only POST and expected content type,
   cap raw body, reject multiple/invalid signature headers and re-serialization,
   and verify signature before parsing or logging. An authenticated signature
   proves only integrity under a configured key.
4. **Provider binding**: allow only approved subscribed event types; verify
   the server-owned Cal.com event type/account ID and correct authorized tenant.
   Never take `tenant_id`, org, role or owner from a webhook or booking URL.
   Independently reconcile booking UID/state with Cal.com API v2 using a
   server-side least-privileged credential before an authoritative command.
   Do not log or expose booking UIDs or customer details.
5. **Durable replay and ordering**: use existing Avuhz shared idempotency
   records to claim a unique booking event/change in a transaction; handle
   reschedules, cancels, duplicate delivery, out-of-order and failed retries.
   A successful HMAC does NOT prevent replay.
6. **Work Item/communication cutover**: only the shared command service
   can create/transfer tenant-scoped Work Items and lifecycle/outbox entries.
   Run synthetic positive/negative end-to-end tests; verify RLS, operator
   authority, consent, deduplication, no-show handling and sanitized
   notification payloads before n8n activation or sending customer email/SMS.
7. **Fresh separate approvals**: hosted DATA migration, AUTH credential,
   DEVELOPMENT runtime, Cal.com webhook activation, n8n and website
   production deployments each need their own exact approval and
   postcondition checks. Do not bundle under a PR merge.

**Business outcome:** reusable Book → Own → Follow Up → Recover flows,
with Sekinfra as internal proving ground and no new vertical-specific
booking, auth, automation or billing backbone.
