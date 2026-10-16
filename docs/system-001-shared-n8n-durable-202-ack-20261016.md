# System #001 LOCAL — strict shared n8n durable-202 acknowledgment

**Verified boundary:** Avuhz shared source repo `AnonymousKoo/avuhz-infra`, LOCAL/TEST; source-only \`N8nOutboxSink\` + unit/integration tests + documentation. No hosted AUTH (`pwlhruwutoitnieactol`), hosted DATA (`gnuqaefotwgkwurjpyik`), production, local n8n credential or workflow, endpoint, listener, owner or customer resource changed.

## Existing contract and detected gap

The installed LOCAL shared receiver v2 template is **inactive**, native Header Auth unbound, with a deliberately unreachable private receipt URL until separately approved. Its graph can only return HTTP 202 **after** its private receipt gate confirms status 202 and an accepted/duplicate receipt; the private receipt store independently constrains the trusted tenant and commits the idempotent receipt before acknowledgment.

Before this source change, the outbound `src/avuhz_worker/n8n_event_sink.py` accepted HTTP **200, 201, 202 and 204** as `PUBLISHED`. That was inconsistent with the receiver's durable-202 contract: a reverse proxy, default n8n response or intermediary returning another 2xx could falsely promote a work event to delivered even with no committed receipt.

## Small shared-core correction

- `N8nOutboxSink` now marks `PUBLISHED` **only** after exact HTTP 202. A 202 is necessary, not sufficient, for end-to-end proof: the **trusted configured** n8n receiver and independent durable receipt gate must still enforce their contract; no raw 202 from an unverified arbitrary endpoint is owner authority.
- Other 2xx responses (200/201/204/206/207/etc.) are `DeliveryUnavailable` with a static safe error, never `PUBLISHED`. The existing `OutboxWorker` owns the persisted retry/lease/attempt limits and eventual dead-letter; there is **no** new queue or alternate orchestration/authorization path.
- HTTP 429 and 5xx remain temporarily unavailable, and 4xx remain terminal rejections. The existing HTTPS hostname restrictions, PII-stripped event projection and tenant scope remain unchanged.
- New tests prove 200 -> recorded retry -> a later 202 is published only after the outbox backoff, and repeated 204 -> terminal failure without a false success or infinite loop. The original callback and fake transport remain source-only.

## Current V1 status and next action

PR #719 (native receiver Header Auth credential gate) merged and the installed shared receiver remains **inactive/unbound**, as observed at the start of this patch. The local private Docker receipt HTTP tests passed in an earlier step, but the installed receiver is not continuously running.

A real, approved LOCAL shared-secret source accessible to both Avuhz's sender and n8n still must be verified before provisioning one encrypted credential; the operator must separately approve exact credential registration, workflow binding, private receipt service, verified HTTPS ingress and one fictional unattended acceptance run. No real business or provider data should be sent under this patch. Keep OIA/prospect discovery parallel to automation completion.

**Next action:** review exact-head CI and merge this single shared sink safety correction; then resolve the two-sided LOCAL secret source + trusted TLS receiver boundary before performing any provider mutation.
