# Avuhz shared n8n receiver — INACTIVE source template v1

**Classification:** R1 forward-only, LOCAL/TEST automation source artifact.
Imported **only** into a disposable, no-network n8n **1.103.2** instance
for structural validation. That workflow remained inactive, had no credential
binding, and was destroyed with its disposable container/database. It was
**not installed into a retained or hosted n8n instance**, is not certified
for hosted execution, and is not connected to a credential, durable store,
Cal.com, email, billing, DATA, outbox, or prospect-facing website.

## Evidence and boundary

- Canonical repository: `AnonymousKoo/avuhz-infra`; origin main commit
  `de45184b6195b96720623e698b7977e316a1b4f5`.
- `contracts/templates/n8n/avuhz-shared-event-receiver-inactive-v1.json`
  is an **unconfigured source template**, not an installed workflow.
  It uses the node types/versions observed in local Docker n8n **1.103.2**,
  a different resource from the **unverified hosted** n8n instance.
- One POST Webhook node has n8n native `headerAuth` selected **without any
  credential binding**. Only an approved operator can bind encrypted
  n8n Header Auth credentials in a distinct authorized environment.
- A Code node checks an eight-field shape and two initial event names for
  LOCAL/TEST readability, but does not grant authority. **Every path that
  reaches the response node returns 503 `RECEIVER_NOT_READY`.** Authentication
  rejection or execution failures
  can have another non-2xx status; no event can be acknowledged without a
  separately verified durable receipt. No workflow node makes provider calls,
  stores events, sends notifications, mutates tables or produces 2xx responses.
- n8n execution-save settings are disabled in the template to limit sensitive
  retained execution data. Those settings need independent provider-version
  verification before any real customer event.
- The canonical `security/forbidden-path-patterns.txt` still rejects
  `n8n-workflows/` and `.n8n/`. This new, explicitly sanitized
  `contracts/templates/n8n/` source path is NOT a general export/import
  permission. Do not copy legacy JSON here.

## Required to become a real receiver — NOT implemented

1. Confirm the exact **DEVELOPMENT** hosted n8n identity/project, node
   versions, permission scope, URL/TLS and independent AUTH vs DATA mapping.
   AUTH is `pwlhruwutoitnieactol`; DATA is `gnuqaefotwgkwurjpyik`.
2. Review and approve **one** receiver import in an isolated DEVELOPMENT
   namespace, initially INACTIVE, and verify from provider readback that it
   remains INACTIVE. Do not import this template yet.
3. Bind one least-privileged **encrypted** native Header Auth credential,
   never add secrets to Git or to n8n Code nodes; prove anonymous denial.
4. Wire an approved tenant/event allowlist independent of caller claims and
   a **durable atomic** receipt store. Enforce strict schema, delivery key,
   replay/collision semantics, rate limits, exact allowed event types and
   safe errors. Only a committed receipt may return a 202 ACK. No direct
   authoritative Avuhz DATA writes by n8n.
5. Test synthetic acquisition and work-item lifecycle events using existing
   `N8nOutboxSink` and `OutboxWorker`, lost acknowledgements, duplicates,
   cross-tenant denial and storage failure with **real n8n** before any
   separately approved activation. Provider callbacks cannot create tenants,
   grant work ownership, trigger billing or send unconsented messages.
6. Only after the shared receiver works, prepare **one** versioned n8n
   synthetic #001 Revenue Intake workflow and reuse the same infrastructure
   for #002 Booking, #003 Onboarding, #004 Operations, #005 Retention.
   Sekinfra OIA is separate. Preserve owner-reported disabled Cal.com
   webhook and held Sekinfra website production release.

No hosted credentials, production changes, n8n activation or customer records
are authorized by this source change.

**Offline evidence:** a disposable, network-disabled n8n 1.103.2 CLI
import succeeded for exactly one workflow, with `active=false`, native
Header Auth selected, no credential binding, three nodes, and a fixed 503
response. The disposable instance and database were destroyed. This does
not certify hosted n8n or live webhook processing.

**Next action:** obtain confirmed hosted DEVELOPMENT n8n instance/project
inventory and separately scoped approval for exactly one **inactive**
receiver import. No n8n activation or credential binding is authorized.
