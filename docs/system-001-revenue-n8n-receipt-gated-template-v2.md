# System #001 — reusable n8n Revenue Intake, durable-receipt gate v2

**Status:** LOCAL/TEST SOURCE ONLY, INACTIVE. This file and its matching
workflow JSON are not the finished Revenue Engine and are **not installed**
in the operator's existing localhost n8n. No hosted workflow, AUTH/DATA,
credentials, owner, company, Cal.com, Stripe, communication or client record
is created or changed by this source change.

## Exact resource boundary

- Shared source: `AnonymousKoo/avuhz-infra`.
- Changed automation resource:
  `contracts/templates/n8n/avuhz-system-001-revenue-receipt-gated-inactive-v2.json`.
- Target proof: disposable, network-disabled n8n v1.103.2 and offline Node VM.
- Existing operator LOCAL instance: `http://127.0.0.1:5678`;
  the two-node v1 System #001 child is independently installed **inactive**
  as `zxF2NZWcrtEKqyiG`. The v2 export has not been imported or activated.
- DEVELOPMENT AUTH: `pwlhruwutoitnieactol`.
  DEVELOPMENT DATA: `gnuqaefotwgkwurjpyik`.
  They are never interchangeable. Neither is touched.
- The existing shared receiver remains inactive and returns 503. The existing
  receipt bridge child is not imported or connected. No connection or token
  was silently provisioned.

## What the five connected nodes actually do

1. **From Shared Receiver — UNBOUND.** Execute Workflow Trigger with passthrough
   input, not a public webhook and not a client form.
2. **Validate Shared Acquisition Event.** Reuse the exact existing shared
   receipt-bridge validation code to require one minimal
   `acquisition.intake.received` projection; reject unknown types, malformed
   timestamps, duplicate input items or extra PII.
3. **Shared Durable Receipt Backend — UNCONFIGURED.** Reuse the exact existing
   shared receipt HTTP Request node. POST to the deliberately unreachable
   `http://127.0.0.1:1/v1/avuhz/local-n8n-receipts`, with a native
   encrypted Header Auth **credential requirement but no bound credential**.
   The unconfigured destination is not a live service. No redirects; short
   timeout; no hardcoded secret. Do not replace the URL or bind a credential
   without a separately approved, exact local runtime/network change.
4. **Require Committed Receipt (202 Only).** Reuse the shared exact-202
   confirmation gate; only a minimal `{accepted:true, duplicate:boolean}`
   receipt is accepted. All other responses stop with a generic error.
   It emits only a safe marker with `durable` and `first_delivery`.
5. **Stop at Governed Owner and Work Item Boundary.** Identical replay
   terminates with **no output** and no next stage. A first durable receipt
   returns only `OWNER_LOOKUP_REQUIRED` with explicit booleans that no Work
   Item, deadline, follow-up or notification has been committed. Malformed or
   forged receipt markers fail closed. This is a request for the *existing
   Avuhz shared command* boundary, **not** authorization or assignment.

In particular, there is **no outgoing HTTP command** to invent an unsupported
owner-lookup endpoint, no direct Supabase SQL in n8n and no email/SMS provider
effect. The receipt store itself is not a durable work queue for a subsequent
side effect. Do not equate receipt acknowledgement with completed processing.

## What a complete System #001 still requires

| Step | Current authority / source | Blocking runtime work |
| --- | --- | --- |
| 1. Consent-based acquisition | Shared `development_acquisition_ingress.py` and `acquisition_intake_command.py` source; Sekinfra website fails closed | Real verified tenant/owner, dedicated service identity and approved intake mount |
| 2. Authoritative lifecycle/outbox | Installed DEVELOPMENT DATA lifecycle/outbox and idempotency schema | Hosted command service revision and shared authenticated execution proof |
| 3. n8n durable receipt | `local_n8n_receipt_store.py` and this v2 source | Restricted, real receipt service and encrypted credential binding; independently approved workflow wiring |
| 4. Owner + deadline | `SharedWorkIntakePostgresCandidate` in `shared_work_intake_postgres_candidate.py`, local synthetic PG proof | Server-side verified tenant/member/owner resolution and an approved API handler; no such hosted route in current code |
| 5. Due-work review + escalation | `SharedDueWorkReadCandidate`, `review_followup_due`, canonical DATA deadline column | Authenticated scheduled adapter, durable obligation/retry semantics and review ownership |
| 6. Contact and booking | Shared provider-neutral booking candidate; old Cal.com integration is not certified | Consent/suppression, delivery receipts, customer-specific routing, approved Cal.com verification, no duplicate sends |
| 7. Operator outcomes | Avuhz events/outbox and separate private Command Center source | Authenticated owner/tenant activity read model, deployment and runtime telemetry verification |

**Definition of complete:** a consented, authorized customer request creates a
real tenant-bound Work Item with correct owner/deadline; repeats do not create
duplicates; shared n8n receives an authenticated committed event; owner is
notified by an approved communication channel; follow-up/escalation is durable;
the operator can observe the outcome; all denial/failure paths recover safely.

## Reusable template policy

This is **one shared Avuhz automation** reused by business verticals.
Sekinfra OIA, HVAC, roofing, VerifiedPost, mortgage or other tenants may supply
only domain configuration and permitted content; no vertical-specific billing,
auth or orchestration stack. Shared AUTH, DATA/RLS, n8n and eventual Stripe
billing remain single core service boundaries.

The remaining template families from actual legacy reconciliation are
#002 Booking, #003 Client Onboarding, #004 Work & Operations and #005
Customer Retention. These are business-intent classifications, **not claimed
implemented n8n flows**. Complete and certify System #001's shared command
and receipt boundaries first; then reuse those proven primitives for the
other system templates, one resource at a time.

## Test and import evidence

- Focused offline tests exercise the real Code node source in a Node VM:
  new receipt, duplicate stop, invalid event/PII, forged marker, unsafe HTTP
  response, exact shared-contract reuse, single bounded outbound placeholder.
- Imported the v2 export successfully into a **disposable network-disabled**
  n8n 1.103.2 container with an ephemeral data directory; no changes to the
  retained operator's n8n container/database.
- Confirm code is inactive, has no pinned execution data, no credentials, no
  public webhook or network-send node other than the unreachable localhost:1
  receipt boundary.
- Full repo baseline and GitHub PR gate are separate required checks.

**Next action:** after merge, design and locally certify the **existing shared
Avuhz owner-resolution/Work Item command adapter** with a real restricted
LOCAL/TEST HTTP contract. Do not activate the new child or create customer
records until that adapter, tenant authority, and durable retry semantics are
proven. A separate exact permission is required even for importing v2 into
the operator's retained LOCAL n8n instance.
