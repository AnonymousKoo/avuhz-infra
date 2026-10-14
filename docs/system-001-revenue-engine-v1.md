# System #001 — Reusable Lead-to-Client Revenue Engine (delivery contract)

**Status: source-only design and LOCAL/TEST booking-decision candidate.**
This is the intended business outcome, **not** a live booking website, an
activated CRM, an installed calendar integration, a delivered reminder, or
proof of an end-to-end hosted transaction.

## Purpose and separation

**Avuhz System #001** is the shared, configurable revenue workflow: accept
opportunities, establish an accountable owner and next action, request and
confirm appointments, recover from missed follow-ups, record business
conversion, and hand off execution. It composes existing Avuhz identity,
authoritative data, command/idempotency, lifecycle events, outbox, n8n and
shared communications/billing primitives. No separate auth, automation, billing
or data tenancy is permitted for individual verticals.

**Sekinfra** is the first **internal operating user**, not Avuhz's first
external client. Its OIA is an optional Sekinfra consulting step; OIA must not
appear as a universal requirement to book or become a client. Mid-State
remains a prospect, not an onboarded tenant or customer.

## Revenue lifecycle / accountable outcomes

| Stage | Human/business outcome | Actual implementation status |
| --- | --- | --- |
| Capture | Consented prospect request received, uniquely identified, acknowledged | Sekinfra website currently copy/email only; API POST 503/GET NOT_CONNECTED. Avuhz shared acquisition ingress/writer and event/outbox path exist as dormant DEVELOPMENT candidates |
| Own | Authorized operator takes responsibility, due time recorded | Shared Work Item reducer + forced-RLS DEVELOPMENT DATA table exist; hosted command transaction/idempotency is not complete |
| Qualify | Owner records whether and how to proceed | Sekinfra consulting journey and bounded triage exist; generic qualification automation is not activated |
| Request booking | Bounded preferred window and next-action deadline validated; not stored yet | **New LOCAL/TEST provider-neutral booking-preference validator**, not a reservation, hosted intake or persistent work item |
| Confirm booking | Authoritative calendar adapter commits a non-conflicting slot, then shared command records receipt | LOCAL/TEST transition policy only; no verified calendar provider/slot lock/durable adapter |
| Remind/recover | Confirmed appointment reminder, overdue lead alert, no-show recovery | Local follow-up deadline predicate only; no stored obligation, scheduler, delivery, attendance decision or escalation |
| Propose/convert | Agreed offer, verified acceptance, billing evidence as appropriate | Sekinfra-specific proposal/conversion contracts exist; no shared generic proposal-to-billing execution proven |
| Handoff | Client work assigned with owner, versioned lifecycle events | Shared Work Item handoff design/local demonstration exists; hosted atomic command+event+outbox not yet proven |

**No lead falls through the cracks** is a measurable service objective, not a
technical guarantee. Active opportunities must have **one authorized owner,
a state, next action, deadline, and escalation rule**. Report unowned and
overdue opportunities, false confirmations, and lost-ACK retries; ensure a
governed recovery workflow exists for genuine delivery failures.

## Booking domain and safety boundaries

The new `src/avuhz_service/shared_booking_candidate.py` validates only a
strict four-field *untrusted preference*: approved booking-type code, UTC start,
UTC end and a mandatory next-action deadline strictly before the requested
start and within a server-defined maximum follow-up SLA. It rejects caller-
supplied tenant, owner, work-item, role, email, phone, contact content,
calendar credential and confirmation fields. It makes **no authoritative
booking state transition** and has no provider confirmation or no-show
function. A validated preference means **only valid input**, never a
reserved slot, a received lead, or a promised appointment.

A calendar provider must separately enforce **conflict-free, durable slot
reservation**, time-zone conversions, cancellation/release, slot expiry and
webhook signature verification. The shared command service must independently
verify tenant identity, operator authority and Work Item ownership, serialize
changes, persist booking state/version using existing idempotency and publish
sanitized events through its **existing** transactional outbox. None of those
hosted side effects are performed by this module.

The local next-action time predicate is **not** a scheduler, persisted
follow-up obligation, or authorized tenant read model. Authoritative
deadline queries and escalations belong behind shared RLS and command
boundaries and must never expose contact PII. Notifications require consent,
opt-out/suppression, templates, rate limiting, signed provider callbacks,
failed-delivery recovery, and authorized tenant-bound routing.

Do not expose customer contacts, phone numbers, email addresses, calendar
tokens, raw meeting notes or provider webhook bodies in booking events,
business logs, or n8n payloads. Minimize demo-line logs to operational IDs or
at most the last four phone digits where strictly required.

## Reusable configuration, not cloned systems

A vertical selects an approved configuration: lead source mappings,
appointment types and durations, bookable resources, business hours/time zone,
qualification labels, owner routing, response SLA, reminder lead time,
consent/suppression policy, escalation rules, and close/handoff criteria.
Industry-specific templates may change **configuration and domain questions**,
never create new billing, auth, workflow runner, or event infrastructure.
Every deployment uses the shared core and a separately authorized tenant.

## Dependency order / next actionable cuts

1. **PR #673**: fix gate failure and certify shared Work Item command-idempotency source; do not merge until exact-head gate is green. A separate one-time, exact DEVELOPMENT DATA approval is required before the migration.
2. **Acquisition cutover**: satisfy existing authority and DATA grant restrictions; independently verify the actual Sekinfra tenant/owner, AUTH service identity and durable rate limiter. Public website stays fail-closed until signed synthetic end-to-end tests and separate activation approval.
3. **Booking connector selection**: pick an approved calendar integration and implement signed adapter + atomic hold/commit/rollback in Avuhz shared code, with conflict and replay tests. Only then can CONFIRMED mean reserved.
4. **Communications and deadline worker**: use existing event/outbox/n8n; add consent-aware confirmation, reminders, overdue alerts and no-show recovery with durable receipts. No sidecar automation system.
5. **Conversion and handoff**: establish a proposal decision and payment/contract evidence path through existing shared billing (when activated), then use shared Work Item ownership transfer. Keep Sekinfra OIA optional and internal.
6. **Cutover evidence**: one synthetic lead → acknowledged and owner-assigned → calendar-reserved booking → reminder → no-show recovery → proposal/acceptance → work handoff, with denial and retry cases. No actual client records before authorization.

**Next action:** get PR #673 CI green, then review this booking candidate as a
separate source-only PR. The first hosted/live integration remains explicitly
approval-gated.
