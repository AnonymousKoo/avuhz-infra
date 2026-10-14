# Avuhz System #001 Revenue Intake — inactive n8n child candidate v1

**Status:** Repository-only LOCAL/TEST automation candidate. This is a
two-node n8n child workflow, not a connected intake service or a deployed
automation. No hosted n8n, local existing instance, AUTH/DATA, secret,
customer, Cal.com, billing, outbound message or production change.

## Source and intended reuse

The single inactive child workflow at
contracts/templates/n8n/avuhz-system-001-revenue-intake-inactive-v1.json
uses an Execute Workflow Trigger and a Code node, based on the existing
shared Avuhz event/outbox contract. It is NOT connected to the shared
receiver or any sender and is not imported into a retained instance.

The Code node consumes only the eight-field sanitized Avuhz event projection.
It accepts exactly one structurally valid acquisition.intake.received event
with an ACQUISITION_INTAKE reference and version 1. Unknown event types,
ambiguous batches, contact fields, malformed tenant/reference IDs and
version mismatches all produce REVENUE_EVENT_REJECTED without returning
any of the untrusted input.

A valid *shape* produces OWNER_LOOKUP_REQUIRED and bounded opaque
references. This is a non-authoritative planning marker only. It does not
verify tenant/owner permission, assign an actual owner, issue a reply, store
a receipt, send a message, change a Work Item, or run any network/SQL action.
The name OWNER_LOOKUP_REQUIRED is not a claim that a user is authenticated.

## Security/implementation boundaries

Avuhz owns identity, tenant context, governed commands, DATA RLS, domain
records, lifecycle events, outbox and shared billing. n8n orchestrates
only after a separately certified shared event receiver verifies source,
tenant and event allowlists and durably deduplicates the event. No n8n
workflow may directly mutate authoritative Supabase tables or create
an alternate vertical-specific billing/auth/automation stack.

The selected local n8n instance on 127.0.0.1:5678 contains an existing
owner and a credential and is distinct from production n8n.sekinfra.com.
The existing local n8n user lacks a usable password, and there is no
configured SMTP recovery.
Do NOT reset user management, read the encrypted credential, or import into
the existing instance under this source-only change. The existing
Cal.com webhook remains owner-reported OFF and website production release
is held.

This candidate cannot deliver the complete business outcome of no missed
leads until a least-privileged Avuhz API action authoritatively resolves an
owner, follow-up deadline and escalation, persists the obligation, and
approved n8n communication deliveries are proven. No Sekinfra OIA-specific
requirements are introduced into this reusable system.

**Verified offline:** synthetic valid/invalid event tests and the full
Avuhz repository baseline passed; an exact template was imported into a
disposable, no-network n8n 1.103.2 instance, verified inactive and
credential-free, and the disposable database/container was destroyed.
Independent Codex security review passed subject to these documentation
and timestamp-validation corrections.

**Next action:** publish a source-only PR with fresh exact-head tests/review.
Separately authorize local n8n account recovery before installing workflows
into 127.0.0.1:5678; do not execute user-management reset in this PR.
