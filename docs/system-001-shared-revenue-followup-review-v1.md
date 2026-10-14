# System #001 — Shared Revenue Follow-up Review v1

**Status:** LOCAL/TEST source-only business-domain decision. Not a hosted
scheduler, durable follow-up obligation, n8n activation, SMS/email sender,
tenant directory, customer communication, or SLA guarantee.

## Business capability

The new src/avuhz_service/shared_revenue_followup_review.py reuses Avuhz's
existing shared WorkItem model to classify which already-owned work requires
timely action. A trusted caller supplies a bounded tuple of **persisted**
Work Item snapshots with one separately persisted next_action_due_at each.
This repository does NOT yet persist next-action due times.

The pure review classifies:

- FOLLOWUP_DUE: an OPEN Work Item whose action is due but not yet beyond
  the server-owned escalation threshold.
- FOLLOWUP_ESCALATION_REVIEW_REQUIRED: an OPEN Work Item at or beyond the
  configured escalation threshold (15 minutes to seven days).
- BLOCKED_OWNER_REVIEW_REQUIRED: a BLOCKED item with a due time reached,
  signaling review, not unauthorized unblock.
- Future items and RESOLVED items: no review candidates.

Results contain only the opaque Work Item ID, record version, opaque owner
reference, next-action due timestamp, and fixed review code. No tenant ID,
phone, email, name, text, or customer payload is emitted. The caller must
prove the owner is authorized for the actual tenant.

## Security and reliability

The reviewer rejects mismatched/cross-tenants, missing owners, invalid
states, forged versions, duplicate Work Item IDs, malformed UTC times,
a non-UTC trusted clock, invalid source/classification, empty batches and
over 100 observations. It performs no provider calls, database operations,
file access, side effects or workflow activations. trusted_tenant_id,
Work Item/due snapshots and server policy are **caller-injected**, not proof
of actual tenant authority. Never derive them directly from a browser or
untrusted webhook.

Decisions are non-authoritative and MUST NOT cause an n8n send directly.
A later approved shared Avuhz command must:
1. Independently verify identity, tenant, RLS-scoped latest Work Item,
   version, deadline, and eligible owner.
2. Atomically persist the follow-up obligation, idempotency, Work Item
   update, lifecycle event and shared outbox intent.
3. Enforce consent/suppression/provider credentials before communications.
4. Recover lost acknowledgment, replay, delayed workflow execution,
   business-state changes and failed escalations without double sends.

Local n8n on 127.0.0.1:5678 is DEVELOPMENT; n8n.sekinfra.com is
PRODUCTION. Neither is modified. DEVELOPMENT AUTH pwlhruwutoitnieactol
and DATA gnuqaefotwgkwurjpyik remain separate, untouched projects.

## Shared system, not Sekinfra infrastructure

This is one reusable Avuhz Revenue Engine capability for any authorized
tenant. Sekinfra may eventually pilot the same capability, but its OIA,
trade-specific questions, registration or ownership verification do not
block source creation or fictional test coverage.

**Known gap:** Shared Work Item does not yet persist next-action due times.
A pure review cannot create a real customer obligation or prevent lost
leads by itself.

**Source review:** Independent Codex review passed (no HIGH/CRITICAL issue).
Focused tests and the repository baseline passed; exact updated-head tests
will be repeated before PR creation and in GitHub CI.

**Next action:** Submit one source-only PR, then deliver
an authorized persisted Work Item deadline/obligation command through
existing shared transaction/event/outbox before enabling communications.
