# System #001 — Shared due Work Item reader (LOCAL/TEST candidate)

**Repository:** `AnonymousKoo/avuhz-infra`, shared Avuhz Revenue Engine.
**Environment:** LOCAL/TEST only; no Supabase AUTH/DATA write, no hosted
API, n8n activation, communications provider, customer data or production.

## Business capability

This candidate is one read-only step toward preventing lost follow-ups:
an authenticated Avuhz operator can receive sanitized review candidates
for **their currently owned, due Work Items** in the active tenant.
Candidates identify due/overdue or blocked-owner-review decisions.
They are not persisted notifications, scheduled obligations, confirmed
customer contact attempts, or authority to send an email or SMS.

## Authoritative dependencies and isolation

`src/avuhz_service/shared_due_work_reader_candidate.py` reuses
`SharedWorkIntakeCandidate._trusted` and the existing
`work_intake:read` capability, **not** an independently invented
auth path. Its identity and membership resolvers must be server-owned,
independently verified, and bound to real tenant/owner authority; current
hosted identities are not enrolled for this capability.

The existing `PostgresUnitOfWork` binds the trusted tenant to
transaction-local `avuhz.tenant_id`. Readback requires non-login,
non-BYPASSRLS `avuhz_command_service`, row_security=on, FORCE RLS,
exactly one tenant-scoped `avuhz_work_items` policy,
`next_action_due_at` column, SELECT permission and no DELETE grant.
A separate authoritative membership readback must confirm the actor.
The query is parameterized, filters **both tenant_id and current
owner_reference**, and reads a maximum of 100 open/blocked rows with
persisted UTC deadlines at or before the supplied server clock.
It projects no contact details and orders deterministically.

Each row is verified again for tenant, owner, timestamp precision and
shared domain shape, then passed to the existing pure
`review_followup_due` decision function. All reads use transaction
rollback and connection close; even failure cleanup is sanitized.
No new database, workflow runner, billing or tenant-specific adapter.

## Tests and scope limitations

- Ten provider-free unit tests validate capability checks, membership,
  owner/tenant scoping, bounded limits, parameterized SQL shape,
  denial on drift, timestamp precision and safe cleanup.
- Three disposable PostgreSQL 17.6 integration tests exercise the
  actual RLS-bounded read, two isolated tenants, handoff/revoked owner,
  and fail-closed disabled RLS. All were executed with pinned isolated
  Python dependencies and no hosted provider connection.
- The existing comprehensive repository baseline must pass before merge.

**Not yet live:** DEVELOPMENT DATA has not been verified to contain
the Work Item command-idempotency vocabulary or
`next_action_due_at` column; the existing migrations remain separate,
explicitly approval-gated changes. No hosted principal/member resolver,
read API mount, durable scheduler, notifications, booking calendar or
first-client workflow is activated. Missing/invalid membership fails
closed; the query's 100-item bound is **not** a proof that an entire
tenant backlog has been examined.

**Next action:** Review and merge this source-only reader after green
CI and independent security review. Separately authorize one exact
DEVELOPMENT DATA idempotency migration and independently certify
postconditions, then handle the deadline-column migration as another
distinct resource boundary. Only after both and real owner enrollment
should a bounded synthetic hosted due-work journey be attempted.
