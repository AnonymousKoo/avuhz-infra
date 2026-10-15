# System #001 — minimally scoped acquisition metadata read (source proposal)

**Status:** LOCAL/TEST and DEVELOPMENT DATA *source only*. The SQL is
not authorization to run a provider migration, enable n8n, register a
business, access contact PII, or deploy an owner resolver.

## Verified existing implementation and concrete gap

The current shared Avuhz acquisition intake table has forced tenant
RLS and a policy for the existing avuhz_command_service, but that
runtime role has no SELECT privilege on acquisition columns. The
acquisition **ingress** role has intentionally restricted privileges:
it cannot SELECT intake_state. That restriction is independently
checked by development_acquisition_data.py and MUST remain intact.

The existing LocalSystem001GovernedHandoff requires independent proof
that an acquisition intake is actually RECEIVED before calling the
shared Work Item writer. A durable n8n receipt or intake-event payload
alone cannot confer business ownership. An authoritative acquisition
reader, separate qualified human identity and owner assignment policy
are still missing. The DATA intake record also has no owner Work Item
ID or next-action deadline; neither may be invented from its fields.

## Proposed one-table boundary

One forward-only candidate at
supabase/migrations/20261015193000_grant_shared_acquisition_handoff_metadata_read.sql
grants the *existing* avuhz_command_service SELECT access only to:

- intake_id, tenant_id, organization_id: opaque scope identifiers
- intake_state: authoritative state, not caller-supplied event metadata
- record_version: optimistic version/evidence

No email, phone, contact name, company name, diagnostic text, route,
source system, consent data, receipt payload, billing, or secrets become
visible to the command role. The migration grants no UPDATE/INSERT/DELETE,
table-wide SELECT, new role, credential, policy, owner or tenant.
It does not change the separately constrained ingress role.

SQL fail-closed prerequisites: verified table-owning role, forced RLS,
exact existing tenant policy expression, unprivileged NOLOGIN command
role with no inherited parent membership, and an EXACT two-member role
reachability allowlist: the existing non-login migration role and the
existing private DATA runtime login. Their membership options and the
runtime login's only parent grant from postgres and the migration role's
own only postgres administrator are checked before AND after the grant.
The migration and runtime roles cannot acquire any other parents or
members, and neither can have CREATEROLE/CREATEDB/REPLICATION powers. Browser/JWT roles must never be able to assume the
command role. The migration checks exact columns and no prior command
column grants, no PUBLIC/anon/authenticated column read and no acquisition-ingress
intake_state read. Postconditions
require precisely five direct non-grantable SELECT column ACL entries
for the command role and continued denial of PII and writes.
The candidate runs in one transaction and rejects a repeat.

Disposable PostgreSQL 17 cases and a static contract test verify tenant A cannot read tenant B,
unauthorized direct PII SELECT/UPDATE/DELETE fail, browser-to-command
membership and browser column SELECT are denied, and the separate
ingress role remains unable to read intake_state. Empty tenant context
sees zero records, wrong policy/public grants cause no mutation, replay
is denied, and post-grant errors roll back every new column privilege.
A test fixture creates two entirely fictitious tenants in a disposable
database and deletes the database and its isolated container afterward.

## Execution authority and next business feature

The only future provider target is DEVELOPMENT DATA
gnuqaefotwgkwurjpyik, **never** DEVELOPMENT AUTH
pwlhruwutoitnieactol, production, or a customer dataset. A provider
migration requires a *separate*, exact source SHA-256 and project/
owner-bound approval, plus real schema/ACL postconditions. No such
execution is approved by merging the source PR.

After a separately approved DATA change, implement an Avuhz-owned
tenant-scoped read adapter through the *existing shared* authenticated
PostgresUnitOfWork. Independently verify the authorized tenant, the
intake state, stable version, and owner identity/due-time assignment
policy; only then call the existing Work Item writer.
Do not let n8n, a fake QA membership, or intake text become a trusted
owner identity. Continue LOCAL synthetic tests until a real verified
AUTH owner is explicitly approved for DEVELOPMENT.

**Next action:** finish canonical baseline and independent source review,
submit a single source-only PR, then separately review the DATA grant
execution and trusted acquisition-to-Work Item read adapter. Neither
Mid State nor Yaadbody requires a new auth/billing/automation backbone.
