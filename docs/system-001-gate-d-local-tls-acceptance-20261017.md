# System #001 — Gate D LOCAL unattended transport and Work Item acceptance

**Status: source-only acceptance boundary, NOT a deployment or authorization.**
Grounded on October 17, 2026 in `AnonymousKoo/avuhz-infra` main
`93149807c2ed5e3796836da17f72fb7a88034ac4` (PR #737 merged).
Inspected resource: DefNet LOCAL Docker `n8n`, loopback `127.0.0.1:5678`,
existing personal project `axT3GLERZRiPXxnj`. This note modifies no n8n,
credential, running listener, hosted database, service configuration, customer
record, network configuration or provider. DEVELOPMENT Supabase AUTH
`pwlhruwutoitnieactol` and DATA `gnuqaefotwgkwurjpyik` are distinct
and untouched. Production is outside scope.

## What has passed and should not be rebuilt

- Gate C live LOCAL five-node shared receiver `0068feb4c96bdb5f`:
  first fictional POST returned HTTP 202 with exactly one private durable
  receipt; the exact replay returned HTTP 202 while preserving that one row;
  one deliberately invalid header-auth POST returned HTTP 403 with zero new
  executions and the unchanged receipt. The native header-auth credential and
  private receipt credential were unchanged; the workflow remains inactive.
  These are *operator-driven native temporary webhook* tests, not unattended
  service acceptance.
- The separate five-node **System #001 Revenue Intake** child
  `taVvANCjsRXBrChh` and its existing one-shot local certifier are already
  implemented. `scripts/run_system001_local_contiguous_qa.py` read-only
  preflight passed against this installed child on October 17; it makes no
  resource changes unless a new, exact approval permits
  `--execute-local-qa`. Its approved executable path uses an isolated,
  ephemeral, loopback PostgreSQL 17 container, a manual n8n QA parent, a
  synthetic owner and restores the child to its original inactive state.
  It does **not** prove a running unattended dispatch service.
- The shared `OutboxWorker`, `N8nOutboxSink`,
  `LocalN8nOutboxDispatcher`, `LocalN8nHttpsTransport`, and opt-in
  `LocalN8nOnePasswordCredential` already exist. The dispatcher reuses the
  outbox's tenant-scoped claim/lease/retry semantics; none of these modules
  grants n8n authority to issue a Work Item command.
- Focused regression selection on October 17: 45 tests passed, with one
  opt-in disposable-PostgreSQL test skipped because no authorized test
  database was started. Skipped does not count as a live PostgreSQL proof.
- Read-only host listener inspection: loopback port 5678 is listening;
  there is **no** listening socket on LOCAL ports 443 or 8443. No verified
  HTTPS ingress into the existing shared receiver was observed.

## The actual missing link

The existing `N8nOutboxSink` requires a preapproved
`https://<verified-host>/webhook/avuhz-events` endpoint using port 443,
a real DNS hostname, no redirects and a trusted injected credential.
`LocalN8nHttpsTransport` requires a TLS 1.2+ SSL context with chain and
hostname verification. It intentionally rejects plain
`http://127.0.0.1:5678`, `.local`, `.internal`, literal-IP destinations,
non-443 HTTPS ports and the temporary `/webhook-test/` route as its
unattended destination. Do **not** weaken these existing protections or
silently use the temporary Gate C listener as a durable endpoint.

The actual Gate C native receiver is inactive. Its approved encrypted native
header credentials and private receipt backend do not establish a verified
TLS edge, autonomous event producer, real authority-backed acquisition lookup,
or an authenticated business owner. The reusable LOCAL bounded dispatcher is
not currently wired to a persistent tenant-scoped source, a running reviewed
HTTPS n8n ingress, or an approved local service supervisor.

## Gate D acceptance: sequential resource boundaries

All new mutations need fresh exact LOCAL approvals. Confirm the
repository/host, environment, personal project, resource identity, source
digest, and postconditions **before each resource change**. Do not batch
these steps by treating this plan or a green PR as authority.

1. **Read-only ingress design review** — identify an actual operator-controlled
   hostname, its resolution to the authorized restricted LOCAL destination,
   a verified certificate/trust chain, listener process, exposure restrictions,
   and rollback. Determine the exact network resource before proposing its
   creation. There is presently no evidenced hostname, cert or 443 listener.
   An arbitrary public tunnel, DNS name or trusted CA must not be invented.
2. **Separately approve one restricted LOCAL HTTPS ingress resource**, only
   after the exact hostname, DNS/SNI, TLS chain, destination and rollback are
   reviewed. Keep plain n8n 5678 loopback-only. Never expose unauthenticated
   n8n admin or any receipt bridge. Verify the host and TLS identity from the
   intended sender, not only that port 443 accepts TCP.
3. **Separately approve receiver activation only when ready** — reverify
   five-node `0068feb4c96bdb5f`, both existing encrypted credential
   bindings, the private receipt service, allowlisted fictional tenant,
   fail-closed 202-after-durable gate, exact native production webhook
   `/webhook/avuhz-events` and absence of unexpected workflows or routes.
   Native temporary manual listening is not an unattended receiver.
   Do not activate the separate System #001 QA child as a substitute.
4. **Separately approve a restricted source and sender** — use existing
   Avuhz tenant-bound PostgreSQL outbox and `OutboxWorker`, existing
   `N8nOutboxSink`, HTTPS transport, reviewed server-side secret source and
   bounded dispatcher. Prove least-privilege identity, tenant-scoped RLS and
   immutable real-transaction event projection. Do not use
   `service_role`, a hardcoded token, an n8n-owned new queue, or a
   per-vertical automation path.
5. **Separately approve one fictional integrated acceptance run**, after
   the exact private receipt and source boundaries are verified: write the
   fictional intake in an authorized *disposable LOCAL/TEST* source, start
   the bounded dispatcher, then create the event. Show automatic claim and
   HTTPS request **without** an operator invoking the manual QA parent,
   durable HTTP 202 and one exact receipt. A separate Avuhz-owned, independently
   resolved acquisition/strong HUMAN authority check must then invoke the
   existing tenant-RLS Work Item writer; verify one Work Item,
   idempotency/lifecycle/outbox/deadline and guarded owner readback.
   Repeat only through separately authorized idempotency/negative tests;
   prove wrong-tenant, invalid auth, replay and lost ACK fail closed.
6. **Stop and independently reconcile** — stop the bounded runner and
   temporary test services, remove only approved disposable resources, keep
   the original receipt and shared workflow integrity intact, verify no
   unapproved activation, storage, duplicate Work Item, network exposure or
   retained credentials. Record aggregate safe results only. On any
   ambiguous result stop; do not retry or auto-rollback an unknown mutation.

## Acceptance criteria / disqualifiers

Gate D is **not complete** merely because Gate C passed, the one-shot
System #001 certifier passed, a source PR merged, or TLS/health returned 200.
Completion requires *one contiguous observed run*: committed fictional
intake → independently authorized tenant-scoped outbox → unattended existing
shared dispatcher → authenticated verified HTTPS → actual installed shared
n8n native receiver → durable receipt-before-202 → independently
authorized Work Item creation → current-owner and persisted-deadline readback,
plus fail-closed negatives and read-only cleanup evidence.

Even after LOCAL Gate D passes, a real first-client launch additionally
requires independent real-business owner verification, separately authorized
DEVELOPMENT AUTH and DATA boundaries, operator staffing/recovery,
consent-aware communications and explicit hosted activation. Synthetic
identity is never real tenant authority. Shared calendar/billing/notifications
are not proven by this gate; verticals may not create separate auth, billing
or orchestration systems.

**Known blockers, not approvals:** exact LOCAL TLS hostname and certificate
trust route are not established; port 443 is not listening; runtime worker
and real owner lookup are not wired; local dispatcher has not delivered to
the installed n8n receiver. No source or hosted secret should be read merely
to fill these gaps.

**Next action:** review this one-file source-only acceptance record. Then
perform the separately authorized **read-only ingress design inventory**
(hostname, trust, intended loopback target, access policy) and submit exactly
one restricted LOCAL HTTPS ingress resource for approval. Do not start with
activation, real customer data or a second manual-parent QA test.
