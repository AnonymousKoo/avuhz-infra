# System #001 — governed LOCAL receipt-to-Work Item handoff

**Confirmed source scope:** `AnonymousKoo/avuhz-infra` LOCAL/TEST only.
Existing local DefNet n8n `127.0.0.1:5678`, its four stored
workflows (zero active, zero executions), and the installed System #001
v2 child remain unmodified and inactive. This change has **no** new
localhost listener or installed n8n execution path.

Supabase DEVELOPMENT **AUTH** `pwlhruwutoitnieactol` and separate
**DATA** `gnuqaefotwgkwurjpyik` are not touched. Neither is a
source of trusted identity for these synthetic tests. No production,
billing, hosted data, real customer, token or n8n credential is modified.

## Actual code

- `LocalN8nReceiptStore.committed(...)` performs a strictly read-only
  equality check of the full, allowlisted event-envelope digest against
  the preexisting PRIVATE SQLite durable receipt store. It reuses the
  same rigorous tenant/type/header/size validation as `receive`.
  Missing, mismatched, unauthorized or modified receipts fail closed
  before any owner lookup. It never inserts a missing receipt.
- `LocalSystem001GovernedHandoff` is a LOCAL/TEST-only, unmounted
  orchestration adapter in the **shared Avuhz worker**, not an n8n
  authorization system or per-vertical infrastructure. It accepts an
  already committed `acquisition.intake.received` envelope only.
- A **server-owned, independently provisioned acquisition lookup**
  receives only the opaque intake UUID and must read a trusted
  tenant-bound, RECEIVED intake record; it must not echo an n8n payload
  or client-submitted authority. It provides stable Work Item UUID,
  source/classification, deadline and owner identity *evidence*.
- A second **independent server-owned human identity resolver** must
  return fresh STRONG authenticated Avuhz HUMAN context with
  `work_intake:create` and the **same exact tenant** as the
  independently resolved acquisition record. This precheck is crucial:
  an otherwise-valid owner of a different tenant must not be permitted
  to cause the writer to create a Work Item in their own tenant.
- Finally the existing `SharedWorkIntakePostgresCandidate.execute`
  independently checks identity again, *current* membership, the
  bounded `avuhz_command_service` PostgreSQL role, forced tenant RLS,
  persisted row state and shared idempotency/lifecycle/outbox
  transaction. Deterministic receipt/intake-derived idempotency
  prevents duplicate Work Items after a replay.
- No payload phone number, email, arbitrary tenant/owner, raw
  acquisition body, session or token is copied into Work Item events.
  No messages are sent and no follow-up scheduler is started.

**Security design:** A durable n8n transport receipt proves neither
business ownership nor Work Item authority. The handoff stops unless
both independently verified *acquisition* and *strong human owner*
binding match the receipt's tenant; the real writer retains the final
authorization decision. This is source-only and the independent
lookup/resolver are synthetic TEST callbacks: no hosted uses are
registered or authorized by these tests.

## Verification evidence

- Existing local receipt / outbox / authenticated loopback HTTP
  regression tests, including tampering, missing receipt, wrong
  credential, cross-tenant, retry, collision, and disk failure.
- New unit tests for non-writing receipt proof, missing and tampered
  event, independent acquisition mismatch, cross-tenant HUMAN owner,
  revoked/missing writer permission and safely sanitized lookup errors.
- New disposable PostgreSQL 17 integration proof: signed local receipt
  store + independently verified intake and HUMAN identity +
  **real PostgreSQL Work Item writer**. It proves wrong-tenant owner
  denial, exactly one durable Work Item, idempotency receipt,
  lifecycle event and outbox entry, persisted deadline, correct
  owner/tenant and isolated due-review readback.
- The local tests intentionally use fictional tenant UUIDs and
  explicitly synthetic authentication. These are not customer
  onboarding or AUTH/DATA enrollment evidence.

## Unmet operational and provider gates

1. The actual installed n8n v2 child is inactive, has a deliberately
   unreachable receipt node and an unbound input; **zero real n8n
   executions** are on record. The new adapter isn't wired to n8n.
2. A real *server-controlled authoritative acquisition lookup* and
   separate AUTH-backed STRONG HUMAN owner resolver are **not
   implemented/deployed**. The synthetic callbacks cannot confer
   hosted authorization. Work Item association may not be inferred
   from a receipt, nor may n8n command the shared writer directly.
3. The receipt server launcher remains preflight-only. Starting
   `--serve`, registering an n8n encrypted credential and making a
   one-event LOCAL invocation require their own exact resource
   verification and approval. Do not expose local port 5678.
4. A DEVELOPMENT DATA QA tenant needs an explicit reversible,
   RLS-scoped, **never verified-by-fiction** seed procedure; no
   hosted DATA write has occurred. This adapter does not create one.
5. End-to-end System #001 certification will require an actual
   installed n8n execution with durable transaction, independent
   authorized owner binding, due review, and negative replay/tenant
   evidence, not these partial source/PG proofs alone.

**Next action:** review and merge this LOCAL-only source PR after
the repository gate passes. Then implement and certify the
authoritative acquisition + identity resolver as a bounded LOCAL
proof before approving one n8n inactive-workflow binding change or
start of the private receipt backend.
