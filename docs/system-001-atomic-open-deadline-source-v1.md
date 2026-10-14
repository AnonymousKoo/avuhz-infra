# System #001 — Atomic initial Work Item deadline on OPEN (source only)

**Environment:** Avuhz shared Revenue Engine, LOCAL/TEST source candidate,
not a hosted intake route, autonomous scheduler, customer-message sender or
approved DEVELOPMENT DATA migration execution.

## Verified source behavior

- Reuses the existing shared WorkIntakeCommand, WorkItem, optimistic
  reducer, authenticated SharedWorkIntakePostgresCandidate,
  PostgresUnitOfWork, shared idempotency ledger, lifecycle event and
  transactional outbox. No vertical-specific auth, billing or n8n
  infrastructure, and no new table or role.
- An existing OPEN command may optionally carry next_action_due_at as
  exactly YYYY-MM-DDTHH:MM:SSZ; invalid calendar dates, offsets,
  fractional seconds and free-text are denied before any SQL.
  Every non-OPEN command must have a null deadline.
- The PostgreSQL writer checks a new OPEN deadline against its
  **server-owned UTC clock**: minimum 1 minute, maximum 30 days after
  command execution, checked against the full-precision trusted time
  rather than the seconds-normalized lifecycle timestamp. It requires the existing shared Work Item table
  to have a nullable timestamptz deadline and column-scoped command
  INSERT privilege. The source-only DATA migration from PR #682 is
  a distinct prerequisite; this PR does NOT apply it to a real project.
- When approved, the writer inserts owner, state, version and deadline
  in the same transaction as a work_intake.opened lifecycle event,
  idempotency record and PENDING outbox delivery. Only sanitized Work
  Item ID and state enter lifecycle event metadata; neither deadline
  nor customer PII enters event metadata or logs.
- For legacy commands with no deadline, fingerprints preserve their
  exact pre-change format. A deadline is added to the request fingerprint
  only when non-null, preventing existing replay receipts from drifting.
  Idempotency fingerprints bind the initial deadline, so reusing a key
  to silently change a deadline is a conflict. An identical replay
  returns the original accepted version without a second work item,
  event or outbox, **even after time has passed**. The initial deadline
  survives subsequent owner/state transitions, because their UPDATE
  statements do not change the deadline column.
- The in-memory LOCAL/TEST reducer represents the optional deadline
  for synthetic tests; it cannot authorize a hosted command, resolve
  real ownership or persist a customer obligation by itself.

## Scope limitation and V1 gaps

This implements only the **initial OPEN deadline**, not changing or
clearing an existing deadline, sending follow-up notifications, booking
meetings, recovering failed n8n executions or proving a real business
owner. The persisted deadline is not yet exposed through a trusted
tenant-scoped read path to the due/overdue reviewer from PR #681.
A nullable deadline is not an SLA: a later policy must decide whether
every inbound lead requires one and who is accountable.
The existing work_intake.opened event vocabulary is reused exactly;
no new event bypass or success assertion is introduced.

Revenue Engine V1 still requires a separate version-checked,
idempotent next-action *update* command with the appropriate lifecycle
event vocabulary and transactional outbox, a trustworthy RLS-scoped
deadline reader, a bounded follow-up worker/dispatcher, consent checks,
booking integration and lost-ACK recovery. Local n8n must remain
inactive until all authorization and reliability tests pass.

## Evidence and next action

The 21 domain tests passed and the final disposable PostgreSQL 17.6
integration suite passed 21/21 after its migration replay test was
corrected to refer explicitly to the idempotency migration rather
than assuming it was last. Tests use fictional tenant and Work Item
IDs, no hosted DATA, no credentials and a destroyed disposable database
and container. The legacy-replay test compares a stored fingerprint byte-for-byte with
the prior algorithm without mutating immutable completed receipts.
Exact/subsecond-boundary tests now pass. The full repository baseline
and Codex remediation review must still pass on the final source.

Provider namespaces: DEVELOPMENT DATA gnuqaefotwgkwurjpyik is distinct
from DEVELOPMENT AUTH pwlhruwutoitnieactol. No provider writes,
real customer data, n8n activation or production actions are in scope.

**Next action:** Pass full baseline and independent review, submit a
source-only PR. Separately approve any exact DATA migration execution,
then implement version-checked rescheduling and trusted deadline reads.
Mid State and Yaadbody are potential clients, not vertical-specific
infrastructure implementation requirements.
