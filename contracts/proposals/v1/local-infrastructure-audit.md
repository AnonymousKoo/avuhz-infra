# Infrastructure authority LOCAL v1 milestone 3B

R2, shared Avuhz runtime, synthetic LOCAL/TEST source candidate. The complete
change is additive and limited to:

- `src/avuhz_runtime/local_infrastructure_audit.py`
- `tests/architecture/test_local_infrastructure_audit_v1.py`
- `contracts/proposals/v1/local-infrastructure-audit.md`

The current isolated worktree is the sole repository boundary. Existing tracked
and untracked files, including the five preceding authority modules, tests,
proposals and preexisting CI correction, are preserved. The canonical checkout
is off limits and was neither inspected nor changed. The supplied main reference
is `f015972c`, merge #764; it was not verified using Git or the network here.
These checks do not certify integrated merged-main behavior.

## Trusted provisioning and public API

`LocalTestInfrastructureAudit` is provisioned exclusively by the trusted test
harness with an existing disposable `/tmp` SQLite file, original policy sources,
`ExecutionApproval`, `VerifierGrant`, `VerificationBinding`, `AuditGrant`,
`AuditBinding`, and `TestClock`. Only namespace `fictional.lab`, resource class
`COMPONENT`, resource `fictional.component01`, and LOCAL/TEST are supported.
Paths, database access and handle distribution remain harness responsibilities.
The constructor never invokes an executor, verifier, comparison or observer.

The audit grant's role is exactly `AUDITOR`, with exactly the capability
`APPEND_FICTIONAL_AUDIT`. The auditor must differ from the principal, original
observer, human approver, fictional executor and verifier. Its scope matches
the principal's exact tenant, environment, namespace, resource class, resource
and owner. The immutable binding additionally pins execution ID/version/digest,
verifier binding digest, exact verification evidence digest, auditor identity
and audit grant ID/version. The verification evidence digest is independently
registered by the harness from trusted synthetic evidence, never accepted from
a public execution/verification result or a requester assertion.

The harness distributes only `append`, `auditor_handle` and `binding_handle` as
appropriate. The call is `append(auditor_handle=..., binding_handle=...)` and
accepts no other input. Handles are internally minted built-in objects, resolved
by exact type and object identity; fresh instances mint fresh handles. Client
claims, callbacks, paths, clocks, SQL, source records and observed state cannot
be supplied to this call. Invalid handles return `AUTHORIZATION_DENIED` without
opening storage. Provisioning accessors are not public enrollment endpoints.

Original policy, manifest, observation and approval registrations are validated
through the existing immutable source model. Historical comparison is not
rerun against changed physical state. Current audit/verifier/principal/observer/
human grants, approval window and both fixture clocks must remain active and
fresh, including for replay. Diagnostic revocation or conflicting consumption
and replay snapshots deny access. An exactly bound `CONSUMED` diagnostic is
historical evidence only; durable execution registry consumption must be one.
The registry's current revocation flag is checked inside every transaction.

These checks deliberately deny even historical reads after original authority
expires. Durable retention does not imply indefinite read authority. The clock
and current grant snapshots are harness supplied, not live wall-clock or
identity-directory attestations. A harness must provision current snapshots;
old in-memory instances do not receive a live grant-revocation feed.

## Source validation and storage

The constructor accepts only the original executor table definitions and exact
verifier schema/triggers. It rejects substituted views, extra source triggers,
indexes, schema drift, conflicting execution pins and missing evidence before
provisioning its own storage. Original executor SQL indentation is normalized;
audit and verifier SQL must match exactly. No existing schema or data is repaired.
Unrelated tables are not audit sources and cannot be read by the write adapter.

`local_audit_evidence` is the sole new table. A globally unique execution ID
permits one row per existing reservation, including across audit identities,
tenants and versions. It has bounded fields, closed outcomes/reasons, digest
format constraints, integer version bounds and a hard capacity of 256 rows.
Immutable triggers reject UPDATE, DELETE and replacement INSERT. The capacity
trigger rejects overflow, including external INSERT attempts. No pruning,
overwrite, rotation, schema migration or retention service is implemented.
Capacity exhaustion fails closed and requires a separately designed boundary.

Each append opens the existing database using `mode=rw`, enables synchronous
FULL and recursive triggers, disables trusted schema, rejects nondurable journal
modes, installs a limited authorizer, and reserves `BEGIN IMMEDIATE`. All schema,
registry, attempt, verification and previous-audit checks plus the single INSERT
share that connection and transaction. SQLite writer serialization prevents a
source mutation, revocation or schema race between validation and commit, across
threads and processes. The five-second lock wait is bounded contention handling.
It does not retry any effect. The database is never created when missing.

The authorizer permits only audit INSERT, reads from explicitly named evidence/
ledger/schema tables, transaction control and the built-in functions required
by constraints and immutable/capacity triggers. A special columnless count read
is limited to the fixed audit capacity trigger. DDL, source writes, simulated
state reads/writes, arbitrary functions and database attachment are denied.
Constant audit DDL runs only during trusted constructor provisioning under the
same writer reservation, after source validation; it is not a requester path.

All eight execution reservation and attempt pins must match original approval:
execution ID/version, approval ID/version, request ID, challenge, full serialized
scope and execution approval digest. Registry revocation must be zero and
consumption one. Only `ATTEMPTED` and `UNCERTAIN` are accepted. Unknown and legacy
certified outcomes are rejected, never normalized into success.

The verifier's entire immutable row is checked against independent source and
binding pins, desired/prestate pairs, original operation digest, observed pair,
reason, canonical historical timestamp, evidence hash and the separately pinned
verification evidence digest. Historical time must be valid, inside the verifier
and approval windows, and no later than the audit fixture clock. A coherent
rehash of altered verification evidence still breaks the independent digest pin.
Audit never takes a fresh physical snapshot or modifies verification evidence.
The executor ledger has no attempt timestamp; these checks cannot establish
whether an attempted effect occurred inside its approval window.

Stored evidence contains fictional opaque scope/identity references, versions,
source/binding/operation/policy/approval/manifest/observation digests, reservation
and attempt digests, verification evidence digest, bounded outcomes/reason and
historical observation/recording clocks. Request/challenge and source payloads
are retained only through digests. No secrets, PII, provider payloads, authenticated
URLs, arbitrary metadata or exception bodies are stored or returned.

## Result and replay semantics

`AUDIT_RECORDED` means evidence committed, with `SYNTHETIC_LOCAL_RECORD` on first
append and `HISTORICAL_REPLAY` on an exact retry or restart. Replay checks current
authority, durable registry and verification evidence again; it returns the
identical original audit digest, outcomes and historical clocks. Audit record
content is reconstructed from trusted registrations and historical source pins
before its hash is accepted. Conflicting rows are not replaced. A redirected
execution key is also detected through bound evidence/binding digest lookups.
Invalid authority yields `AUTHORIZATION_DENIED`; invalid sources, tampering,
schema conflicts, storage refusal, capacity or commit uncertainty yield
`CONFLICT` with no observation/evidence claim.

The audit captures both the executor outcome sampled at recording and the outcome
sampled earlier by the verifier. A later `ATTEMPTED` to `UNCERTAIN` transition may
be recorded separately; replay preserves the historical sampled outcome and
never upgrades it. `UNCERTAIN` to `ATTEMPTED` regressions are denied when visible
against verifier or audit history. Source ledgers are never rewritten.

`ATTEMPTED` also represents a durable reservation after a pre-effect crash; it
proves neither dispatch, acknowledgment nor an effect. `UNCERTAIN` remains
uncertain even with a `LOCAL_STATE_MATCH` observation. `PENDING` and `MISMATCH`
are historical observations and remain so after physical state changes. Even a
match proves only the verifier's sampled synthetic digest and version, with no
claim of causality, ongoing state, live action success or provider verification.
Every result has `authority_effect=NONE`.

Evidence is returned only after commit succeeds. A refused commit rolls back;
lost acknowledgment after an actual commit yields `CONFLICT`, followed by safe
historical replay on retry. Missing or malformed sources never create an attempt,
consume authority, dispatch, recover, repair state or fabricate verification.

## Trust limits, validation and next boundary

The original trusted Python process, harness, SQLite engine and filesystem model
is unchanged. Handles are not network authentication or an OS sandbox. Hashes
are deterministic bindings, not signatures. A privileged filesystem/database
owner able to coherently replace source registrations, evidence, digests/schema
or the file itself can defeat these protections. Reflection, stolen handles,
malicious provisioning, database file replacement and hardware durability failure
remain outside the model. Trigger protection does not revoke database ownership.

Security gains bounded evidence validation and denial coverage; Infrastructure
gains durable synthetic history. No live Automation or first-client Business
authority is added. Provider/Supabase, credentials, n8n, network, staging,
production, runtime/service registration, real clients and live execution are
excluded. The canonical agent resource map already includes runtime code and
proposals; no absent provider/runtime surface is introduced.

The new architecture suite covers exact evidence, attempts/uncertainty,
pending/mismatch/match semantics, restart in another process, retries, concurrent
threads/processes, lock timeout, serialized revocation, lost commit acknowledgment,
capacity, field-by-field tampering, coherent verification rehash, hostile triggers,
schema/index/view replacement, cross-tenant registrations, LOCAL/TEST, expiry,
invalid handles and zero physical/source writes. The five original suites are
also run in full. The sole engineer uses the change-review checklist for a
separate self-review pass; this is not independent review or release certification.

The unmodified `bash ./scripts/check-baseline.sh` is attempted offline with a
temporary cwd-only root resolver and a wrapper blocking all actual Git operations.
Its historical Git-blob checks conflict with the explicit no-Git boundary.
No blob identity is fabricated and no repository check is weakened. Its remaining
non-Git checks and all three Phase5D validators are run separately; the original
full baseline remains blocked until an authorized environment can perform those
Git reads. Semgrep uses the local config, no Git ignore discovery, metrics off,
version checks off and writable paths under `/tmp`. No claim of full-baseline
success or merged-main integration follows from the continuation's output.

Local validation on 2026-10-19: all 262 architecture tests passed together
(authority 22, trust 31, policy 34, execution 48, verification 53, audit 74).
All 98 non-Git direct baseline contract-validator commands completed, including
the three Phase5D validators; the three baseline security suites passed 12 tests.
JSON syntax, forbidden paths, credential-shaped content, local Semgrep and SQL
allowlist checks passed. The full baseline exited 1 at its first prohibited
Git-blob lookup; its other two Git-dependent validators remain unrun. Continuation
checks passed separately, with no claim that this satisfies the full gate.
Semgrep initially needed its log path redirected to `/tmp`; the corrected scan
passed. Sole-engineer self-review found no blocking implementation findings
within the documented trust boundary. Independent review remains outstanding.

Next action: independent review and the complete unchanged baseline against
canonical main in a separately authorized integration boundary. No commit,
push, fetch, publication or provider action is authorized here.
