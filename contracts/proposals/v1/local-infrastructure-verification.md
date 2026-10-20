# Infrastructure authority LOCAL v1 milestone 3A

R2, synthetic LOCAL/TEST source candidate. This proposal adds only
`src/avuhz_runtime/local_infrastructure_verification.py`,
`tests/architecture/test_local_infrastructure_verification_v1.py`, and this file.
It preserves the four preceding LOCAL modules and their tests, including the
48 execution tests from PR #763. The supplied canonical reference is merged
#763, `0bc9ed8c7c6ef8294ba65ba2c74a274c942fa185`; no network verification or Git
metadata mutation is part of this isolated older-worktree implementation.

## Boundary and provisioning

Only `fictional.lab`, resource class `COMPONENT`, resource
`fictional.component01`, and LOCAL/TEST are accepted. Disposable SQLite files
must already exist under `/tmp`. This is shared Avuhz runtime infrastructure;
it implements no vertical-specific authority and mounts no service or endpoint.

The trusted test harness independently provisions an immutable
`ExecutionApproval`, the existing policy source dataclasses, `VerifierGrant`,
`VerificationBinding`, and `TestClock`. It does not obtain these from an
execution result or client request. The constructor validates the existing
`ExplicitApproval`, manifest, original operation digest, policy decision and
source observation digest, exact source registrations, and execution approval
binding. Historical sources are matched without rerunning the old prestate
comparison or claiming that the execution occurred inside an approval window.
The execution ledger has no timestamps from which to establish that claim.

Verifier scope binds its own identity to the exact tenant, owner, namespace,
resource class, resource and environment. The separate binding retains the
execution principal and the exact execution ID, version, approval digest, and
verifier grant ID/version. The verifier identity must differ from the requester,
original observer, human approver and fictional executor. Its role is `VERIFIER`
and sole capability is `OBSERVE_FICTIONAL_POSTSTATE`; an execution capability is
not a verification capability. The execution operation must explicitly be
`APPLY_FICTIONAL_STATE`.

Only two internally minted opaque object handles reach `verify`. Lookup uses
object identity after exact type checking. Client claims, execution results,
clocks, paths, observed digests, callbacks and state cannot be supplied at call
time. Provisioning accessors are harness-only. Each new instance mints new
handles. The fixed trusted clock and verifier grant are checked for freshness
and active status on every call, including replay. This is fixture-based
revocation checking, not a live identity directory or wall-clock attestation;
a harness must supply current trusted grants when provisioning instances.

## Physical observation and recording

The verifier does not instantiate or invoke an executor and never calls its
`_observe` method. It opens its own SQLite `mode=ro` connection and reads the
physical `simulated_resource_state`, `execution_registry` and `local_attempts`
in one read transaction. All eight execution registration/attempt pins must
match: execution ID/version, approval ID/version, request ID, challenge, exact
scope and execution approval digest. Registry revocation must be zero and the
attempt must be consumed. Only `ATTEMPTED` and `UNCERTAIN` are accepted; legacy
`VERIFIED`, unknown outcomes, missing attempts and conflicting pins fail closed.

A separate `mode=rw` connection reserves `BEGIN IMMEDIATE` before that snapshot.
This prevents other SQLite writers changing the source between snapshot and
recording, including across threads/processes. The read-only connection closes
before the evidence insert commits. The verifier never creates a missing
database, execution table, attempt or physical state, and never seeds a state.

The only new table is `local_verification_evidence`. Its primary key is exact
attempt execution ID, serialized scope and verifier identity. The execution
ledger already permits one attempt per execution ID; changed versions or
bindings conflict instead of replacing that observation. The record retains
binding/source/operation/execution digests, desired and prestate digest/version,
observed digest/version, the sampled allowed execution outcome, bounded reason,
fixture observation time, and a domain-separated evidence digest. Expected pins
remain independently available from the immutable constructor registration.
No raw source payloads are persisted or returned.

SQLite constraints enforce the key and closed outcome/reason fields. Immutable
triggers reject update, delete, and replace, and the adapter checks its exact
evidence schema and trigger set before using it. Its writer authorizer allows
only evidence insertion, reads, functions and transaction control after bounded
schema provisioning. It cannot modify the three existing execution tables.
Exact duplicate calls return existing evidence; conflicting records, malformed
source/schema, digest inconsistency and storage errors return bounded `CONFLICT`
without a successful observation. A failed commit never returns a match.

## Result semantics

| Result | Meaning |
| --- | --- |
| `LOCAL_STATE_MATCH` | Physical digest **and version** matched the pinned desired pair in the sampled synthetic snapshot. |
| `PENDING` | Physical pair still equaled the approved prestate. |
| `MISMATCH` | Physical pair was valid but matched neither expected pair. |
| `CONFLICT` | Missing, inconsistent or invalid authority/evidence/storage; no successful observation. |
| `AUTHORIZATION_DENIED` | Inactive/expired verifier or invalid fixture clock window. |

A newly recorded result is explicitly `SYNTHETIC_LOCAL_SNAPSHOT`. Replay is
`HISTORICAL` and returns the stored result/digest/version, even if physical state
has since changed. A previous pending or mismatch result is never silently
upgraded. The current attempt/registry must still validate before replay, and
the caller's verifier authority must remain valid. No read-only public evidence
endpoint or SQL view is introduced; the handle-gated replay path is the bounded
evidence read surface.

Every result has `authority_effect=NONE`. Desired state may have been present
for an unrelated reason. Matching it proves neither causal execution success,
actual effect timing, exactly-once effects nor continuing state. `UNCERTAIN`
remains `UNCERTAIN` in the execution ledger even when a snapshot matches.

## Trust limits and excluded work

The Python process, test harness, database files and filesystem are shared and
trusted. Immutable dataclasses and opaque handles are not an independent OS
security boundary. Hashes provide deterministic binding and detect inconsistent
or mismatched forged/tampered records; they are not signatures or authentication.
A privileged writer capable of coherently rewriting records, digests, schema,
or deleting the entire database can defeat these checks. Reflection, malicious
provisioning and replacing database files are outside the model. No persistent
external verifier-revocation service is implemented.

No provider, credentials, AUTH/DATA, n8n, network, production, staging, IaC, live
service, real client, audit/recovery, human-authenticated approval or wider
release-gate certification is included. Security-lane work is limited to the
local authority boundaries; Infrastructure gains a synthetic observation
candidate; Automation and Business receive no additional operating authority.

## Validation and next boundary

Focused tests cover attempted and uncertain outcomes, pre-effect crashes,
nonmatching states, independent role/scope bindings, expired/revoked grants,
hostile equality and injection, schema/startup failures, persistence/restart,
historical replay, tampering, immutable constraints, evidence write refusal,
physical-state preservation and concurrent threads/processes. Validation also
runs all five LOCAL suites, the full offline baseline with Semgrep, all three
Phase 5D validators, whitespace checks, and SHA-256 preservation of all old
tracked/untracked files and the original dirty security test.

The sole engineer performs a separate adversarial review pass using the
repository change-review checklist; this is self-review, not another engineer's
independent approval. No commit or publication is authorized. The next action
is review of these three additive files against canonical main in a separately
authorized integration boundary. Provider verification remains a distinct,
unimplemented and unauthorized stage.
