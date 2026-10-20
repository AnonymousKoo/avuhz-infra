# Bounded fictional recovery action candidate

R2 source-only, LOCAL/TEST SQLite harness. No provider, service endpoint, network,
secret, scheduler or real resource authority. The reconciliation module and its
proposal remain unchanged: HOLD, REVIEW_REQUIRED and NO_RETRY_AUTHORIZED remain
non-executing decisions with no retry authority. Gate 9 release acceptance and
the certification runner remain unchanged; LOCAL v1 remains NOT CERTIFIED.

## Fence proof and positive boundary

This candidate permits a new action only for a consumed ATTEMPTED original with
HOLD reconciliation, the exact original expected prestate, and durable proof of
no original dispatch. Updated original execution atomically registers an immutable
protocol marker alongside a *new* registry entry. Reopening never backfills that
marker. Every original physical write, including the change-before-effect failure
fixture, occurs in one BEGIN IMMEDIATE transaction after checking the immutable
fence and inserting an immutable dispatch receipt. Receipt and state write commit
or roll back together. The fixture side write now shares that transaction rather
than using a separate transaction; its externally tested failure behavior remains.

The action acquires that same SQLite writer lock, requires exact scope/digest,
consumed nonrevoked ATTEMPTED registration, protocol marker and no dispatch
receipt, then atomically commits an immutable original fence and its own unique
reservation. Either original dispatch commits first and recovery denies, or the
fence commits first and delayed original dispatch cannot physically write. No
observation, HOLD, timeout, return value or synthetic quiescence flag is fence
proof. UNCERTAIN originals, committed dispatches, legacy registrations and changed
prestate deny. There is no recovery for an ambiguous or partial original effect.

The proof applies only to fresh fictional harness executions with **all writers
running this reviewed updated executor code**. Old or mixed-version processes,
external dispatchers, hostile Python/reflection, replaced SQLite databases and
privileged database owners are outside this simulation. This is not an upgrade
protocol for live or outstanding legacy executions. Existing unconsumed legacy
registrations also fail dispatch without protocol membership and become UNCERTAIN;
positive execution requires a freshly registered updated-code fixture. No production inference is
permitted. SQLite/Python/filesystem and independent harness provisioning remain
trusted; consistency digests are not signatures or real identity verification.

## Separate authority and evidence

`LocalTestRecoveryAction` is a new harness-only registration and capability API.
It accepts complete reconciliation sources plus a separately registered
`RecoveryActionRequest`, exact version-1 ALLOW policy, fresh human
`RecoveryActionAuthorization`, four grants and trusted clock. These constructors
must never be exposed as requester enrollment or deserialized request authority.
The action is restricted to the original approved fictional desired digest/version.

The request pins the original execution/attempt/case and reconciliation digests,
complete original scope, desired postconditions and a separately persisted fresh
prestate observation. Transitive original audit/case pins retain the failure,
original authority, tenant, environment, namespace, resource, policy and sources.
The observation uses the existing independent collector on a new case opened
strictly after the immutable reconciliation decision. The action observer has its
own role pin; collection uses its separately bound observation capability.

Action, request, challenge, observation/case and human authorization identities
are distinct from the original identities; action/request/challenge/authorization
are durably unique. The action human, executor, observer and verifier all differ
from each other and from every original and reconciliation role. The human intent
binds the complete request, exact policy, all four grants and executor identity.
The complete authorization binding additionally pins its window, version and
one-attempt limit. Missing, forged, stale, future, revoked or
mismatched sources deny. `revoke(authorization_handle=...)` permanently records
human revocation under the same writer lock. Revocation between reservation and
effect prevents the effect; consumption and fence remain. Revocation is never
cleared by reopening or new consent.

`execute` accepts instance-local executor and human handles only. It revalidates
sources and prestate immediately before reservation and again before the one
conditional fake state write. The effect and ATTEMPTED evidence commit atomically.
A committed reservation is never dispatched again, including after process crash,
concurrent delivery or lost acknowledgment. A changed source, expiration or
revocation after reservation leaves the action consumed and unverified. No retry,
compensation or reset API exists. One action is permitted per original execution.

`verify` accepts a distinct verifier handle, opens a separate read-only physical
connection, compares actual scope/digest/version with approved postconditions,
and writes one immutable VERIFIED or UNVERIFIED record including actual observed
state and time. The executor cannot insert verification records; the verifier
writer cannot mutate physical state, fence or original authority. Historical
verification replay returns immutable evidence, never a continuing-state claim.
An unavailable verifier returns UNVERIFIED; only persisted verification establishes
a verified local result. All calls, including replay/verification, require current
fresh authority and observation (60 seconds); expiration or revocation can prevent
later verification and requires separate future design, not bypassing freshness.

PROPOSED/AUTHORIZED, RESERVED, ATTEMPTED and best-effort UNCERTAIN are append-only
action events, linked by a digest of request, policy, grants and exact consent.
DENIED is a response without dispatch, not necessarily a persisted record for an
invalid/unregistered caller. VERIFIED/UNVERIFIED use a separate immutable table.
If storage fails, RESERVED may remain the final durable state; that is unresolved
consumption, never success. Capacity limits and exact schemas fail closed; update,
delete and replacement of evidence are rejected. A late fenced original may
update its original outcome to UNCERTAIN without physical effect; subsequent
source checks conservatively deny further action/verification. Previously recorded
historical evidence remains immutable and does not assert continuing state.

## Offline validation and remaining release work

Run all `tests.architecture.test_local_infrastructure_*_v1` unittest modules with
`PYTHONPATH=src:.` and `PYTHONDONTWRITEBYTECODE=1`. Focused action and fencing suites
exercise delayed original dispatch (including the fixture side write), no legacy
backfill, ambiguous/completed original denial, role separation, exact pins,
authority freshness, durable revocation, forged handles, actual wrong poststate,
concurrency, reservation/evidence failure, lost acknowledgment and immutable
records. Run unchanged `./scripts/check-baseline.sh` offline with Semgrep metrics
and version checks disabled and settings/log paths under `/tmp`.

Security and Infrastructure progress is limited to fictional recovery. Automation
has no dispatch endpoint; Business/customer readiness is unchanged. Independent
security review of this R2 candidate and a separately authorized release-harness
R1 integration remain required. The existing runner must continue reporting
RECOVERY_MUTATION_GATE_UNMET. No v1 certification, provider or deployment claim.

Bounded implementation validation (2026-10-20): 336 LOCAL infrastructure tests
passed without skips, including 24 action and 8 fencing tests. The unchanged
offline baseline passed, including local Semgrep and its 12 security unittests.
An independent read-only source/security review found no remaining blocking
findings after separating executor and verification storage privileges. Reviewed
action source SHA256:
`dcc7a95052e43117f68160681db0e6af9ec375539a4c0c9b3ecb29d5c50f418c`.
This review is component evidence, not release certification. Next action:
owner review followed by a separately authorized R1 release-harness integration.
