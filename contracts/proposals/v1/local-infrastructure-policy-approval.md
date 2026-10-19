# LOCAL infrastructure policy and approval proposal — Milestone 2B

R2 authority modeling only. This proposal is outside the frozen runtime catalog.
It applies exclusively to LOCAL/TEST, namespace `fictional.lab`, resource class
`COMPONENT`, resource `fictional.component01`. Every result has authority effect
`NONE`. There is no operational authority or runtime registration.

## Trusted composition and request boundary

`LocalTestInfrastructurePolicyAdapter` is frozen and slotted. Its constructor is
owned exclusively by a trusted test harness. The harness independently prepares
immutable PR761 grants, ownership, manifests, observations, comparison slots,
clock and replay snapshot, plus an explicit policy registry, HUMAN grants,
explicit approvals and an immutable consumption/revocation snapshot. Never build
these sources by deserializing a request. Exact record and primitive types,
registry tuples, duplicate identities/request slots/challenges and source scope
relationships are checked before use. Malformed provisioning raises a fixed
`LocalInfrastructureDenied` diagnostic code. Unknown integer policy versions
remain fail-closed at evaluation; booleans are not versions or counters.

The actual PR761 class is `LocalTrustAdapter`. This composition constructs it
internally and retains the original source records. It accepts neither a client
comparison result nor an injected adapter or callback. Harness-only accessors
expose immutable tuples of internally minted handles. Requesters receive only
selected handles and bound review methods. Lookup uses object identity, never
caller equality, hashing or serialized identity strings. Handles from other
instances, other registries or unregistered objects fail closed.

`evaluate_policy(request, *, principal_handle, comparison_handle)` compares the
exact request internally. Only `CONTRACT_MATCH` with authority effect `NONE` can
reach policy review. All PR760/761 request, ownership, observer authorization,
prestate, freshness and replay checks remain in force.

## Closed policy v1

`EvidencePins` binds the original full `ApprovedManifest`, `SimulatedObservation`
and `ComparisonSlot`, the operation digest, fixed `COMPARE_FICTIONAL_STATE`
operation and a secondary SOURCE digest. Consequently scope includes principal,
tenant, owner, environment, namespace, resource and class; evidence includes
manifest identity/digest/version, desired digest/version, expected-current
and observed-current digest/version, request/challenge, observation identity,
observer identity, and slot/observation timestamps.

SOURCE canonicalization uses sorted compact ASCII JSON and domain separator
`avuhz.local-infrastructure-policy.SOURCE.v1` followed by a newline. It includes
the entire observation and independently registered observer grant, including
role, status, scope and grant timestamps. This is necessary because the PR760
operation digest excludes observer identity and observation timestamps. A changed
observer or time cannot reuse the same operation digest to satisfy existing pins.
These SHA-256 bindings are not signatures or proof of provenance.

The independently pinned `PolicyRule` registry supplies a policy ID, version,
exact evidence pins and closed ALLOW/DENY decision. Only version 1 is recognized.
Missing policy, unknown version, any pin mismatch and explicit DENY produce
`POLICY_MISSING`, `POLICY_VERSION_UNKNOWN`, `POLICY_PIN_MISMATCH` or
`POLICY_DENIED`. Exact allowlist membership produces `POLICY_ALLOW_DIAGNOSTIC`.
Desired/observed mismatch alone grants nothing. The policy decision digest binds
the entire rule using domain separator
`avuhz.local-infrastructure-policy.DECISION.v1` followed by a newline.

## Separate human approval review

`review_approval(request, *, principal_handle, comparison_handle,
approver_handle, approval_handle)` recomputes comparison and policy. A human
cannot override policy denial. The independently registered HUMAN must have
`REVIEW_FICTIONAL_POLICY` capability, ACTIVE status, the exact scope and a current
window, and must differ from principal, observer and `fictional.executor01`.

An `ExplicitApproval` records its ID/version, human identity, explicit
APPROVE/DENY, full evidence pins, policy ID/version/decision digest, fixed fictional
executor, validity window, `max_attempts=1` and `max_recoveries=0`. All windows are
UTC, second-precision, start-inclusive/end-exclusive and at most 300 seconds.
Expired, future, overlong, forged or mismatched approval evidence fails closed.
Duplicate approval IDs, request slots or challenges (including conflicting
versions/decisions) fail during construction. Only the selected registered
approval can be reviewed; callers cannot provide an approval record at call time.

Consumption entries record approval ID/version, request, challenge, operation
digest and CONSUMED/REVOKED status. A match on any identity, request, challenge or
operation digest denies reuse, even if another approval version is supplied.
PR761's separate replay snapshot remains enforced. Approval-review reason codes
are `HUMAN_SCOPE_OR_SEPARATION_DENIED`, `HUMAN_GRANT_INACTIVE`,
`APPROVAL_BINDING_MISMATCH`, `APPROVAL_TIME_INVALID`, `APPROVAL_UNAVAILABLE`,
`HUMAN_DENIED` and `APPROVAL_MATCH_DIAGNOSTIC`. A match is an immutable diagnostic,
never an approval token, execution token or dispatch permission. Results contain
only fixed codes and digests, never raw request or provider payloads.

## Limits and validation

The harness can review repeatedly with an unchanged empty consumption snapshot.
This implementation neither persists nor atomically consumes anything. Snapshot
completeness, freshness and independent provisioning are harness assumptions.
A stale empty snapshot cannot detect a previous review. There is no durability,
recovery, exactly-once behavior, real authentication, approved provider
observation, cryptographic authentication, real human approval or verified
execution. Python reflection, monkeypatching, concurrent request mutation and
`object.__setattr__` are outside this in-process test model.

No provider, SQL, credentials, network, services, runtime wiring or deployment is
introduced. Phase5D client-system `DeploymentAuthorization` is separate and is
not used as infrastructure authority. This work advances fictional Infrastructure
and Security modeling; it creates no Automation dispatch or Business readiness.

The offline adversarial suite covers exact evidence binding, policy denial,
human separation, revoked/expired grants, approval windows/counters, consumption,
replay, changed observers/times with unchanged operation digests, registry
conflicts, equality traps, handle isolation, mutation and call-time injection.
Run the PR760, PR761 and new suites together, the offline repository baseline,
and the three safe Phase5D contract validators. Full CI on a new PR is separately
required before integration. No local passing result grants publication or
provider authority.
