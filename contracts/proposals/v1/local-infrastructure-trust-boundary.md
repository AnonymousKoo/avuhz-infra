# Milestone 2A: LOCAL/TEST trust composition candidate

This R2 repository-only candidate in AnonymousKoo/avuhz-infra covers exactly
`fictional.lab`, class `COMPONENT`, resource `fictional.component01`, in LOCAL
or TEST. It adds no runtime command registration, provider connection, execution,
policy allow, approval, dispatch, or verified-result path. A successful comparison
returns PR760's `LocalContractResult` with `CONTRACT_MATCH` and authority effect
`NONE`. It does not establish deployment or production readiness.

## Test harness boundary

`LocalTrustAdapter` provisioning belongs exclusively to an independently owned
test harness. The harness supplies separate immutable registries for:

- identity grants, with exact identity, tenant/owner membership, environment,
  namespace, resource class/resource, role, active/revoked status and time window;
- resource ownership, independently of an identity's membership grant;
- approved manifests, pinned by internal manifest ID and containing desired and
  expected-current digest/version pairs;
- independently collected simulated observed state, with its own digest/version,
  observation ID, time window and separately registered observer identity;
- comparison slots binding principal, pinned manifest, observation, request,
  challenge and validity window;
- a fixed UTC test clock with a bounded window and a test-owned replay snapshot.

An entry in the approved-manifest registry means the harness provisioned that
fixture. There is no requester-supplied approved/trusted flag, provenance string,
or arbitrary `TrustedBinding`/`TrustedObservation` accepted as proof. Simulated
observation values must be collected independently; the adapter never fills them
from the request or the manifest's expected-current values. Code cannot prove a
test author actually collected independent facts; that is the harness boundary.

The harness constructs the adapter before receiving the independent request
fixture. Only it uses `identity_handles` and `comparison_handles` to provision
selected capabilities. Requesters receive the selected principal and comparison
handles and access to `compare(request, *, principal_handle, comparison_handle)`.
They must not control provisioning or receive registry access. These accessors
are test setup conveniences, not public identity lookup or authentication APIs.

Handles are fresh built-in `object()` instances retained in adapter-internal
tuples. Resolution requires the exact built-in type and uses object identity
(`is`), never client strings, equality, hashing, or a serialized object ID.
Different adapters mint different handles even for identical fixture records.
Principal and comparison handles occupy separate registries. An observer handle
cannot serve as a principal; matching a string identity is not sufficient.

Every registry record is exact-type checked before equality/hash operations;
accepted fields are bounded primitives, validated frozen scopes and UTC datetime
values. Registries are tuples of at most 256 records, including the local replay
fixture. IDs are bounded to 3–64 characters; versions to positive signed 32-bit
integers; digests to the PR760 SHA-256 shape. Windows are positive and at most
300 seconds. Nested mutable aliases, subclasses and duplicate registry keys
(including conflicting values), ownership keys, requests and challenges fail
closed. Different manifest/observation IDs can identify separate historical
fixtures; the comparison slot pins exactly one of each, with no latest/fallback
selection. Denials contain fixed codes only, with no raw supplied values.

## Composition and limits

The principal must have the PRINCIPAL role and exact slot identity. Its full
scope must match the manifest, observation and independently registered ownership.
The observer must be a distinct active identity with the OBSERVER role and the
same tenant, owner, environment, namespace, class and resource membership.
Both grants must be current under the harness clock. PR760's
`TrustedObservation.scope.identity_id` remains the **principal** identity for
scope equality; observer identity stays in adapter source metadata.

Only after these checks does the adapter derive `TrustedBinding` and
`TrustedObservation`, then call the unchanged `validate_local_resource_contract`
with its internal replay snapshot and UTC clock. The existing validator checks
the independent observed pre-state digest/version, timing, exact request equality
and consumed request/challenge entries. No requester may select the observer,
manifest, clock, trusted context or replay state at call time.

This is an **in-process-only capability model**, not cryptography, authentication,
production trust, durable replay protection, or an isolation boundary against
arbitrary Python code. Reflection, `object.__setattr__`, monkeypatching, stolen
handles and a compromised harness are outside the model. Frozen slotted records
prevent ordinary mutation, not hostile interpreter access. Revocation is a fact
in the supplied snapshot, not a live revocation feed. Test-clock freshness is
relative to its independently provisioned fixture window, not wall-clock proof.

Comparison never consumes or persists a request/challenge. Repeating a comparison
with an unchanged empty snapshot still succeeds. Atomic replay consumption,
clock attestation, authenticated identities, real ownership and manifest approval,
independent live observation and all execution authority remain unimplemented.

## Validation and later integration

The focused offline suite is:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -B -m unittest tests.architecture.test_local_infrastructure_authority_v1 tests.architecture.test_local_infrastructure_trust_v1
```

The full applicable offline gate is `scripts/check-baseline.sh`, with Semgrep
metrics and version checks disabled and its settings under `/tmp`. Local checks
use the isolated checkout at HEAD `55ff37f` plus the preserved PR760 files.
They cannot certify post-merge integration. The additive three-file patch is
intended for later publication against main
`315bba43729b43044c0b585280b2b2a08097bb90`; GitHub CI must separately check the
integrated result. This task does not publish, commit, push or authorize any
provider action. Security/Infrastructure source progress here does not implement
Automation or advance first-client Business enrollment gates.
