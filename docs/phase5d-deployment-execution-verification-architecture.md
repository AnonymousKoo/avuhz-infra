# Phase 5D-D5 -- Deployment Execution and Verification Architecture

Status: frozen architecture and JSON Schema 2020-12 contract boundary; D5a/D5b runtime and local persistence active
Scope: exact deployment-operation attempt truth and separate exact deployed-state verification truth
Out of scope: provider deployment adapters, rollback execution runtime, credentials, production operations, remote infrastructure, n8n, and website work

## 1. Normative truth and authority chain

These records are distinct and non-substitutable:

```text
ImplementationAuthorization
!= CodexBuildPackage
!= BuildExecutionResult
!= QAResult
!= ClientAcceptance
!= DeploymentAuthorization
!= DeploymentExecution
!= DeploymentVerification
```

Progression is also non-substitutable:

```text
DeploymentAuthorization ACTIVE != deployment started
DeploymentExecution started != deployment operation completed
DeploymentExecution SUCCEEDED != deployed state verified
DeploymentVerification VERIFIED != continuing or widened deployment authority
```

A command request, event, outbox intent, read model, generic boolean, or caller assertion cannot replace authoritative truth. Every historical relationship binds an exact identity, positive version, and digest. Mutable-current or "latest" lookup is forbidden as historical authority.

## 2. Frozen contract surface

D5 defines exactly two authoritative resources, three commands, three capabilities, three lifecycle events, and two derived read models. They are provider-neutral JSON Schema 2020-12 contracts and are active in the runtime command and resource-schema registries.

| Resource | Purpose | Frozen states |
|---|---|---|
| DeploymentExecution | One exact versioned deployment or rollback operation attempt | IN_PROGRESS, SUCCEEDED, FAILED, PARTIAL, BLOCKED |
| DeploymentVerification | Immutable target-by-target observed-state truth for one exact terminal attempt | VERIFIED, FAILED, PARTIAL, BLOCKED |

The command surface is `StartDeploymentExecution`, `CompleteDeploymentExecution`, and `RecordDeploymentVerification`. No rollback command is introduced: an authorized rollback is a new `DeploymentExecution` whose action is `ROLLBACK_EXACT_ARTIFACT` and which binds the exact attempt it corrects.

## 3. Exact source binding

Every execution carries one immutable `authority_binding` containing the exact:

- DeploymentAuthorization ID, version, and deployment-authority digest;
- ImplementationAuthorization ID, version, and digest;
- CodexBuildPackage ID, version, and digest;
- BuildExecutionResult ID, version, and digest;
- QAResult ID, version, and digest;
- ClientAcceptance ID, version, and digest;
- artifact identity, version, and digest;
- target environment; and
- complete authorized target-resource set.

An execution may start only while that exact DeploymentAuthorization is `ACTIVE`, within its validity window, with both attributable approvals still valid, and only for an action, artifact, environment, and target set explicitly contained in it. Revocation, expiry, supersession, a changed artifact, or any wrong upstream binding denies start with no success side effects.

An attempt remains historically bound to the authority valid when it started. Later authority changes never rewrite it. Verification may record post-attempt evidence after the authority window closes because verification creates no deployment authority and performs no target mutation; it must still bind the exact historical authorization and execution.

## 4. DeploymentExecution truth

`StartDeploymentExecution` creates `IN_PROGRESS` attempt truth only. Its payload has no status, success, verification, approval, or authority boolean. `CompleteDeploymentExecution` supplies bounded per-target operation outcomes and evidence references. The authoritative service must derive the terminal status and digest:

- `SUCCEEDED`: every exact authorized target reports `APPLIED` or `UNCHANGED`; operation completion still requires verification.
- `FAILED`: at least one target reports `FAILED`, no target reports `APPLIED`, and no target mutation needs rollback.
- `PARTIAL`: at least one target reports `APPLIED` and at least one reports `FAILED` or `BLOCKED`; rollback is required.
- `BLOCKED`: no target reports `APPLIED` or `FAILED`, and at least one reports `BLOCKED`; no mutation occurred.

The target-outcome set must cover every and only the exact authorized targets once. Evidence is bounded to opaque reference, class, digest, and provenance; raw logs or provider payloads are prohibited. `SUCCEEDED` means the requested operation completed, not that the deployed state matches authority.

## 5. DeploymentVerification truth

`RecordDeploymentVerification` binds one exact terminal DeploymentExecution version/digest and repeats the exact immutable authority binding. Verification evaluates every authorized target exactly once against the authorized artifact digest using bounded observed-state evidence.

Per-target results are `MATCHED`, `MISMATCHED`, or `BLOCKED`. For `MATCHED` and `MISMATCHED`, observed artifact digest and observed-state fingerprint are required. Overall truth is deterministic:

- `VERIFIED`: every target is `MATCHED`;
- `FAILED`: at least one target is `MISMATCHED`;
- `PARTIAL`: no target is mismatched and results mix `MATCHED` with `BLOCKED`; or
- `BLOCKED`: every target is `BLOCKED`.

Only `VERIFIED` establishes that the exact deployed target state matches the exact authorized artifact. A generic `deployment_succeeded`, `verification_passed`, `verified=true`, or similar caller field is prohibited. Execution status, events, and projections cannot manufacture verification truth.

## 6. Rollback and correction

Rollback requirement is fail-closed and derived, never caller-selected:

- a `SUCCEEDED` execution has `PENDING_VERIFICATION`;
- a `PARTIAL` execution has `REQUIRED`;
- a `FAILED` or `BLOCKED` execution with no applied target has `NOT_REQUIRED`;
- `VERIFIED` verification sets `rollback_required=false`; and
- `FAILED`, `PARTIAL`, or `BLOCKED` verification sets `rollback_required=true`.

A rollback performs no work in this architecture batch. Future runtime may start a rollback only through a new exact `DeploymentExecution` using `ROLLBACK_EXACT_ARTIFACT`, an exact `rollback_of_deployment_execution_reference`, and a currently valid DeploymentAuthorization that permits rollback. That authorization's artifact binding is the exact recovery artifact to restore; authority for a different artifact cannot be repurposed. Expired, revoked, or artifact-mismatched authority cannot be reused; replacement requires a separately approved exact authorization. The rollback attempt requires its own independent DeploymentVerification. Earlier failure and rollback-required facts remain immutable.

Retry, correction, retest, and rollback create new attempt versions with exact supersedes/correction references. Terminal execution records and every verification record are immutable. No outcome may be rewritten from failure, partial, or blocked to success.

## 7. Commands, capabilities, callers, and events

| Command | Trusted caller | Capability | Event |
|---|---|---|---|
| StartDeploymentExecution | HUMAN or INTERNAL_SERVICE | `deployment_execution:start` | `deployment_execution.started` |
| CompleteDeploymentExecution | INTERNAL_SERVICE | `deployment_execution:complete` | `deployment_execution.completed` |
| RecordDeploymentVerification | HUMAN or INTERNAL_SERVICE | `deployment_verification:record` | `deployment_verification.recorded` |

TrustedExecutionContext supplies tenant, identity, caller type, capability, and human attribution. Payload identity, role, approval, success, or authority claims are non-authoritative. Completion uses expected record version. Later attempts and verification versions bind exact superseded records. Exact idempotent replay returns `DUPLICATE`; the same reservation with changed semantics returns `CONFLICT`; stale versions fail boundedly.

Future accepted transitions must atomically persist authoritative state, idempotency, one schema-valid lifecycle event, and one `PENDING` transactional-outbox intent. Events are sanitized descriptions, never authority or raw evidence.

## 8. Human, workload, and AI boundary

A trusted HUMAN may request an authorized attempt or record attributable manual verification evidence where policy permits. A trusted internal workload may execute the exact authorized action and record bounded machine observations. AI may assist with summaries or anomaly suggestions.

No human payload, workload, or AI may invent operation success, omit failed targets, fabricate evidence, self-approve authority, widen artifact/environment/targets/actions, override prohibited actions, select its own attribution, or convert execution truth into verification truth. Runtime must resolve authority and evidence provenance through trusted boundaries before accepting consequential truth.

## 9. Security and provider neutrality

Contracts contain no credentials, tokens, passwords, private keys, authenticated URLs, secret material, provider-specific payloads, unrestricted logs, or capability secrets. Bounded evidence and operation references are opaque identifiers plus digests and provenance only. Credential use remains behind a future separately authorized provider/vault boundary and is not designed here.

The same contracts represent roofing/home services, security staffing, medical-office operations, infrastructure providers, and unrelated future companies without core changes. No company, domain-specific diagnostic concept, deployment vendor, repository host, or secret format appears in the contract vocabulary.

## 10. Required negatives

Schema and semantic validation reject or deny:

- inactive, expired, revoked, or superseded DeploymentAuthorization;
- wrong authorization or upstream identity/version/digest;
- artifact, environment, target, action, tenant, or engagement mismatch;
- omitted, duplicate, or extra target outcomes/verifications;
- attempt start treated as completion;
- execution `SUCCEEDED` treated as verified deployment;
- generic deployment-success or verification-pass claims;
- inconsistent derived execution or verification status;
- invented, missing, or unproven evidence/provenance;
- stale record version, duplicate identity/version, and idempotency conflict;
- workload authority widening, role spoofing, and attribution spoofing;
- rollback without exact current rollback authority and correction binding; and
- secret-shaped fields, raw credentials, raw provider payloads, and unbounded logs.

Rejected commands create no authoritative record, event, idempotency success, or outbox intent.

## 11. Read models and runtime boundary

`DeploymentExecutionStatusView` exposes operation truth and always fixes `deployment_verified` to false. `DeploymentVerificationStatusView` exposes exact verification truth; `deployment_verified` is true only for `VERIFIED` and `rollback_required` is its deterministic inverse.

D5a/D5b implement the frozen `DeploymentExecution` and `DeploymentVerification` command handlers, repository ports, UnitOfWork members, local persistence tables, and tenant RLS policies. They add no provider adapter, rollback operation, production change, credential handling, or remote mutation. Runtime records bounded execution and verification truth only; it does not perform a real deployment.
