# Phase 5D-A — Implementation Brief and Codex Build Package Architecture

Status: frozen architecture and JSON Schema 2020-12 contract boundary
Scope: governed implementation truth, bounded non-production implementation authority, and an executor-ready Codex build package
Out of scope: runtime handlers, repositories, database schema/RLS, migrations, n8n, website work, deployment authorization runtime, production change, deployment, and managed operations

## Purpose and authority progression

Phase 5D-A defines the bridge from verified OIA truth and active Phase 5C ongoing authority to a safe implementation packet. It answers what may be built, why it is justified, the exact limits, how correctness will be tested, and what must not change.

The following inequalities are normative:

```text
OIAFindingsDelivery != conversion
AssessmentAccessGrant != OngoingAccessGrant
OngoingAccessGrant != ImplementationAuthorization
ImplementationBrief != ImplementationAuthorization
CodexBuildPackage != ImplementationAuthorization
ImplementationAuthorization != DeploymentAuthorization
CodexBuildPackage != DeploymentAuthorization
deployment authorization != managed-operations authority
```

An active ongoing access channel is a prerequisite for current implementation eligibility; it is not change authority. An approved brief describes governed truth; it is not change authority. A released package carries bounded instructions; it is not authority. Only a separately active and usable `ImplementationAuthorization` permits its enumerated non-production build actions against its exact targets and validity window.

Phase 5D-A does not define a `DeploymentAuthorization` resource. That omission is intentional. Deployment authority requires a later separately governed contract and runtime batch. Every Phase 5D-A read model fixes `deployment_authorized` and `production_change_authorized` to `false`.

## Resource model

### ImplementationBrief

`ImplementationBrief` is the versioned, human-readable implementation truth. It binds one tenant and engagement to:

- an exact `OIAAssessment` record version;
- an exact `OIAFindingsDelivery` identity and delivery sequence;
- exact selected Finding identities, revisions, and SHA-256 content digests;
- the accepted `OIAConversionDecision` version;
- the active Agreement #2 `OngoingAgreementAuthority` version;
- the exact currently valid `OngoingPaymentVerification` version;
- the exact currently usable `OngoingAccessGrant` version;
- a source-truth digest and an independent brief digest.

It contains the approved business problem, desired outcome, traceable approved scope, explicit exclusions, known constraints, current-state context, approved integrations and access level, risks, implementation requirements, acceptance criteria, prohibited changes, dependencies, assumptions and limitations, distinct human approvals, trusted attribution, timestamps, and positive versions.

States are `DRAFT`, `APPROVED`, and `SUPERSEDED`.

```text
DRAFT -> APPROVED
APPROVED -> SUPERSEDED
```

`APPROVED` requires active exact client and Sekinfra approvals over the same `implementation_brief_digest`. A draft or approval creates no access, implementation, deployment, production-change, or operations authority.

Statements classified as `VERIFIED_OIA` require Finding-level traceability. Assumptions and limitations remain explicitly classified; AI or a caller cannot convert them into verified facts.

### ImplementationAuthorization

`ImplementationAuthorization` is a new first-class authority identity. It is never an `AssessmentAccessGrant`, `OngoingAccessGrant`, renamed grant, widened grant, or package field.

It binds:

- one exact approved `ImplementationBrief` version and digest;
- the same exact conversion, Agreement #2, commercial-verification, and ongoing-access chain;
- one authorized-scope digest;
- exact repositories, components, or non-production targets;
- a closed set of permitted build-action classes;
- the complete prohibited-change set;
- an effective time and expiry;
- distinct client and Sekinfra human approvals;
- an implementation-authority digest and positive version.

Permitted actions are limited to repository reads, code/test/documentation creation or modification, test execution, and a non-production build artifact. `DEPLOY`, production change, credential rotation, permission widening, deletion, billing changes, and out-of-scope network or security-control changes are not permitted action classes.

States are `PROPOSED`, `ACTIVE`, `EXPIRED`, `REVOKED`, and `SUPERSEDED`.

```text
PROPOSED -> ACTIVE | REVOKED
ACTIVE -> EXPIRED | REVOKED | SUPERSEDED
```

`PROPOSED` is unusable. Future activation must revalidate server-side:

```text
brief exact version is APPROVED
and brief digest matches
and conversion exact version is ACCEPTED
and Agreement #2 exact version is ACTIVE and in term
and commercial verification exact version is VERIFIED and currently covered
and OngoingAccessGrant exact version is usable by the Phase 5C predicate
and no offboarding is active
and scope digest and targets match the brief
and both exact human approvals are active
and effective_at <= server_time < expires_at
and authorization.state == ACTIVE
```

Commercial invalidation, ongoing-access invalidation, revocation, expiration, offboarding, digest mismatch, or target mismatch makes the authorization unusable immediately. Historical state remains intact.

### CodexBuildPackage

`CodexBuildPackage` is the immutable, versioned, machine/executor-ready packet derived from one exact approved brief and one exact implementation authorization. It includes:

- package identity and version;
- tenant and engagement;
- exact brief and implementation-authorization references and digests;
- authorized build scope;
- problem statement and desired outcome;
- current architecture/context;
- required bounded integrations;
- implementation requirements and traceable acceptance criteria;
- constraints and the complete prohibited-change set;
- allowed repositories/components/non-production targets;
- test obligations;
- rollback/recovery expectations for reviewable pre-deployment work;
- distinct client and Sekinfra approvals;
- a package digest and trusted attribution.

States are `DRAFT`, `RELEASED`, and `SUPERSEDED`.

```text
DRAFT -> RELEASED
RELEASED -> SUPERSEDED
```

Release requires an exact approved brief, a currently usable active `ImplementationAuthorization`, matching digests and targets, and separate active human approvals over the package digest. A released package remains non-authoritative: execution requires the separate usable implementation authorization. It contains no secret, credential, raw provider payload, deployment instruction, or production-change authority.

## Exact source-truth binding and correction

“Latest Finding,” “current Finding,” and “current delivery” references are forbidden. All diagnostic bindings use exact IDs, positive revisions, and content digests. The delivery uses its exact identity and sequence.

A corrected Finding or governed re-delivery never mutates a prior brief or package. A correction requires:

1. a new `ImplementationBrief` version with corrected exact bindings and `supersedes_implementation_brief_reference`;
2. new client and Sekinfra approvals over the new brief digest;
3. a new `ImplementationAuthorization` version and approvals when scope, targets, constraints, or authority change;
4. a new `CodexBuildPackage` version with its exact superseded-package reference and approvals.

`ReviseImplementationBrief`, `ReviseImplementationAuthorization`, and `ReviseCodexBuildPackage` require optimistic concurrency and exact superseded-version references. The old version becomes `SUPERSEDED` in the same future authoritative transaction; no body is patched or deleted. Client outcome, requirements, constraints, scope, and approved integrations follow the same rule. No generic patch command exists.

## Acceptance criteria and prohibited changes

Every acceptance criterion has a stable identity, a `BUSINESS`, `TECHNICAL`, or `SECURITY_COMPLIANCE` category, a specific statement, a testable verification method, approved scope-item references, and exact Finding revision/digest traceability. At least one business criterion is required. Metrics unsupported by evidence or approved outcome must not be invented.

The complete prohibited set is first-class and mandatory in the brief, authorization, and package:

- `OUT_OF_SCOPE_SYSTEM_CHANGE`
- `PERMISSION_WIDENING`
- `DATA_DELETION`
- `CREDENTIAL_ROTATION`
- `PRODUCTION_DEPLOYMENT`
- `PRODUCTION_CHANGE`
- `BILLING_CHANGE`
- `OUT_OF_SCOPE_NETWORK_CHANGE`
- `OUT_OF_SCOPE_SECURITY_CONTROL_CHANGE`

Omitting one is invalid. A package, capability, caller claim, or AI-generated draft cannot override the set.

## Human approval and AI boundary

Phase 5D-A adds exact roles `CLIENT_IMPLEMENTATION_AUTHORITY` and `PROVIDER_IMPLEMENTATION_AUTHORITY`. They are separate attributable `HumanApproval` records bound to the exact Phase 5D subject ID, version, and digest through `phase5d_authority`. Existing diagnostic and Phase 5C approvals retain their roles/bindings and cannot be reused.

Both roles approve final brief truth, the bounded implementation authorization, and final package release.

AI/Codex may summarize exact Findings, propose requirements and acceptance criteria, identify missing information, propose structure, and assist a draft submitted by a human or bounded internal service. `draft_assistance: AI_ASSISTED` is attribution, not authority.

AI/Codex may not invent scope, widen targets/actions, override approvals, convert assumptions to facts, grant access, activate authority, release itself, or authorize deployment. `N8N_ORCHESTRATOR`, `SCHEDULED_AUTOMATION`, provider adapters, and security automation are excluded from every Phase 5D-A command caller set.

## Commands, capabilities, and events

Principal means authenticated trusted execution context, never a payload role claim. Every accepted future command requires matching tenant/engagement, exact capability, schema validation, durable idempotency, and authoritative guards.

| Command | Caller | Capability | Result | Event |
|---|---|---|---|---|
| `DraftImplementationBrief` | HUMAN/internal service | `implementation_brief:draft` | `DRAFT` v1 | `implementation_brief.drafted` |
| `ReviseImplementationBrief` | HUMAN/internal service | `implementation_brief:draft` | new `DRAFT`; prior superseded | `implementation_brief.revised` |
| `RecordImplementationBriefApproval` | HUMAN exact role | `implementation_brief:approve` | approval record | `implementation_brief.approval_recorded` |
| `ApproveImplementationBrief` | internal service | `implementation_brief:approve` | `APPROVED` | `implementation_brief.approved` |
| `ProposeImplementationAuthorization` | HUMAN/internal service | `implementation_authorization:propose` | `PROPOSED` v1 | `implementation_authorization.proposed` |
| `ReviseImplementationAuthorization` | HUMAN/internal service | `implementation_authorization:propose` | new `PROPOSED`; prior superseded | `implementation_authorization.revised` |
| `RecordImplementationAuthorizationApproval` | HUMAN exact role | `implementation_authorization:approve` | approval record | `implementation_authorization.approval_recorded` |
| `ActivateImplementationAuthorization` | internal service | `implementation_authorization:activate` | `ACTIVE` | `implementation_authorization.activated` |
| `RevokeImplementationAuthorization` | HUMAN exact role | `implementation_authorization:revoke` | `REVOKED` | `implementation_authorization.revoked` |
| `DraftCodexBuildPackage` | HUMAN/internal service | `codex_build_package:draft` | `DRAFT` v1 | `codex_build_package.drafted` |
| `ReviseCodexBuildPackage` | HUMAN/internal service | `codex_build_package:draft` | new `DRAFT`; prior superseded | `codex_build_package.revised` |
| `RecordCodexBuildPackageApproval` | HUMAN exact role | `codex_build_package:approve` | approval record | `codex_build_package.approval_recorded` |
| `ReleaseCodexBuildPackage` | internal service | `codex_build_package:release` | `RELEASED` | `codex_build_package.released` |

There are 13 commands, 9 capabilities, and 13 lifecycle events. Events contain only bounded stage/state, subject IDs, approval ID, and superseded version—never a body, credential, raw payload, or deployment instruction.

## Readiness and read models

The tenant-bounded derived read models are:

- `ImplementationBriefReadinessView`
- `ImplementationAuthorizationStatusView`
- `CodexBuildPackageReadinessView`
- `Phase5DAuthorityProgressionView`

`IMPLEMENTATION_BRIEF_READY` requires exact source truth, accepted conversion, active agreement, valid commercial authority, usable ongoing access, active dual approvals, traceable scope/criteria, the complete prohibited set, and no offboarding.

`IMPLEMENTATION_AUTHORIZATION_READY` requires a ready brief, exact matching scope/targets/digests, active dual approvals, current commercial/access eligibility, and a valid time window. Usability additionally requires state `ACTIVE`.

`CODEX_BUILD_PACKAGE_READY` requires state `RELEASED`, a ready exact brief, usable exact implementation authorization, matching digests, active dual approvals, complete criteria/prohibited changes, and no offboarding.

No Phase 5D-A command accepts caller-declared `ready`, `active`, `usable`, `deployment_authorized`, or `production_change_authorized`.

## Idempotency, concurrency, and future atomicity

All 13 commands use the existing idempotency record and envelope. Exact replay returns `DUPLICATE`; changed semantics under the same reservation returns `CONFLICT`; stale expected version returns `VERSION_STALE`. Revision, approval, activation, revocation, and release require expected record version. Creation commands establish version 1 only.

Future runtime must commit authoritative writes, idempotency completion, immutable lifecycle events, and outbox rows in the existing UnitOfWork transaction. Revision atomically creates a new immutable version and marks the exact old version superseded. A rollback preserves none of the attempted transition.

No runtime, repository, database object, RLS policy, migration, n8n change, or website change is part of Phase 5D-A.

## Cross-phase protection

Phase 5D-A references but cannot target or mutate OIA evidence, observations, root causes, Finding revisions, Findings Deliveries, assessments, diagnostic grants, conversion, Agreement #2, commercial verification, ongoing grants, or offboarding. Its approval binding is distinct from Phase 5C. Phase 5B/C runtime registries remain unchanged.

## Cross-industry representability

Deterministic fictional fixtures use the same contracts for roofing/home-services inspection-to-dispatch validation, security-staffing coverage-request validation, and medical-office administrative intake validation without clinical data. Only bounded statements and opaque target/integration references vary. Authority, source binding, traceability, prohibited changes, approval, versioning, and deployment denial remain identical.

## Phase 5D-B runtime boundary

The next separately authorized batch may implement these frozen commands through the existing `CommandExecutor`, guard pipeline, UnitOfWork, repositories, events/outbox, idempotency, concurrency, tenant isolation, and local Postgres architecture.

That batch must not implement deployment authorization or production change. A later owner-reviewed architecture batch must separately decide a first-class `DeploymentAuthorization`. No deployment can occur merely because a brief, implementation authorization, or package exists.
