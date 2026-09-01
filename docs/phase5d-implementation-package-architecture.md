# Phase 5D-A/B — Implementation Brief, Authorization, and Codex Build Package Architecture

Status: frozen JSON Schema 2020-12 contracts; B1–B3 runtime and local persistence active
Scope: provider-neutral implementation truth, bounded non-production implementation authority, and an executor-ready Codex build package
Out of scope: provider internals, deployment authority, deployment operations, production change, credentials, n8n, website work, and remote infrastructure

## Purpose and authority progression

Phase 5D begins from one approved provider-neutral `ImplementationHandoff`. It answers what may be built, why it is justified, the exact limits, how correctness will be tested, and what must not change. Avuhz does not know the provider's methodology or private source records.

```text
ImplementationHandoff != ImplementationBrief
ImplementationBrief != ImplementationAuthorization
CodexBuildPackage != ImplementationAuthorization
ImplementationAuthorization != DeploymentAuthorization
CodexBuildPackage != DeploymentAuthorization
```

An approved handoff and brief describe governed truth; neither grants change authority. Only a separately active, exact `ImplementationAuthorization` permits its enumerated non-production build actions against its exact targets and validity window. A released package carries bounded instructions inside that authority and creates no new authority.

## Resource model

### ImplementationBrief

`ImplementationBrief` is versioned implementation truth for one tenant and engagement. It binds the exact approved `ImplementationHandoff` identity, positive version, and SHA-256 digest. It preserves the handoff's provider-neutral approved problem, desired outcome, scope, exclusions, constraints, context references, integrations, risks, requirements, acceptance criteria, prohibited changes, dependencies, assumptions/limitations, and opaque source traceability.

States are `DRAFT`, `APPROVED`, and `SUPERSEDED`.

```text
DRAFT -> APPROVED
APPROVED -> SUPERSEDED
```

`APPROVED` requires exact active client and provider human approvals over the same `implementation_brief_digest`. A draft or approval creates no access, implementation, deployment, production-change, or operations authority. Assumptions and limitations remain explicitly classified; a workload or caller cannot convert them into verified facts.

### ImplementationAuthorization

`ImplementationAuthorization` is a separate first-class authority identity. It binds:

- the exact approved `ImplementationBrief` identity, version, and digest;
- the brief's exact `ImplementationHandoff` identity, version, and digest;
- one authorized-scope digest;
- exact repositories, components, or non-production targets;
- a closed set of permitted build-action classes;
- the complete prohibited-action set;
- an effective time and expiry;
- distinct client and provider human approvals; and
- an implementation-authority digest and positive version.

Permitted actions are limited to bounded repository reads, code/test/documentation creation or modification, test execution, and non-production build artifacts. Deployment, production change, credential rotation, permission widening, deletion, billing changes, and out-of-scope network or security-control changes are prohibited.

States are `PROPOSED`, `ACTIVE`, `EXPIRED`, `REVOKED`, and `SUPERSEDED`.

```text
PROPOSED -> ACTIVE | REVOKED
ACTIVE -> EXPIRED | REVOKED | SUPERSEDED
```

Activation revalidates the exact approved brief and handoff bindings, scope digest, targets, complete prohibited set, both human approvals, validity window, tenant, and engagement. Revocation, expiry, supersession, source mismatch, digest mismatch, scope widening, or target mismatch makes the authorization unusable without rewriting history.

### CodexBuildPackage

`CodexBuildPackage` is an immutable, versioned executor-ready packet derived from one exact approved brief and one exact implementation authorization. It includes package identity/version, tenant/engagement, exact source references/digests, authorized build scope, problem/outcome/context, bounded integrations, requirements, acceptance criteria, constraints, prohibited changes, allowed targets, test obligations, rollback/recovery expectations, distinct client/provider approvals, trusted attribution, and a package digest.

States are `DRAFT`, `RELEASED`, and `SUPERSEDED`.

```text
DRAFT -> RELEASED
RELEASED -> SUPERSEDED
```

Release requires the exact approved brief, a currently usable exact authorization, matching scope/digests/targets, and separate active human approvals over the package digest. A released package remains non-authoritative. It contains no secret, credential, raw provider payload, deployment instruction, or production-change authority.

## Exact source binding and correction

Mutable-current or "latest" lookup is forbidden as historical authority. Every relationship uses an exact ID, positive version, and digest. A revised or revoked handoff never silently rebinds a brief, authorization, or package.

Correction requires:

1. a new `ImplementationHandoff` version from the source provider when approved source truth changes;
2. a new `ImplementationBrief` version with the exact predecessor and handoff bindings;
3. new client and provider approvals over the new brief digest;
4. a new `ImplementationAuthorization` version and approvals when authority changes; and
5. a new `CodexBuildPackage` version with exact predecessor/source bindings and approvals.

Old versions and approvals remain immutable. Revision commands require optimistic concurrency and exact superseded-version references; no generic patch command exists.

## Acceptance criteria and prohibited changes

Each acceptance criterion has a stable identity, bounded category, testable statement/method, scope-item references, and exact opaque source traceability. Unsupported metrics or evidence must not be invented.

The complete prohibited set is mandatory in the brief, authorization, and package:

- `OUT_OF_SCOPE_SYSTEM_CHANGE`
- `PERMISSION_WIDENING`
- `DATA_DELETION`
- `CREDENTIAL_ROTATION`
- `PRODUCTION_DEPLOYMENT`
- `PRODUCTION_CHANGE`
- `BILLING_CHANGE`
- `OUT_OF_SCOPE_NETWORK_CHANGE`
- `OUT_OF_SCOPE_SECURITY_CONTROL_CHANGE`

Prohibited changes always win. A package, capability, caller claim, or AI-assisted draft cannot override them.

## Human approval and AI boundary

`CLIENT_IMPLEMENTATION_AUTHORITY` and `PROVIDER_IMPLEMENTATION_AUTHORITY` are separate attributable `HumanApproval` records bound to the exact subject ID, version, and digest. They approve final brief truth, bounded implementation authority, and package release.

AI/workloads may summarize exact approved handoff truth, propose requirements/criteria, identify gaps, and assist drafts. `AI_ASSISTED` is attribution, not authority. They may not invent scope/evidence, widen targets/actions, override approvals, convert assumptions to facts, activate authority, release themselves, authorize deployment, or spoof a human role. `TrustedExecutionContext` is authoritative.

## Commands, capabilities, events, and atomicity

The frozen surface has 13 commands, nine capabilities, and 13 lifecycle events across brief drafting/revision/approval, authorization proposal/revision/approval/activation/revocation, and package drafting/revision/approval/release.

Every accepted command requires schema validation, trusted tenant/engagement/capability context, exact expected version where applicable, and durable idempotency. Exact replay returns `DUPLICATE`; changed semantics under the same reservation returns `CONFLICT`; stale expected version is boundedly rejected. Accepted transitions atomically persist authoritative state, idempotency, one schema-valid lifecycle event, and one `PENDING` outbox intent. Rejection leaves no success side effects.

## Read models and security

The tenant-bounded views are `ImplementationBriefReadinessView`, `ImplementationAuthorizationStatusView`, `CodexBuildPackageReadinessView`, and `Phase5DAuthorityProgressionView`. Readiness derives from exact authoritative records and cannot create authority. Deployment and production-change authority remain false throughout this boundary.

Contracts and records contain no secrets, raw credentials, authenticated connection strings, raw provider payloads, or unrestricted logs. PostgreSQL persistence uses the shared UnitOfWork, immutable history, tenant RLS, the trusted command-service identity, lifecycle events, and transactional outbox.

## Provider-neutral boundary and compatibility

Avuhz consumes only `ImplementationHandoff`; it has no active dependency on OIA, findings, diagnostic/commercial resources, provider roles, or company implementations. Source artifacts remain opaque public-contract references. The same core contracts represent unrelated industries through bounded policies, targets, criteria, and source references.

B1–B3 are active through the existing `CommandExecutor`, `TrustedExecutionContext`, UnitOfWork, repository ports, idempotency, events/outbox, Postgres persistence, and RLS. They do not perform a deployment or production change. Later Phase 5 resources remain separate exact records and cannot retroactively alter this history.
