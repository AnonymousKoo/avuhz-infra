# Phase 5D-C -- Build, QA, Acceptance, and Deployment Authority Architecture

Status: frozen architecture and JSON Schema 2020-12 contract boundary
Scope: exact build execution truth, governed QA truth, explicit client acceptance, and bounded deployment authorization
Out of scope: runtime, repositories, persistence, migrations, RLS, deployment execution, credentials, n8n, website work, and remote Supabase

## 1. Normative authority chain

The following resources are distinct and non-substitutable:

```text
AssessmentAccessGrant
!= OngoingAccessGrant
!= ImplementationAuthorization
!= CodexBuildPackage
!= DeploymentAuthorization
```

Progression is also non-substitutable:

```text
CodexBuildPackage RELEASED != build completed
build completed != QA passed
QA passed != client accepted
client accepted != deployment authorized
DeploymentAuthorization ACTIVE != deployment completed
```

No earlier record, state, boolean, caller assertion, or read-model projection creates a later authority. Every historical binding uses an exact identity, version, and digest; "latest" lookup is forbidden.

## 2. Frozen contract surface

This batch defines exactly four resources, nine commands, eight capabilities, nine lifecycle events, and five derived read models. All are provider-neutral JSON Schema 2020-12 contracts. They are intentionally absent from runtime registries.

| Resource | Purpose | Frozen states |
|---|---|---|
| BuildExecutionResult | Immutable attempt against one released package | IN_PROGRESS, SUCCEEDED, FAILED |
| QAResult | Immutable criterion-by-criterion test result | PASSED, FAILED, BLOCKED |
| ClientAcceptance | Attributable client-human decision | ACCEPTED, REJECTED |
| DeploymentAuthorization | Exact, dual-human governed deployment authority | PROPOSED, ACTIVE, EXPIRED, REVOKED, SUPERSEDED |

## 3. BuildExecutionResult

A build attempt binds tenant and engagement to one exact RELEASED CodexBuildPackage and its exact ImplementationAuthorization. It records execution identity, attempt/version, changed repositories/components, opaque artifact and source-commit references, bounded test-result references, failure/correction state, trusted workload or human attribution, timestamps, and a digest.

A successful result means only that the exact build attempt completed. It is not QA truth, client acceptance, deployment authority, or proof that deployment occurred. A failed attempt is immutable. Correction creates a later attempt with an exact supersedes reference; it never rewrites the failed record or silently rebinds sources.

## 4. QAResult

QA binds one exact BuildExecutionResult, package identity/version/digest, and the complete acceptance-criterion set from that package version. Every criterion has its stable identifier, package version, one result from PASS, FAIL, or BLOCKED, and bounded evidence/provenance references.

Overall status is derived: PASSED only when every criterion is PASS; FAILED when any criterion is FAIL; otherwise BLOCKED when no criterion fails and at least one is BLOCKED. Generic `qa_passed` claims are prohibited. Failure and blocked history are immutable. A correction requires a new build when the artifact changed and always requires a new QA result with an exact supersedes reference.

## 5. ClientAcceptance

ClientAcceptance is a separate CLIENT HUMAN decision over the exact package digest, build result, artifact digest, and QA result. TrustedExecutionContext supplies the human identity and role `CLIENT_ACCEPTANCE_AUTHORITY`; payload role or approval claims are non-authoritative.

WORKLOAD/AI cannot accept for the client. Acceptance does not authorize deployment. It becomes stale when the package, artifact/build result, criterion set, or QA result changes or is superseded. A later decision is a new immutable version and never changes earlier history.

## 6. DeploymentAuthorization

DeploymentAuthorization is separate from ImplementationAuthorization and CodexBuildPackage. It requires an ACTIVE exact ImplementationAuthorization, the exact RELEASED package, a SUCCEEDED exact build, a PASSED exact QA result, exact ACCEPTED client acceptance where required, and separate approvals from CLIENT and SEKINFRA humans.

The authorization binds one exact artifact identity/version/digest, target environment, target resources, permitted deployment actions, prohibited actions, rollback/recovery requirements, validity window, record version, digest, and immutable history. Permitted actions are only `DEPLOY_EXACT_ARTIFACT` and `ROLLBACK_EXACT_ARTIFACT`. Prohibited actions always win: artifact substitution, target or environment widening, permission widening, credential rotation, data deletion, billing changes, unauthorized production change, and out-of-scope network or security-control changes.

An ACTIVE authorization grants no blanket production authority. It applies only to the exact artifact, environment, targets, action, and validity window approved. `deployment_allowed` and similar generic claims have no authority. Expiry and revocation are terminal historical facts; replacement requires a new exact version. No deployment execution is designed or performed here.

## 7. Commands, capabilities, and events

| Command | Caller | Capability | Event |
|---|---|---|---|
| StartBuildExecution | HUMAN or INTERNAL_SERVICE | build_execution:start | build_execution.started |
| CompleteBuildExecution | HUMAN or INTERNAL_SERVICE | build_execution:complete | build_execution.completed |
| RecordQAResult | HUMAN or INTERNAL_SERVICE | qa_result:record | qa_result.recorded |
| RecordClientAcceptance | HUMAN only | client_acceptance:record | client_acceptance.recorded |
| ProposeDeploymentAuthorization | HUMAN or INTERNAL_SERVICE | deployment_authorization:propose | deployment_authorization.proposed |
| ReviseDeploymentAuthorization | HUMAN or INTERNAL_SERVICE | deployment_authorization:propose | deployment_authorization.revised |
| RecordDeploymentAuthorizationApproval | HUMAN only | deployment_authorization:approve | deployment_authorization.approval_recorded |
| ActivateDeploymentAuthorization | INTERNAL_SERVICE only | deployment_authorization:activate | deployment_authorization.activated |
| RevokeDeploymentAuthorization | HUMAN only | deployment_authorization:revoke | deployment_authorization.revoked |

Completion, deployment revision, approval, activation, and revocation require an expected record version. Initial immutable result/decision creation uses exact source bindings and uniqueness; later versions carry exact supersedes references. Idempotency reservation semantics remain DUPLICATE for exact replay and CONFLICT for changed semantics.

## 8. Human and AI boundary

The roles are `CLIENT_ACCEPTANCE_AUTHORITY`, `CLIENT_DEPLOYMENT_AUTHORITY`, and `PROVIDER_DEPLOYMENT_AUTHORITY`. Client acceptance is its own record; deployment approval uses separate attributable HumanApproval records from both organizations.

WORKLOAD/AI may execute released package tasks, run tests, record bounded evidence, draft summaries, propose authorization text, and suggest corrections. It may not approve itself, invent test success, accept for a client, widen implementation scope, authorize deployment or production change, change targets, override prohibited actions, or spoof a role. TrustedExecutionContext is authoritative.

## 9. Failure, correction, and stale-source rules

- Build failure remains FAILED; rebuild creates a new attempt.
- QA FAIL or BLOCKED remains historical; retest creates a new QA result.
- Package revision requires a new build and invalidates downstream QA, acceptance, and deployment authority.
- Changed acceptance criteria require new QA and downstream acceptance.
- Changed artifact requires new build, QA, acceptance, and authorization.
- Revoked, expired, or invalid ImplementationAuthorization blocks progression and activation; history remains readable.
- Superseded build or QA makes downstream acceptance stale.
- Stale acceptance cannot activate deployment authority.
- Expired or revoked DeploymentAuthorization cannot be reactivated; replacement is a new version.
- No rule resolves a prerequisite using mutable current or "latest" state.

Accepted transitions must eventually use the existing command executor, trusted context, UnitOfWork, idempotency, lifecycle event, transactional outbox, and persistence architecture, but no such runtime is implemented in this batch.

## 10. Read models

The five projections are BuildExecutionStatusView, QAResultStatusView, ClientAcceptanceStatusView, DeploymentAuthorizationStatusView, and Phase5DDeliveryProgressionView. They expose exact source versions and staleness/revocation flags. They cannot accept generic success or authority claims and never become authoritative records.

## 11. Security negatives

Contracts reject raw credentials, secret fields, unrestricted provider payloads, caller-supplied `qa_passed`, caller-supplied `deployment_allowed`, payload approval roles, wrong source types, and malformed digests. Semantic validation rejects wrong package/build/QA/artifact/target binding, stale prerequisites, revoked ImplementationAuthorization, scope widening, prohibited deployment actions, WORKLOAD acceptance or deployment approval, and role spoofing.

Opaque bounded artifact, evidence, and capability-handle references may be retained. Raw secret material, authenticated connection strings, provider payloads, and production credential runtime are prohibited.

## 12. Cross-industry representability

The same contracts represent roofing/home services, security staffing, and medical-office operations using only bounded targets, criteria, artifacts, and evidence. No core field assumes a vertical, provider, repository host, deployment platform, or secret format.

## 13. Compatibility and runtime boundary

Phase 5B, Phase 5C, Phase 5D-A, Phase 5D-B1, Phase 5D-B2, and Phase 5D-B3 vocabularies remain additive and unchanged. Existing runtime schema registries intentionally remain unchanged. The recommended first runtime resource is BuildExecutionResult. DeploymentAuthorization runtime, deployment execution, production credential handling, production changes, remote Supabase, n8n, and website work remain outside this batch.
