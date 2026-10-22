# Gate10 WORM retention decision — Avuhz infrastructure LOCAL v1

Status: **DESIGN_CANDIDATE / OWNER_DECISION_PENDING / NO_PROVIDER_OPERATION**.
Release: **LOCAL_v1_NOT_CERTIFIED**; LOCAL v1 NOT CERTIFIED; release HOLD.
Classification: R0 DOC-ONLY; reviewer-ready recommendation, NOT OWNER APPROVAL.
Repository: `AnonymousKoo/avuhz-infra`; environment: LOCAL/TEST.
Provider namespace: NONE; responsibility: release-evidence custody design.
Action: repository-local creation of this memo only, dated October 21, 2026.
No account policy, credentials, storage, deployment or release authority is granted.

## Decision requested and evidence boundary

Conditionally recommend AWS S3 Object Lock COMPLIANCE for per-object-version WORM.
The owner must choose the target, retention period, separated roles and budget.
No AWS account, region, bucket, identity or existing capability is inferred.
This recommendation is not approval to provision, upload, lock or inspect accounts.
This memo closes none of the outstanding release gaps.

The exact Gate10 source is `3b0eadcae26f5695505a35a65775c9415b28b539`.
Observed verified run: `39700493187`, first attempt, exact signed wheel subject.
Independent attestation verification: attestation `58449920` succeeded.
These are recorded dossier observations, not fresh remote verification here.
Signed provenance succeeded; it is not a pending signing retry.
GitHub temporary artifact ID: `12393350895`.
Wheel: `avuhz_service-0.1.0-py3-none-any.whl`.
Wheel SHA256:
`9ddc983a7f8c432ebc7203c60491e1b9ca08ba719eba363e070aee935c93f2c1`.
Artifact ZIP SHA256:
`623bd5768e8a1ff68a7a4d7589b7a936410b8b2ba4e1ef09c40057207784ab61`.
The ZIP digest identifies archive bytes; it is not the signed wheel digest.
Artifact expires **November 21, 2026 at 00:44:54 UTC**.
The nominal 30-day GitHub retrieval window is not WORM.
Local copies, signatures and action summaries alone are not immutable custody.

Previously independently verified GitHub main: `4ee12d52e0c33d84587ce46c96c9c699d2945d39`.
Its documentation-updated tree: `5e6ca52e276d6e77299b022870ad02b8358eb63c`.
The preserved source tracked tree is `83735e94370fb7dc45720a28845d7d172b14bd49`.
That tree plus the preserved closure dossier reconstructs the supplied main tree.
Remote main was not contacted or refreshed during this LOCAL/TEST preparation.
No retrospective certification of documentation-updated main is claimed.
Custody preserves the exact signed subject; it does not change SHA or re-sign.

`cross_repo_suite_portable=false` remains unresolved.
Independent human security/SBOM review and owner certification remain pending.
Residual supply-chain risk disposition also remains a human review requirement.
WORM is a release-evidence requirement in the current closure dossier.
It does not supersede independent establishment of all normative local Gates 1–10.
Green Gate10 CI does not prove that all ten gates have passed.
Those gates describe the local fake authority journey, not a provider deployment.

## Options and reference basis

Official references below are checked as design references for October 2026.
This offline memo uses the supplied reference basis; URLs were not fetched here.
No actual deployments, effective permissions, prices or account policies are verified.

| Option | Design assessment | Decision posture |
|---|---|---|
| AWS S3 Object Lock COMPLIANCE | Per-version retention prevents shortening or deletion during retention, including by root. | Recommended conditionally; validate exact setup and readback. |
| Google Cloud Storage locked retention | Locked bucket retention, and applicable object retention, are possible candidates. Bucket retention-policy locking is irreversible. | Alternative needing separate capability, scope and cost review. |
| Azure immutable Blob policy | Potential time-based immutable retention/hold alternative. Exact policy scope and lock semantics need independent review. | Alternative only; no capability or price verification here. |
| Cloudflare R2 bucket locks | Official documentation allows bucket-rule editing/removal; effective permissions need independent verification. | Do not equate bucket locks with irreversible regulatory WORM. |

[AWS Object Lock overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
explains COMPLIANCE versus GOVERNANCE protection and object-version scope.
GOVERNANCE is not the final recommendation because bypass permission can defeat it.
[AWS configuration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html)
and [retention management](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html)
are the design basis for enabling locks, retention and legal holds.
[GCS retention-policy lock](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/lockRetentionPolicy)
is the supplied reference for irreversible bucket-policy locking, not proof of deployment.
[R2 bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/)
describes rule management; independently assess permissions before any WORM claim.
Azure needs independent official capability and cost review before selection.
No provider is selected by account discovery or an assumed existing subscription.

## Conditional AWS architecture

Prefer a dedicated evidence-only AWS account, subject to owner approval.
Alternatively, the owner may select a strongly isolated purpose-scoped bucket/account.
Isolation must be justified by effective access boundaries and independent review.
Choose the region only after owner selection and compliance/cost review.
Enable Object Lock at bucket creation and enable versioning in the proposed setup.
Require COMPLIANCE retention on every archived object version, including manifests.
A generic lifecycle policy is not a substitute for version retention metadata.
A bucket default alone is not proof: read back each actual version's effective state.

Review candidate: **365 calendar days**, NOT approved and not regulatory advice.
The owner must explicitly decide the actual period, start/end timestamps and mode.
An alternative period needs the same explicit decision and documented rationale.
Include legal holds, authorized hold management, expiry and eventual disposal policy.
A legal hold is separate from timed retention and needs its own removal controls.
COMPLIANCE retention cannot be shortened to recover from an accidental long period.
Do not enable irreversible retention until the exact approved scope is confirmed.

Use SSE-S3 only if the owner approves that encryption choice.
Otherwise review KMS key retention, recovery, administration and deletion lifecycle.
Cryptographic erasure can invalidate practical evidence availability despite a lock.
Keep required keys recoverable throughout retention and any approved legal hold.
No immutable IAM-policy claim is made: permissions and account controls can change.
Versioning protects individual versions; a new upload may create a new version.
Delete markers can hide a key's current view without deleting a protected version.
Version-ID retrieval and a separately retained index preserve exact-version discovery.

## Roles and privilege separation

Human policy/admin provisioning owns the approved configuration boundary.
The CI writer is upload-only to the designated evidence prefix.
Deny Delete and bypass authority; do not grant PutObjectRetention unless required,
explicitly justified, independently reviewed and separately authorized.
Prefer an approved bucket default supplying retention without writer lock-management.
Constrain any future workload trust to the exact approved repository/workflow identity.
The writer must not administer bucket policy, encryption keys or account controls.

An independent reader/verifier reads locked versions and retention metadata.
Grant narrowly scoped version listing as needed to verify the exact archive index.
Its identity must be distinct from the writer and provisioning administrator.
A separate human security reviewer assesses provenance, locks, SBOM and residual risk.
A separate human release approver decides acceptance after required proof exists.
No role assignment, principal identifier, secret or credential is created here.
STOP if identities, separation or effective least privileges cannot be established.

## Evidence preparation and manifest design

Collect the exact signed wheel and detached attestation bundle without executing them.
Retain the artifact ZIP if selected for custody, keeping its digest distinct.
Bind source SHA, workflow path/identity, run ID, attempt and artifact/attestation IDs.
Preserve dependency lock files, SBOM and concise verified provenance proof.
Review completeness and sensitivity before uploading; no secret or client payloads.
Do not invent an SBOM or human approval if the required evidence is unavailable.
Record missing evidence explicitly; its absence blocks acceptance where required.

Create a SHA-indexed manifest of actual bytes, sizes and sanitized reference names.
Include verification method, trusted issuer/workflow constraints and review status.
Record object version IDs, exact retention state and ETag when recorded.
S3 ETag is NOT SHA256 proof; compute SHA256 from independently retrieved bytes.
Provide manifest self integrity through a detached digest of canonical manifest bytes,
retained in an independent custody record; avoid circular self-hashing claims.
A version-index receipt may bind assigned version IDs to the initial manifest.
Lock that receipt too and retain its digest/version ID through independent custody.
Do not imply a mutable key name or an ETag is an immutable content identity.

This is one-time reference-evidence custody for the existing exact signed subject.
A repeatable future CI archival pipeline is a separate implementation milestone.
It needs reviewed trust, authorization, failure handling and independent verification.
This memo supplies no live Terraform, operational script or credential instructions.

## Owner decision register

Every value is PENDING; proposed architecture does not fill these approvals.

| Required decision | Owner entry / acceptance requirement |
|---|---|
| Account/project, isolation and region | PENDING — exact owner-selected AWS target and regional review. |
| Bucket and prefix | PENDING — exact evidence-only scope and namespace. |
| Object Lock at creation and versioning | PENDING — both enabled; verify actual configuration. |
| Actual retention length and mode | PENDING — explicit period/timestamps; COMPLIANCE candidate, 365 days unapproved. |
| Holds and expiry policy | PENDING — hold authority, review, disposal and escalation. |
| Writer/admin identities | PENDING — distinct principals, prefix scope and effective privileges. |
| Independent verifier and human reviewers | PENDING — reader, security reviewer and release approver separation. |
| Encryption / KMS lifecycle | PENDING — SSE-S3 approval or reviewed key availability/recovery. |
| Audit | PENDING — scope, access, retention and optional CloudTrail data events. |
| Cost and budget cap | PENDING — region/account pricing and approved spending limit. |
| Target date before artifact expiry | PENDING — owner date before November 21, 2026 00:44:54 UTC. |
| Verification/no-bypass and owner signoff | PENDING — exact proof criteria, approver identity and recorded decision. |

## Proof plan and acceptance conditions

Separately authorize each future boundary before any external implementation.
First inventory the approved account read-only; validate identities and capabilities.
Then authorize a disposable canary in a separate sandbox test boundary, no production.
Use only that SAFE canary to attempt denied delete, overwrite, shortening and bypass.
Distinguish a denied protected-version mutation from a permitted new-version upload.
Never test destructive operations on the signed evidence by default.
Record effective denial semantics and any unexpected privileges; failures mean STOP.

After exact archival authorization, record every uploaded object's version ID.
List versions and fetch exact metadata: mode, retain-until timestamp and hold state.
Require at least one independent readback by VERSION ID for every required object.
Hash actual retrieved bytes and compare SHA256 with the approved subject/manifest.
Verify the manifest, version-index receipt and detached integrity record consistently.
Record only sanitized version IDs, digests, timestamps and bounded proof outcomes.
Upload success alone is insufficient; missing readback or mismatched bytes means STOP.
Optional CloudTrail data events need separate cost, permissions and owner approval.
Audit logging supports investigation; it does not replace lock or digest proof.

## Risks, cost and four-lane assessment

Retention mistakes can create irreversible storage obligations and block deletion.
Expiry before archival, key loss, hidden keys and privilege drift threaten custody.
Cost model: stored bytes in GB-month × price + PUT/GET/LIST requests + transfer
+ optional audit/key charges; include retained versions and retrieval verification.
No amounts are invented; compare cheapest suitable options only after account/region
and required protection, retention, access and audit scope are known.
Security owns separation and exact-subject trust; Infrastructure owns lock/readback.
Automation owns bounded future handoff; it receives no current execution authority.
Business owns cost and acceptance; this effort competes with first-client discovery.
No intake, tenant, billing, communications or deployment authority follows from it.

## Internal basis and next safe milestone

Read with `contracts/proposals/v1/gate10-exact-merge-worm-integration-plan.md`
and `contracts/proposals/v1/local-v1-gate10-exact-commit-evidence-closure-20261021.md`.
`AVUHZ_V1_COMPLETION.md` governs normative Gates 1–10 and their local fake journey.
`docs/local-v1-python-lock.md` bounds platform/lock evidence, not human SBOM approval.
Next: owner reviews provider choice, period and role separation in this register.
Then separately authorize read-only inventory, then sandbox canary, then the exact
approved archival operation with independent readback, then independent human acceptance.
STOP on unmet identities/privileges, ambiguous targets, mismatches or missing authority.
Release remains **NOT CERTIFIED**; a WORM design memo alone closes no release gap.
