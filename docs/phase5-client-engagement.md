# Phase 5 — Client Engagement Eligibility and Assessment Authority

## Mission and starting state

Phase 5 turns an approved diagnostic scope into a governed client engagement without treating scope approval as access authority. Post-Phase-4 authoritative records are AcquisitionHandoff, Engagement, DiagnosticScope, and HumanApproval. None proves a diagnostic agreement, payment satisfaction, or assessment access.

## Frozen boundaries

- **5A — Diagnostic eligibility and assessment authority/access:** verified diagnostic agreement authority, future provider-neutral diagnostic payment verification, and the future AssessmentAccessGrant eligibility and access boundary.
- **5B — OIA execution, evidence, and findings:** execute only within a valid assessment grant; record evidence and findings. It creates no ongoing authority.
- **5C — Conversion and ongoing eligibility:** conversion decision, Agreement #2, and separately governed ongoing authority/access.
- **5D — Implementation Brief / Codex Build Package:** a first-class package containing verified problem, desired outcome, current-system map, constraints, approved scope, integrations, access level, risks, requirements, acceptance criteria, and explicit prohibited changes.

## Agreement #1 and payment

`DiagnosticAgreementAuthority` is the first Phase 5 resource. It is the authoritative record that the diagnostic/OIA agreement has been verified. It has a tenant and engagement binding, a closed `DIAGNOSTIC_OIA` agreement type, opaque agreement reference, closed authority status, exact versioned DiagnosticScope reference and canonical scope digest, effective/end times, verified/recorded times, and record version. It deliberately does not contain a contract PDF, signature, provider payload, payment fact, credential, ongoing Agreement #2, or production-change authority.

`DiagnosticPaymentVerification` is now the separate authoritative payment fact. It is tenant- and engagement-scoped and binds one exact versioned `DiagnosticAgreementAuthority`; it therefore cannot be reused across tenants, engagements, or unrelated agreements. Its closed purpose is `DIAGNOSTIC_OIA`, and its provider-neutral opaque reference identifies only the externally observed payment fact.

Its minimal lifecycle is `VERIFIED` or `INVALIDATED`. `INVALIDATED` requires an invalidation timestamp and retains historical evidence; it no longer satisfies the commercial gate. The contract records a required positive `amount_minor` integer and uppercase three-letter currency code. This captures the verified payment amount without inventing an agreement-derived expected amount; future commercial logic must establish any matching requirement. No floats, payment instruments, billing PII, provider payload, checkout data, webhook data, or secrets are permitted. A future adapter may translate provider callbacks into this authoritative result without retaining raw callback JSON.

## Assessment eligibility and access boundary

A future AssessmentAccessGrant may be created or approved only when all predicates hold: the Engagement is eligible/active; DiagnosticScope is `SCOPE_APPROVED`; its canonical digest exists; the exact scope/version binding matches; a required `DiagnosticAgreementAuthority` is currently `VERIFIED_ACTIVE` and valid; and the required diagnostic payment verification is verified. Scope approval alone never creates access.

Assessment access is diagnostic-only, temporary, read-only/non-destructive by default, and limited to the exact scope, digest, permitted action set, and bounded target systems. It cannot widen authority, cannot contain raw credential material, and requires explicit access verification plus explicit revocation/expiration. The permitted and prohibited diagnostic-action vocabularies remain unchanged from Phase 4.

Maximum TTL is 30 calendar days from successful access verification. It ends immediately, without grace period, on the earliest of findings delivery, assessment/OIA closure, agreement end, explicit revocation, or TTL expiry. Extension requires new client and Sekinfra authorization. Assessment access is distinct from future ongoing access.

## Credential separation

Raw credentials are prohibited from commands, business records, events, outbox, logs, reports, documentation, Git, and normal API payloads. A future grant may reference a secure credential mechanism only by opaque reference; authorization metadata is not credential material.

## Deferred work

No Phase 5B, 5C, or 5D resource is implemented here. No migration, Postgres repository, remote Supabase operation, provider integration, or runtime command execution is included. The authority-contract prerequisite is complete; future access-grant runtime commands must consume both exact assessment approvals and the complete commercial eligibility chain.

## Assessment access authority

`AssessmentAccessGrant` is the separate, authoritative, temporary diagnostic-only authority. Scope approval, agreement authority, and payment verification never equal access. The grant binds one tenant and engagement, exact versioned DiagnosticScope reference, canonical scope digest, action-set version, exact DiagnosticAgreementAuthority reference, and exact DiagnosticPaymentVerification reference. It binds one or more opaque in-scope system references and only the frozen permitted diagnostic actions; future runtime must prove targets are in scope and actions are a subset of that exact approved scope.

Its complete closed state model is `APPROVED`, `ACTIVE`, `EXPIRED`, `REVOKED`, and `CLOSED`. `APPROVED` exists but is not usable access. `ACTIVE` requires successful `verified_at`, with `active_from` equal to that verification time. `EXPIRED` retains verified access history after its usable period ends. `REVOKED` requires `revoked_at`. `CLOSED` requires `closed_at` and exactly one closed reason: `FINDINGS_DELIVERED`, `ASSESSMENT_CLOSED`, or `AGREEMENT_ENDED`.

Future runtime must enforce a maximum TTL of 30 calendar days from successful verification, with no grace period or silent extension. The earliest of findings delivery, assessment closure, agreement end, explicit revocation, or expiry terminates authority. Extension requires separate future client and Sekinfra authorization. Assessment access cannot become ongoing, implementation, deployment, or managed-operations access.

The grant deliberately holds no credential or credential reference. Credential/access provisioning is a separate future resource. A payment invalidation or invalid/expired/revoked agreement makes an otherwise ACTIVE grant unusable and requires termination through future runtime workflow.


## Trusted commercial authority ingress

Agreement authority, payment verification, and payment invalidation now enter the in-memory runtime only through trusted Avuhz execution with narrow diagnostic-agreement/payment capabilities. The runtime derives tenant, scope digest, commercial status, timestamps, versions, and cross-resource bindings from authoritative state.

Trusted provider adapters, authorized Sekinfra humans for supported manual cases, and tightly authorized internal workloads may use this boundary. Browsers, arbitrary n8n workflows, unverified webhooks, and direct database writes cannot establish or alter commercial truth. n8n is only a bounded client of the trusted command boundary.

Ingress stores normalized opaque references only. It excludes agreement documents, raw provider callbacks, payment instruments, credentials, tokens, and metadata escape hatches. Payment invalidation immediately makes ACTIVE access unusable through the existing safety gate; its persisted grant-terminal mapping intentionally remains unresolved.
Before this batch, `HumanApproval` was exclusively bound to `DIAGNOSTIC_SCOPE`; the assessment-access branch below resolves that contract prerequisite without changing the existing Phase 4 command. Future runtime tests must enforce: tenant and engagement equality across grant/scope/agreement/payment; approved scope status; exact digest and action-set binding; payment `VERIFIED`; agreement validity; in-scope targets; action subset; verification-before-active; 30-day TTL; terminal-state denial; and no authority-tier widening.

## Assessment access human approval

`HumanApproval` now has two closed, mutually exclusive subject families: `DIAGNOSTIC_SCOPE` and `ASSESSMENT_ACCESS_GRANT`. The DiagnosticScope branch preserves its exact scope/version/digest/action-set binding unchanged. The assessment branch binds the exact grant ID and its `assessment_access_authority_digest`; neither branch may carry the other branch's binding fields.

The digest is server-derived from canonical compact UTF-8 JSON and SHA-256 over the immutable authority projection: grant, tenant, engagement, exact scope/version/digest/action-set binding, exact agreement and payment references, target system references, and permitted actions. Object keys are sorted; target and action collections are sorted semantic sets and duplicates are rejected. The digest excludes status, verification, activation, expiry, revocation, closure, and record version, as well as credentials, secrets, and provider payloads. An immutable-authority change produces a new digest and requires new exact CLIENT and SEKINFRA approval; lifecycle transition alone does not.

Assessment authority requires separate active `CLIENT_DECISION_AUTHORITY` and `SEKINFRA_ENGAGEMENT_AUTHORITY` approvals for the same tenant, grant, and authority digest. Future persistence/runtime must reject a duplicate active approval for that binding and role. Human approval never overrides commercial validity: invalidated payment or invalid agreement prevents authorization/use through separate cross-resource checks.

The existing `RecordHumanApproval` command remains DiagnosticScope-only. The recommended next command contract is a new narrow `RecordAssessmentAccessApproval`, preserving the frozen Phase 4 scope command, trusted execution-context attribution, and workload-forgery protections. No credential provisioning is implied.

## Assessment approval command contract

`RecordAssessmentAccessApproval` is a new non-executable command contract for one trusted human approval of an `ASSESSMENT_ACCESS_GRANT`. It requires `assessment_access:approve`, a HUMAN trusted context, and exact trusted-role matching; workloads fail even with that capability. Its only payload fields are grant ID and authority role. The digest and all authority content, identity, organization, tenant authority, and capabilities are rejected from payload and must be resolved server-side. Two independent commands are required. Future event: `assessment_access.approval_recorded`.

`RecordHumanApproval` remains DiagnosticScope-only. The current authoritative AssessmentAccessGrant begins at `APPROVED`, so a truthful pre-approval proposed-authority source is not yet modeled: `ASSESSMENT_ACCESS_APPROVAL_SOURCE_READY = NO`. The next batch must define the narrow immutable proposed-authority resource/state and its read path before handler/persistence work. Idempotency needs a future database CHECK vocabulary extension; none is made here.

## Assessment access proposal authority

`AssessmentAccessProposal` is the immutable pre-grant authority source: Proposal ≠ Grant; approval of a proposal ≠ usable access; Grant ≠ ACTIVE access. Its OPEN, SUPERSEDED, WITHDRAWN, and CONSUMED lifecycle prevents stale issuance. Proposal authority contains exact scope/commercial bindings, targets, actions, and a server-derived digest; lifecycle facts and credentials are excluded. HumanApproval and `RecordAssessmentAccessApproval` now bind proposal ID plus digest, never a future grant ID or caller-supplied digest. Future server lookup is tenant plus OPEN proposal. The next sequence is proposal creation, approval recording, finalization/grant issuance, then technical verification.


AssessmentAccessProposal is now the authoritative proposal source. Its content digest excludes proposal and grant identity; AssessmentAccessGrant retains a required versioned source-proposal reference. Future runtime must require OPEN proposal, tenant-scoped read, exact dual approvals, and equality of proposal/grant immutable authority and digest. Historical non-OPEN proposals remain readable.
## Dual approval grant prerequisite

`evaluate_assessment_access_dual_approval` is a provider-neutral, read-only predicate over the authoritative tenant-scoped proposal and HumanApproval records. It is satisfied only when the proposal is `OPEN` and it has one attributable ACTIVE CLIENT approval and one attributable ACTIVE SEKINFRA approval bound to that same proposal ID and server-derived authority digest. It creates no finalization state, event, outbox record, or grant.

Future `IssueAssessmentAccessGrant` must require: OPEN proposal, this predicate satisfied, current `evaluate_assessment_eligibility(...).eligible`, and exact proposal/grant immutable-authority equality. Only successful future grant issuance may consume the proposal (`OPEN` to `CONSUMED`).



Commercial eligibility is now evaluated in memory from authoritative Engagement, approved canonical scope, valid DiagnosticAgreementAuthority, and VERIFIED DiagnosticPaymentVerification. Future trusted ingress commands are `RecordDiagnosticAgreementAuthority` and `RecordDiagnosticPaymentVerification`; neither may accept untrusted browser, n8n, or caller authority claims.

## Technical assessment access verification

`APPROVED` means authority is issued but technical access is not active. `VerifyAssessmentAccess` accepts only a grant ID; success, timestamps, credentials, provider responses, and evidence are server-derived or forbidden. A trusted verifier receives only the grant's non-secret authority facts and returns sanitized per-target outcomes.

Successful verification of every target for the exact permitted actions transitions the same grant to `ACTIVE`; `verified_at` equals `active_from`. `expires_at` is the earlier of verification time plus 30 calendar days and a precisely represented earlier agreement `ends_at`, with no grace. Failed verification leaves the grant `APPROVED` and retryable while authority remains valid. Credentials remain behind the provider/vault boundary and never enter business records, commands, events, outbox, logs, or fixtures.

## Active assessment access usability safety gate

Persisted `ACTIVE` is not technical-use authority by itself. Every future credential, vault, provider, or target-system operation must call `evaluate_assessment_access_usability` immediately before its secure boundary. If unusable, that boundary must not execute.

The evaluator is read-only and fails closed: access is denied when the grant is not `ACTIVE`, trusted time is before `active_from`, trusted time is at or after `expires_at` (no grace), commercial authority is invalid, or exact authority binding mismatches. This denial is immediate even before persisted lifecycle reconciliation changes status to `EXPIRED`, `REVOKED`, or `CLOSED`.

Expiry, agreement end, and payment invalidation are currently authoritatively verifiable. Explicit revocation requires a future trusted command. `FINDINGS_DELIVERED_CLOSURE_SOURCE_READY = NO` and `ASSESSMENT_CLOSED_CLOSURE_SOURCE_READY = NO`: no first-class Phase 5B lifecycle truth exists yet. Payment invalidation has no frozen terminal-state/reason mapping (`CLOSED` reasons are findings delivery, assessment closure, and agreement end); a future lifecycle-model decision is needed for persisted reconciliation, while usability already denies it immediately.
## Terminal lifecycle reconciliation

Runtime usability denial remains immediate and independent of lifecycle persistence. Current truthful reconciliation is narrow: `ACTIVE` at/after `expires_at` may become `EXPIRED`; explicit trusted revocation may move `APPROVED` or `ACTIVE` to `REVOKED`; and server-resolved diagnostic agreement end may move `APPROVED` or `ACTIVE` to `CLOSED` with `AGREEMENT_ENDED`.

Payment invalidation remains immediately unusable with no persisted terminal mapping. Findings delivered and assessment closure remain future Phase 5B authoritative triggers; no caller-selected closure reason is accepted.
