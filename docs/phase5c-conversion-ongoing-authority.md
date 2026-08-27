# Phase 5C — Conversion and Ongoing Authority

Status: frozen architecture and JSON Schema 2020-12 contract boundary
Scope: conversion after governed findings delivery, Agreement #2, bounded ongoing commercial authority, a new ongoing access grant, and offboarding
Out of scope: runtime handlers, repositories, database schema/RLS, implementation design, deployment authority, managed operations, n8n, and website work

## Purpose and invariants

Phase 5C starts from one authoritative immutable `OIAFindingsDelivery`. It answers whether the client and Sekinfra will form a bounded ongoing relationship and whether Avuhz has a currently usable access channel for that relationship.

Authority expands only as the engagement expands. The following are normative inequalities:

```text
conversion accepted != ongoing agreement active
ongoing agreement active != ongoing commercial condition verified
commercial condition verified != ongoing access approved or active
ongoing access active != implementation authorized
implementation authorized != deployment authorized
deployment authorized != managed-operations authority
AssessmentAccessGrant != OngoingAccessGrant
```

No non-response, payment, access setup, or caller payload claim implies acceptance. Every authoritative identifier, tenant, engagement, version, digest, time boundary, approval, and target correlation is checked by the future trusted command service.

## Resource model

### OIAConversionDecision

`OIAConversionDecision` is authoritative client decision history for exactly one tenant, engagement, `OIAAssessment`, and immutable `OIAFindingsDelivery` sequence and manifest digest. A `PROCEED` decision binds exact delivered Finding IDs, revisions, and content digests; `DECLINE` binds an empty selection.

States are `PENDING_SEKINFRA`, `ACCEPTED`, and `DECLINED`.

- `PROCEED` initially records the client decision as `PENDING_SEKINFRA`.
- Sekinfra acceptance, under `SEKINFRA_ENGAGEMENT_AUTHORITY`, moves it to `ACCEPTED`.
- `DECLINE` is immediately terminal and never implies Sekinfra acceptance.
- `ACCEPTED` and `DECLINED` are immutable decision versions. A later governed decision is a new version linked by `supersedes_decision_reference`.

Client decision authority is a separate active `HumanApproval` bound to the conversion authority digest and attributable to `CLIENT_DECISION_AUTHORITY`. Sekinfra acceptance is a distinct `HumanApproval` attributable to `SEKINFRA_ENGAGEMENT_AUTHORITY`.

This resource creates no agreement, payment, access, implementation, deployment, or operations authority.

### OngoingAgreementAuthority

`OngoingAgreementAuthority` is Agreement #2 authority. It binds the accepted conversion decision, exact delivery, exact selected Finding revisions, service areas, intervention categories, target references, commercial boundaries, exclusions, effective term, immutable scope digest, and separate client and Sekinfra approvals.

States are `DRAFT`, `ACTIVE`, `SUPERSEDED`, `ENDED`, `TERMINATED`, and `REVOKED`.

```text
DRAFT -> ACTIVE
ACTIVE -> SUPERSEDED | ENDED | TERMINATED | REVOKED
```

Terminal states never return to `ACTIVE`. An authoritative version is never rewritten. A material scope change creates a new version or amendment with an exact superseded-version reference. Historical versions remain reproducible.

Agreement scope states what Sekinfra may commercially continue working on. It may select all or a subset of delivered Finding revisions and bounded intervention classes. It cannot contain technical designs, code, workflows, production change instructions, deployment sequences, acceptance criteria, credentials, or provider payloads.

### OngoingPaymentVerification

`OngoingPaymentVerification` proves one bounded commercial condition for one exact active Agreement #2 version. Its basis is `PAYMENT`, `RETAINER`, or `APPROVED_COMMERCIAL_COVERAGE`; every basis has explicit `coverage_from` and `coverage_until`.

States are `VERIFIED` and `INVALIDATED`. Payment and retainer verifications require amount in minor units and ISO currency, but never payment instrument data. The evidence reference is sanitized and opaque. Card data, bank credentials, tokens, secrets, and raw provider payloads are forbidden.

Current commercial validity is true only when the engagement is active, the conversion is accepted, the exact agreement version is active and in term, the verification is `VERIFIED`, server time is inside its coverage period, and all bindings match. It is never perpetual.

### OngoingAccessGrant

`OngoingAccessGrant` is a new authority record with a new identity and an ongoing commercial basis. There is no command that converts, extends, upgrades, widens, reuses, or changes an `AssessmentAccessGrant` into an `OngoingAccessGrant`.

It binds exact conversion, Agreement #2 version, commercial verification, service-scope digest, targets, access channel, effective time, review boundary, expiry, approval digest, and trusted attribution. Its sole purpose is `ONGOING_SERVICE_CHANNEL`.

States are `PROPOSED`, `APPROVED`, `ACTIVE`, `EXPIRED`, `REVOKED`, and `CLOSED`.

```text
PROPOSED -> APPROVED
APPROVED -> ACTIVE | REVOKED | CLOSED
ACTIVE -> EXPIRED | REVOKED | CLOSED
```

`APPROVED` is unusable. Activation requires trusted technical verification and a fresh server-side revalidation of tenant, engagement, accepted conversion, exact active agreement, current commercial coverage, approvals, scope digest, target boundaries, grant time bounds, and absence of offboarding.

The authoritative usability predicate is:

```text
grant.state == ACTIVE
and engagement is active
and conversion.state == ACCEPTED
and agreement exact version is ACTIVE and in term
and commercial verification exact version is VERIFIED and currently covered
and agreement/grant scope digests match
and requested target is inside both agreement and grant
and active_from <= server_time < expires_at
and no offboarding is active
and grant is not revoked or closed
```

Commercial invalidation makes the grant unusable immediately through this predicate even before a later terminalization command records `CLOSED`. Historical grant state is preserved. No active access channel authorizes create, modify, delete, deploy, restart, rotate, permission change, configuration change, production change, or any other consequential implementation action.

Manual authorized or emergency security revocation moves the grant to `REVOKED` and makes it unusable immediately. It does not itself terminate the agreement or alter diagnostic history.

### Diagnostic and ongoing grant separation

The grants have different identities, authority bases, commercial bases, scopes, lifecycles, time bounds, and terminal histories.

- `AssessmentAccessGrant` is temporary diagnostic authority based on the diagnostic agreement/payment and assessment scope.
- `OngoingAccessGrant` is ongoing-channel authority based on accepted conversion, Agreement #2, current ongoing commercial verification, and its own approvals.
- Exact delivery and Finding history remain unchanged.
- No Phase 5C schema accepts an AssessmentAccessGrant ID as its ongoing grant identity or authority reference.
- Terminalization of either grant does not rewrite the other.

### OngoingOffboarding and revocation verification

`OngoingOffboarding` is a non-destructive authoritative history with reasons `CONVERSION_DECLINED`, `AGREEMENT_ENDED`, `CLIENT_TERMINATION`, `SEKINFRA_TERMINATION`, and `ENGAGEMENT_COMPLETED`. There is no arbitrary reason.

States are `INITIATED`, `ACCESS_REVOCATION_PENDING`, and `COMPLETED`.

```text
INITIATED -> COMPLETED
INITIATED -> ACCESS_REVOCATION_PENDING -> COMPLETED
```

Initiation immediately makes ongoing eligibility false. It does not assert that an external access channel has been removed. When access removal is required, completion requires immutable `OngoingAccessRevocationVerification` records covering the affected grants. Verification results are `ACCESS_REMOVAL_VERIFIED` and `ACCESS_ALREADY_ABSENT`; a request to revoke is not verification.

Completion preserves diagnostic records, findings deliveries, decisions, agreements, commercial verifications, grants, approvals, events, outbox history, and revocation evidence. Offboarding denies future ongoing access and future Phase 5D eligibility. It performs no destructive cleanup.

## Command and authority matrix

Principal means authenticated trusted execution context, never payload-declared identity. Every accepted command requires matching tenant membership, exact capability, idempotency reservation, and authoritative state. `CLIENT` and `SEKINFRA` columns identify separate `HumanApproval` requirements.

| Command | Principal | Capability | CLIENT | SEKINFRA | Required current state | Result | Event | Access effect | AI/workload |
|---|---|---|---|---|---|---|---|---|---|
| RecordOIAConversionDecision | HUMAN client authority | `conversion:decide` | required | no | governed delivery; compatible assessment | pending or declined decision | `conversion.decision_recorded` | none | prohibited |
| AcceptOIAConversion | HUMAN Sekinfra authority | `conversion:accept` | proceed approval active | required | `PENDING_SEKINFRA` | `ACCEPTED` | `conversion.accepted` | none | prohibited |
| ProposeOngoingAgreement | HUMAN/internal service | `ongoing_agreement:propose` | not yet | not yet | accepted conversion | `DRAFT` version | `ongoing_agreement.proposed` | none | may prepare only |
| RecordOngoingAgreementApproval | HUMAN exact authority role | `ongoing_agreement:approve` | one separate record | one separate record | exact `DRAFT` digest | approval recorded | `ongoing_agreement.approval_recorded` | none | prohibited |
| ActivateOngoingAgreement | internal service | `ongoing_agreement:activate` | active exact approval | active exact approval | accepted conversion; `DRAFT`; term valid | `ACTIVE` | `ongoing_agreement.activated` | none | prohibited |
| TerminateOngoingAgreement | HUMAN bounded authority | `ongoing_agreement:terminate` | according to reason | according to reason | `ACTIVE` | terminal agreement | `ongoing_agreement.terminated` | immediately unusable by predicate | prohibited |
| RecordOngoingPaymentVerification | internal service/provider adapter | `ongoing_payment:record` | no | trusted proof | exact active agreement | `VERIFIED` coverage | `ongoing_payment.verified` | none | cannot self-verify |
| InvalidateOngoingPaymentVerification | internal service/provider adapter | `ongoing_payment:invalidate` | no | bounded authority | `VERIFIED` | `INVALIDATED` | `ongoing_payment.invalidated` | immediately unusable by predicate | prohibited |
| ProposeOngoingAccessGrant | HUMAN/internal service | `ongoing_access:propose` | not yet | not yet | accepted conversion; active agreement; valid commercial coverage | `PROPOSED` | `ongoing_access.proposed` | none | may prepare only |
| RecordOngoingAccessApproval | HUMAN exact authority role | `ongoing_access:approve` | one separate record | one separate record | exact `PROPOSED` digest | approval recorded | `ongoing_access.approval_recorded` | none | prohibited |
| ApproveOngoingAccessGrant | internal service | `ongoing_access:approve` | active exact approval | active exact approval | `PROPOSED`; full commercial chain valid | `APPROVED` | `ongoing_access.approved` | still unusable | prohibited |
| VerifyOngoingAccess | internal service/provider adapter | `ongoing_access:activate` | existing approval | existing approval | `APPROVED`; technical verification; full revalidation | `ACTIVE` | `ongoing_access.activated` | usable only by predicate | prohibited |
| RevokeOngoingAccess | HUMAN/security automation under bounded contract | `ongoing_access:revoke` | bounded reason | bounded reason | `APPROVED` or `ACTIVE` | `REVOKED` | `ongoing_access.revoked` | immediately unusable | no independent AI |
| CloseOngoingAccess | internal service | `ongoing_access:close` | no new approval | authoritative closure source | approved/active and commercial/offboarding cause | `CLOSED` | `ongoing_access.closed` | unusable | prohibited |
| InitiateOngoingOffboarding | HUMAN bounded authority | `offboarding:initiate` | according to reason | according to reason | accepted/declined conversion or ongoing relationship | initiated/pending | `offboarding.initiated` | immediately unusable | prohibited |
| VerifyOngoingAccessRevocation | internal service/provider adapter | `offboarding:verify_revocation` | no | trusted external proof | affected grant terminal; removal requested where applicable | immutable verification | `ongoing_access.revocation_verified` | proves external absence | cannot self-assert |
| CompleteOngoingOffboarding | HUMAN/internal service | `offboarding:complete` | required termination basis | required completion authority | initiated; every required revocation verified | `COMPLETED` | `offboarding.completed` | future denial | prohibited |

The caller-type contract excludes `N8N_ORCHESTRATOR` and `SCHEDULED_AUTOMATION` from authoritative Phase 5C commands. n8n may orchestrate bounded requests but cannot become commercial or access truth.

## Concurrency, idempotency, events, and outbox

All consequential commands use the existing command-scoped durable idempotency record:

- exact replay with the same semantic fingerprint returns `DUPLICATE`;
- reuse of a reservation with changed semantic meaning returns `CONFLICT`;
- identity is tenant, trusted principal, command type, subject identity/version, and idempotency key.

Creation commands establish version 1. Every mutable decision, agreement, payment, grant, revocation, or offboarding transition uses expected positive record version. Stale commands fail; last-write-wins is prohibited. Authoritative agreement versions are immutable once active, and revocation-verification records are immutable at version 1.

Future runtime persists the authoritative mutation, idempotency completion, sanitized `LifecycleEvent`, and outbox row in one UnitOfWork transaction. A rollback preserves none of them. n8n consumes events; it never writes authority directly.

Lifecycle events are limited to:

- `conversion.decision_recorded`, `conversion.accepted`
- `ongoing_agreement.proposed`, `ongoing_agreement.approval_recorded`, `ongoing_agreement.activated`, `ongoing_agreement.terminated`
- `ongoing_payment.verified`, `ongoing_payment.invalidated`
- `ongoing_access.proposed`, `ongoing_access.approval_recorded`, `ongoing_access.approved`, `ongoing_access.activated`, `ongoing_access.revoked`, `ongoing_access.closed`
- `offboarding.initiated`, `ongoing_access.revocation_verified`, `offboarding.completed`

Metadata contains only bounded stage/state, canonical IDs, coverage boundary, and external-revocation boolean. Agreement documents, payment data, credentials, raw payloads, and implementation design are forbidden.

## Read models

All reads are tenant-bounded, derived, and non-authoritative:

- `OIAConversionStatusView`
- `OngoingAgreementAuthorityView`
- `OngoingCommercialAuthorityView`
- `OngoingAccessStatusView`
- `OngoingOffboardingStatusView`
- `OngoingEngagementEligibilityView`
- `Phase5CAuthorityProgressionView`

`OngoingEngagementEligibilityView` answers only whether the engagement can currently proceed into ongoing work. Its reasons include inactive engagement, conversion missing/not accepted, agreement missing/invalid, payment missing/invalid, ongoing access missing/unusable, and active offboarding. It never declares implementation authority.

The progression and access views set implementation, deployment, and managed-operations authority to the constant `false`.

## Security and generalization

Fixtures and validation reject cross-tenant conversion, foreign delivery, undelivered Finding revision, payload role claims, scope/digest/target mismatch, payment spoofing, access activation without commercial authority, diagnostic grant identity reuse, caller-declared active access, access after commercial invalidation or offboarding, workload approval/activation, history deletion, Phase 5D fields, credentials, and payment secrets.

The universal contracts are validated with fictional deterministic examples for roofing/home-services dispatch, security-staffing coverage, and medical-office intake. Only bounded service-area and target references differ. No vertical-specific payment terms, credential model, implementation method, or operational assumptions enter the universal schema.

## Phase 5D boundary

Phase 5C may identify selected delivered Findings and commercial intervention categories. It does not define exact architecture, implementation workflow, code, change set, acceptance criteria, deployment sequence, production authorization, or managed-operations automation. A later separately governed Phase 5D layer must establish implementation authority. No Phase 5D work is part of this batch.
