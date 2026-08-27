# Phase 5B — OIA execution, evidence, and findings architecture

## A. Purpose and frozen boundaries

Phase 5B creates authoritative diagnostic truth for an Operational Infrastructure
Assessment (OIA). Discovery remains an input only. An OIA establishes what was
observed, the evidence that supports it, the operational problem, any supported
root cause, and the reviewed findings delivered to the client.

Phase 5B consumes the frozen Phase 5A commercial and temporary-access authority
chain. It creates neither ongoing access nor implementation/deployment authority.
Phase 5C owns conversion, Agreement #2, and ongoing authority. Phase 5D owns the
Implementation Brief / Codex Build Package.

## B. Root resource and lifecycle

The authoritative root is **`OIAAssessment`**. It is one tenant-bound execution
of one approved diagnostic scope through one exact AssessmentAccessGrant.
`OperationalInfrastructureAssessment` is the descriptive name; `OIAAssessment`
is the stable resource and API vocabulary.

An OIAAssessment contains:

- `oia_assessment_id`, `tenant_id`, `engagement_id`, and `record_version`;
- exact versioned DiagnosticScope, DiagnosticAgreementAuthority,
  DiagnosticPaymentVerification, and AssessmentAccessGrant references;
- frozen `canonical_scope_digest`, action-set version, target-system references,
  and permitted actions copied from the grant for auditable context, never as a
  new source of access;
- `state`, `opened_at`, `opened_by`, `ready_for_delivery_at`,
  `findings_delivered_at`, `closed_at`, and attributable command correlation;
- an assessment conclusion set at readiness: `FINDINGS_PRESENT` or
  `NO_MATERIAL_FINDINGS`.

There is one assessment per `(tenant_id, assessment_access_grant_id)`. A grant is
one temporary diagnostic execution boundary, not a reusable assessment session.

The smallest authoritative state machine is:

```text
OpenOIAAssessment
  -> IN_PROGRESS
  -> READY_FOR_DELIVERY
  -> FINDINGS_DELIVERED
  -> CLOSED

FINDINGS_DELIVERED --ReviseDeliveredOIAFinding--> READY_FOR_DELIVERY
```

`OPEN` is intentionally not a state: successful opening immediately begins the
assessment. `READY_FOR_DELIVERY` is authoritative because it records the reviewed
assessment conclusion and freezes the candidate finding set for a delivery
manifest. `FINDINGS_DELIVERED` records durable client-facing delivery truth;
`CLOSED` ends the assessment. The sole backward edge is an explicit correction
workflow for a delivered finding. It never reactivates assessment access or
permits new external inspection.

Predicates:

- `IN_PROGRESS -> READY_FOR_DELIVERY`: trusted internal reviewer sets the
  conclusion; every included finding is `FINAL`; no included finding has been
  superseded; and either there is at least one final finding or the conclusion is
  `NO_MATERIAL_FINDINGS`.
- `READY_FOR_DELIVERY -> FINDINGS_DELIVERED`: an immutable delivery manifest is
  accepted for exactly the final findings and revisions selected by the command.
- `FINDINGS_DELIVERED -> READY_FOR_DELIVERY`: only an attributable correction
  creates a new finding revision that supersedes a delivered one.
- `FINDINGS_DELIVERED -> CLOSED`: at least one delivery exists and no correction
  revision is pending delivery.

## C. Entry authority and runtime usability

`OpenOIAAssessment` is creation-time eligible only when all authoritative records
are tenant- and engagement-equal and current:

1. Engagement is active (`OPEN` in the frozen lifecycle).
2. DiagnosticScope is `APPROVED`, has the exact scope version and canonical
   digest, and has the exact action-set binding.
3. DiagnosticAgreementAuthority is `VERIFIED_ACTIVE` and valid at trusted time.
4. DiagnosticPaymentVerification is `VERIFIED`.
5. AssessmentAccessGrant is `ACTIVE` and
   `evaluate_assessment_access_usability(...)` is true at trusted time.
6. The grant's exact scope, digest, action set, commercial references, targets,
   and permitted actions match the assessment context.

The assessment never grants access. Every `RecordOIAEvidence` command that
captures from a client system must re-evaluate the Phase 5A usability predicate
immediately before the secure/provider boundary, and must use a target and action
within the exact grant. Evidence already captured may be analysed, correlated,
reviewed, delivered, and closed after access expires or is closed; those actions
must not inspect a client system.

## D. Evidence model and data minimization

`OIAEvidenceItem` is authoritative provenance metadata, not an evidence blob.
It binds one assessment, a permitted target/system or an approved non-system
source, the permitted action used where applicable, and one sanitized secure
object/reference location.

Required fields are tenant, evidence ID, assessment ID, source-system reference,
evidence type, captured time, trusted capturing principal/workload, action used,
opaque secure-object reference/location, content digest when content exists,
classification, retention status, bounded structured attributes, and record
version. `captured_by` and the command correlation are server-derived.

The external secure object store, vault, or provider retains any permitted binary
object. PostgreSQL stores only a provider-neutral opaque object reference, digest,
size class, and bounded safe attributes. It must never contain raw credentials,
connection strings, authorization headers, secrets, full database dumps, full log
archives, or raw provider responses.

Evidence types are the closed vocabulary:

- `CONFIGURATION_SNAPSHOT`
- `LOG_EXCERPT_REFERENCE`
- `METRIC_SNAPSHOT`
- `WORKFLOW_OR_SYSTEM_MAP`
- `PERMISSION_OR_ACCESS_CONFIGURATION`
- `NETWORK_CONFIGURATION`
- `SECURITY_CONFIGURATION`
- `COMPLIANCE_EVIDENCE`
- `OPERATIONAL_SEQUENCE_EVIDENCE`
- `HUMAN_INTERVIEW_CORROBORATION`
- `SCREEN_OR_DOCUMENT_REFERENCE`

Evidence records what was captured, not what it means. Provenance fields are
immutable. Retention disposition may move `AVAILABLE -> REDACTED | RETIRED` with
an expected version and an append-only lifecycle event; it cannot alter the
original digest, source, capture time, or actor.

## E. Observations, problems, and root causes

`OIAObservation` is a first-class, internal analytical record of a verified
condition. It has an assessment reference, one or more evidence links, system or
process area, observed condition, optional expected condition, bounded impact
indicator, confidence, observed time, recording actor, status, and version.
Observations do not contain recommendations.

An observation is `RECORDED` or `SUPERSEDED`. Corrections create a new observation
with a `supersedes_observation_id`; the original remains readable. This prevents
silent replacement of analytical evidence.

A separate `OperationalProblem` resource is not required. A Finding is the
client-facing, verified operational problem. A separate **`OIARootCause`** is
required because one cause may support several findings and a cause may remain
uncertain. It has an assessment binding, causal statement, supporting observation
links, contributing factors, confidence state, status/version, and attribution.

Root-cause confidence is closed: `HYPOTHESIS`, `SUPPORTED`, `VERIFIED`.
`VERIFIED` requires supporting evidence and trusted human acceptance. Automation
may propose a hypothesis, but never writes `SUPPORTED` or `VERIFIED` truth on its
own.

## F. Finding model, priority, review, and history

`OIAFinding` is the authoritative client-facing diagnostic conclusion. It contains
one assessment binding; client-safe problem statement; affected category and
system/process references; why it matters; linked observations and evidence;
linked root causes; desired outcome; bounded intervention class; constraints,
risks, dependencies, and acceptance-oriented success conditions; priority inputs;
priority classification; status; revision lineage; content digest; author; and
version.

A Finding is not an implementation specification. Its intervention class is
bounded to `CONFIGURATION_CHANGE`, `PROCESS_CHANGE`, `INTEGRATION_CHANGE`,
`ACCESS_OR_PERMISSION_CHANGE`, `OBSERVABILITY_CHANGE`, `SECURITY_HARDENING`, or
`FURTHER_INVESTIGATION`. It contains enough verified truth for Phase 5D to derive
a brief, but cannot authorize execution.

Findings are `DRAFT`, `FINAL`, or `SUPERSEDED`. A trusted human internal reviewer
alone may transition `DRAFT -> FINAL`. A final finding is immutable. A delivered
finding is never edited: a correction creates a new revision with an immutable
`suppersedes_finding_id` relationship, is independently reviewed, and is delivered
in a later immutable manifest.

Priority stores bounded inputs—`impact`, `urgency`, `operational_criticality`,
`confidence`, and optional `dependency_blocking`—and the server-derived
classification `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`. `effort_estimate` is
explicitly excluded: it belongs to future implementation planning. The priority
classification is recalculated on expected-version draft updates and frozen at
finalization. This avoids false numerical precision while retaining the facts
behind a ranking.

The normative derivation is versioned as Finding Priority Policy v1 in
`docs/oia/finding-priority-policy.md` and
`contracts/policies/oia-finding-priority-policy.v1.json`. `OIAFinding` contract
v1 is normatively bound to policy version `1.0.0`; a future policy cannot
silently reinterpret v1. An unversioned `latest` reference is not authoritative.

## G. Human authority and client-facing boundary

Trusted internal workloads and authorized Sekinfra humans may record sanitized
evidence. Human interview corroboration requires an attributable human recorder.
Authorized Sekinfra analysts may record observations, root-cause hypotheses, and
draft findings. Only a trusted HUMAN context with `oia:finding:finalize` may
finalize a finding or mark an assessment ready for delivery.

Existing `HumanApproval` remains frozen for scope and access-proposal authority;
it is not reused for generic acknowledgement. Finding finalization is an
attributable professional-review transition, not client consent. Client
acknowledgement, if later required, is a separate receipt and does not change
findings-delivery truth.

Internal evidence, observations, hypotheses, and reviewer notes are not
client-facing by default. A Finding contains only a client-safe conclusion and
sanitized supporting references. Delivery selects finalized finding revisions,
not internal working material.

## H. Findings delivery and assessment closure

`OIAFindingsDelivery` is the authoritative delivery receipt. It has delivery ID,
tenant/assessment binding, monotonically increasing delivery sequence, immutable
manifest digest, the ordered set of `(finding_id, revision, content_digest)`,
delivered time, trusted delivering actor, recipient organization/reference, and
opaque channel-confirmation reference. An email-send attempt alone is not a
receipt and cannot produce delivery truth.

`DeliverOIAFindings` atomically creates the receipt, appends
`oia.findings_delivered`, transitions the assessment to `FINDINGS_DELIVERED`, and
records the exact delivered set. It provides the authoritative source for
`FINDINGS_DELIVERED_CLOSURE_SOURCE_READY = YES`.

`CloseOIAAssessment` requires a delivery receipt, no pending correction revision,
and a trusted close actor. It appends `oia.assessment_closed`, transitions the
assessment to `CLOSED`, and provides
`ASSESSMENT_CLOSED_CLOSURE_SOURCE_READY = YES`.

## I. Phase 5A access interaction

Delivery and closure do not mutate credentials. They consume the existing frozen
Phase 5A closure reasons:

- On findings delivery, an `APPROVED` or `ACTIVE` exact grant is closed with
  `FINDINGS_DELIVERED` in the same authoritative transaction and emits the
  existing `assessment_access.closed` lifecycle event.
- On assessment closure, an `APPROVED` or `ACTIVE` exact grant is closed with
  `ASSESSMENT_CLOSED`. Normally delivery has already closed it, so this is a
  no-op for a grant already terminal.
- If the grant is already `EXPIRED`, `REVOKED`, or `CLOSED`, delivery/closure
  must not rewrite that terminal state.

The single strict `assessment_access.closed` event records the truthful terminal
cause as exactly `AGREEMENT_ENDED`, `FINDINGS_DELIVERED`, or
`ASSESSMENT_CLOSED`. It describes an accepted access closure; it does not create
closure authority or imply assessment delivery, closure, or implementation
authority by itself.

This is not a new access model. It is the previously deferred authoritative source
for the frozen grant closure reasons. It never reactivates access, extends TTL, or
creates ongoing authority. Payment invalidation retains its frozen Phase 5A
mapping: immediate fail-closed usability and no new terminal mapping here.

## J. Commands, capabilities, events, and idempotency

All commands use the real CommandExecutor pattern, trusted tenant context, durable
idempotency, lifecycle event, and transactional outbox. `subject_id` remains the
audit/correlation identity. Every Phase 5B command is **command-scoped** for
idempotency: exact replay must recover a completed operation even when a create or
transition would no longer be legal; a same-key semantic change is `CONFLICT`.

| Command | Subject / transition | Capability and actor | Event |
|---|---|---|---|
| `OpenOIAAssessment` | assessment -> `IN_PROGRESS` | `oia:open`; INTERNAL_SERVICE or authorized HUMAN | `oia.assessment_opened` |
| `RecordOIAEvidence` | immutable evidence item | `oia:evidence:record`; authorized HUMAN or trusted workload | `oia.evidence_recorded` |
| `RecordOIAObservation` | observation -> `RECORDED` | `oia:observation:record`; authorized HUMAN or trusted workload | `oia.observation_recorded` |
| `SupersedeOIAObservation` | old observation -> `SUPERSEDED`, new observation | `oia:observation:record`; authorized HUMAN | `oia.observation_superseded` |
| `RecordOIARootCause` | root cause draft/update | `oia:root_cause:record`; authorized HUMAN | `oia.root_cause_recorded` |
| `CreateOIAFinding` / `UpdateOIAFindingAnalysis` | draft finding create or expected-version update | `oia:finding:write`; authorized HUMAN | `oia.finding_created` / `oia.finding_updated` |
| `FinalizeOIAFinding` | `DRAFT -> FINAL` | `oia:finding:finalize`; HUMAN only | `oia.finding_finalized` |
| `MarkOIAAssessmentReadyForDelivery` | `IN_PROGRESS -> READY_FOR_DELIVERY` | `oia:assessment:review`; HUMAN only | `oia.assessment_ready_for_delivery` |
| `DeliverOIAFindings` | receipt + `READY_FOR_DELIVERY -> FINDINGS_DELIVERED` | `oia:findings:deliver`; HUMAN or verified delivery workload | `oia.findings_delivered` and, when legal, `assessment_access.closed` |
| `ReviseDeliveredOIAFinding` | correction revision + `FINDINGS_DELIVERED -> READY_FOR_DELIVERY` | `oia:finding:finalize`; HUMAN only | `oia.finding_revision_opened` |
| `CloseOIAAssessment` | `FINDINGS_DELIVERED -> CLOSED` | `oia:assessment:close`; HUMAN or authorized internal service | `oia.assessment_closed` |

No command accepts credentials, raw evidence content, caller-selected timestamps,
scope digest, priority, human identity, or closure reason. The server resolves all
such truth from trusted context and authoritative records.

## K. Versioning, concurrency, and immutability

Every mutable authoritative row has `record_version`; commands carrying mutable
state require `expected_record_version` and use conditional updates. A stale write
returns a bounded conflict/rejection without a partial event, outbox record, or
idempotency completion.

Evidence provenance is immutable. Observation supersession preserves history.
Draft findings use expected-version updates; final findings are immutable. Delivered
finding revisions use new rows and a supersession link. A delivery manifest is
immutable and snapshots exact finding revisions/digests, so later corrections
cannot alter what was delivered. Relationship rows are append-only while their
referenced record is current; delivery-item rows are immutable.

## L. Tenant, RLS, n8n, and read models

Every resource and join row is tenant-bound. PostgreSQL execution must bind
`TrustedExecutionContext.tenant_id` to transaction-local `avuhz.tenant_id`; each
new table receives the same command-service RLS posture as Phase 5A. Composite
foreign keys include tenant ID. Browser and n8n direct writes are prohibited.
n8n may later invoke bounded commands only.

Minimum read models are tenant-filtered projections of:

- assessment state, conclusion, and next required action;
- evidence count/progress by evidence type and target, without object locations;
- finding count by status and priority;
- latest immutable delivery status/sequence; and
- whether access is currently usable, supplied only by the Phase 5A evaluator.

## M. PostgreSQL durable-resource plan

No migration is created by this document. The future plan is:

| Resource/table | Purpose and important constraints |
|---|---|
| `avuhz_oia_assessments` | Root; PK `(tenant_id, oia_assessment_id)`; unique grant binding; exact composite FKs to Engagement, Scope, Agreement, Payment, and Grant; versioned state; tenant RLS. |
| `avuhz_oia_evidence_items` | Provenance metadata/reference; composite assessment FK; immutable source/digest fields; versioned retention disposition; tenant RLS. |
| `avuhz_oia_observations` | Internal verified conditions; composite assessment and optional supersedes FK; version/state; tenant RLS. |
| `avuhz_oia_observation_evidence` | Many-to-many evidence citation; unique tenant/observation/evidence; append-only; composite tenant FKs. |
| `avuhz_oia_root_causes` | Causal statements/confidence; composite assessment and optional supersession FKs; version/state; tenant RLS. |
| `avuhz_oia_root_cause_observations` | Supporting observation links; unique tenant/root-cause/observation; append-only. |
| `avuhz_oia_findings` | Client-safe conclusion; assessment FK; priority inputs/classification; state/version; immutable after final; supersession lineage; tenant RLS. |
| `avuhz_oia_finding_observations` | Finding support links; unique tenant/finding/observation; immutable after finding finalization. |
| `avuhz_oia_finding_root_causes` | Finding causal links; unique tenant/finding/root-cause; immutable after finalization. |
| `avuhz_oia_findings_deliveries` | Immutable receipt; unique tenant/assessment/delivery sequence and manifest digest; tenant RLS. |
| `avuhz_oia_findings_delivery_items` | Immutable delivery manifest members; unique tenant/delivery/finding/revision. |

Existing idempotency, lifecycle-event, and transactional-outbox tables are reused;
no Phase 5B parallel orchestration tables are introduced. Required indexes support
tenant+ID reads, assessment state, grant uniqueness, current finding priority, and
delivery sequence. RLS policies deny unbound tenant access and cross-tenant joins.

## N. AI, Phase 5C, and Phase 5D boundaries

Future AI may suggest an observation, correlation, root-cause hypothesis, priority,
or draft client-safe finding language. It cannot create evidence, mark a root cause
verified, finalize a finding, deliver findings, close an assessment, or establish
access/commercial authority. Every accepted AI suggestion is recorded through the
same trusted human command as a human-created record.

Findings delivery is diagnostic completion, not conversion or implementation
approval. Phase 5C alone may make a conversion decision, establish Agreement #2,
or issue ongoing/deployment access. Phase 5D may derive an Implementation Brief
only from finalized/delivered findings and their verified problem, outcome,
context, constraints, scope, integrations, risks, requirements, acceptance
conditions, and prohibited changes. Phase 5B does not create that brief.

## O. Owner decisions

No blocking owner decision remains for Phase 5B contracts. Evidence object-store
provider selection and organization-specific retention durations are deployment
policy decisions; the architecture intentionally uses opaque references and
retention classes so they do not block the authoritative model or implementation.
