# OIA Assessment Planning Architecture

## Decisions

`OIAAssessmentPlan` is a first-class tenant-bound resource: **required**.
`OIAVerticalTemplate` is a reusable versioned knowledge reference, initially
repository content rather than a tenant record. `OIAInspectionItem` is a
first-class execution resource: **required** because it needs identity,
lifecycle, concurrency, authorization, evidence links, and blocked reasons.

The plan says what Sekinfra intends to inspect; it never creates authority.
The invariant is:

```text
methodology/template/plan <= DiagnosticScope
  <= current commercial authority
  <= usable AssessmentAccessGrant target/action authority
```

An unavailable target or action yields `BLOCKED_BY_AUTHORITY` (or a narrower
blocked reason), never an access expansion.

## Plan contents

Conceptually, a plan binds `plan_id`, `tenant_id`, `engagement_id`,
`oia_assessment_id`, methodology/version references, vertical template/version,
exact scope ID/version/digest, objectives, process areas, inspection-item
references, expected-evidence references, sampling strategy, known systems,
constraints, dependencies, exclusions, risk notes, completion criteria,
limitations, plan state/version, attributable creator/reviewer/approver, and
timestamps. It stores diagnostic intent and opaque references, not credentials,
logs, dumps, provider payloads, exports, or arbitrary blobs.

An inspection item expresses one diagnostic objective: what to inspect, why it
matters, lens/process area, expected evidence, target/action relationship,
required or optional status, bounded state, blocked reason, evidence links,
assessor notes, and sufficiency state. It is not a generic checklist task.

## Generation and review

Plan generation consumes approved scope, discovery context, desired outcomes,
known systems, the published universal methodology, a vertical template, and
relevant prior OIA history where appropriate. AI may propose a plan and surface
gaps. A trusted human reviews material plans, verifies that every item is within
the exact authority chain, and approves the plan; approval cannot authorize
anything absent from current scope/grant. Plan revisions are new versions with
expected-record-version concurrency and historical readability.

## Plan and assessment lifecycle relationship

`OIAAssessment` remains the authoritative OIA lifecycle root. A plan is a
versioned child input to execution. Evidence remains the immutable provenance
record actually captured. Observations state evidence-supported conditions;
root causes explain them with bounded confidence; findings are client-safe
conclusions; delivery is an immutable manifest. None of these resources is
interchangeable with a plan.

## Future command impact (no runtime in this batch)

The minimum likely command set is `CreateOIAAssessmentPlan`,
`ReviseOIAAssessmentPlan`, `ReviewOIAAssessmentPlan`, and
`ApproveOIAAssessmentPlan`, plus item-level transitions only if needed:
`MarkOIAInspectionItemBlocked`, `ResolveOIAInspectionItem`, and
`EvaluateOIAInspectionCoverage`. They must use the existing `CommandExecutor`,
unit-of-work, idempotency, expected-version, tenant isolation, events, and
transactional outbox patterns. Plan commands read authority; they do not issue
or widen it.
