# OIA Methodology, Content, and Durability Boundaries

## Immutable published versions

Universal methodology and vertical templates use immutable published versions
plus draft revisions. A published version receives a content digest and cannot
be edited; a later improvement publishes a new version. Every plan and
assessment records the exact methodology version, vertical-template version,
and plan version used. Historical OIAs never silently inherit later content.

The repository is the initial source of truth for universal methodology and
vertical knowledge, with logical future directories such as `docs/oia/` and
`docs/oia/verticals/<vertical>/`. A template contains process areas, common
flows, failure patterns, recommended inspection items, expected evidence,
metrics, dependencies, risks, and exception paths. It contains no client scope,
access authority, finding, deployment authorization, or implementation approval.

## Core versus vertical content

The **OIA engine** owns Avuhz lifecycle, tenant isolation, authority checks,
commands, events, outbox, and durable execution. **OIA methodology** owns
universal diagnostic rules. A **vertical pack** owns reusable industry
knowledge. A **client plan** owns engagement-specific selection and execution
state. All remain in this repository; they are not separate repositories.

## Durability recommendation

Keep published methodology and vertical templates as reviewed,
version-controlled repository content initially. Make client assessment plans,
inspection items, coverage state, review state, and execution references
authoritative tenant-bound database resources in a future persistence batch.
This gives reproducibility and code review for universal knowledge while
preserving tenant isolation, concurrency, auditability, future authoring, and
AI-assisted proposals for client work. Database records reference immutable
content digests; they do not copy raw content blobs or evidence.

## Minimal next contract set

The next contract batch should add only:

1. `OIAAssessmentPlan` (first-class identity, lifecycle, version, authority
   bindings, and plan content).
2. `OIAInspectionItem` (first-class identity/lifecycle because execution,
   concurrency, authorization, evidence links, and blocked reasons are
   independently mutable).
3. `MethodologyReference` and `VerticalTemplateReference` as bounded embedded
   references in the plan, not independent tenant resources yet.
4. Embedded `EvidenceExpectation`, `SamplingStrategy`, completion/limitation
   criteria, and the closed coverage/sufficiency states.

No separate contract is warranted yet for every lens, process-map field,
materiality dimension, intervention class, or interview status; these are
bounded substructures/enums unless future independent lifecycle or authorization
requires promotion. Existing `OIAEvidenceItem`, `OIAObservation`,
`OIARootCause`, `OIAFinding`, and `OIAFindingsDelivery` remain unchanged.

## Phase boundaries

Phase 5B determines what is wrong, where it occurs, why it occurs, what
supports the conclusion, how material it is, and what intervention class is
justified. Phase 5D determines the exact change: requirements, integrations,
constraints, acceptance criteria, prohibited changes, implementation sequence,
and deployment assumptions. No `ImplementationBrief` is created here.
