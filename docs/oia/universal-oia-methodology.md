# Sekinfra Universal OIA Methodology

**Methodology version:** `oia-methodology/1.0.0` (published)

## Purpose and authority

Discovery is what a client believes is wrong, wants improved, or reports as
pain. An Operational Infrastructure Assessment (OIA) is a structured
investigation that determines what should happen, what actually happens, where
they differ, what evidence proves the difference, why the breakdown occurs,
how material it is, and what intervention class is justified.

`CLIENT_REPORTED_PROBLEM != AUTHORITATIVE_FINDING`. A report starts or shapes
an investigation; it never establishes operational truth by itself.

The method is universal. A vertical template supplies reusable industry
knowledge and a client assessment plan selects the authorized, engagement-
specific work. Neither creates access or commercial authority.

## Frozen sequence

Every OIA follows this sequence, recording a rationale when a step is skipped:

1. **Establish intended outcome.** State the business outcome, success signal,
   affected actors, and discovery context without treating the report as proof.
2. **Fix the assessment boundary.** Bind the plan to the approved
   `DiagnosticScope`, exact version/digest, engagement, and current
   `AssessmentAccessGrant` targets/actions. Mark work outside that boundary
   `BLOCKED_BY_AUTHORITY`.
3. **Map the current operation.** Trace trigger, work, decisions, systems,
   people, handoffs, outputs, timing, controls, and exception paths.
4. **Select critical process areas.** Prioritize areas by intended-outcome
   dependency and materiality; record inclusions, exclusions, and limitations.
5. **Inspect through the bounded lenses.** Inspect systems, people, data,
   integrations, and handoffs only with an authorized target/action.
6. **Capture evidence.** Seek the expectation described by the plan and record
   immutable `OIAEvidenceItem` provenance; do not store raw provider payloads.
7. **Detect divergence.** Compare intended and observed operation and identify
   symptoms, exceptions, control failures, and contradictions.
8. **Validate observations.** Produce an evidence-supported `OIAObservation`,
   distinguish reported from observed, and seek corroboration where material.
9. **Investigate causes.** Test causal mechanisms. Keep alternatives as
   hypotheses until evidence and trusted human review support them.
10. **Determine materiality.** Assess impact dimensions and confidence; use the
    existing Finding priority algorithm when a finding is later finalized.
11. **Form findings.** Draft a client-safe verified operational problem,
    supporting observations/evidence, desired outcome, constraints, and a
    bounded intervention class. A finding is not an implementation design.
12. **Check coverage and limitations.** Resolve required items, contradictions,
    blocked areas, evidence sufficiency, and residual uncertainty.
13. **Human review.** An attributable trusted human accepts material
    observations/root-cause states and finalizes findings or accepts documented
    limitations. AI never performs this authority transition.
14. **Findings delivery.** Mark the assessment ready only when the completion
    standard is met, then use the existing immutable delivery manifest.

The resulting flow is:

```text
Universal Methodology -> Vertical Template -> Client Assessment Plan
  -> Evidence -> Observation -> Root Cause -> Finding -> Priority
  -> Findings Delivery -> Phase 5D Implementation Brief
```

## Diagnostic distinctions

- **Symptom:** an observable or reported negative business effect.
- **Operational problem:** a verified undesirable operational condition.
- **Root cause:** a causal mechanism explaining why that condition persists.
- **Evidence:** facts or artifacts that support, qualify, or contradict those
  statements.

Thus, `symptom != finding`, `observation != root cause`, `hypothesis != verified
root cause`, and `correlation != causation`.

## Materiality and depth

Materiality is assessed across revenue, cost, time, customer impact,
reliability, accountability, security, compliance, continuity, and
capacity/scale. It determines how deeply an area deserves investigation; it
does not replace the frozen Finding priority algorithm and does not permit
invented financial values. A high-materiality claim needs stronger direct or
corroborating support and explicit limitations.

Investigation goes deeper when evidence is contradictory, the causal claim is
material but weak, a control boundary is unclear, a repeated sample changes
confidence, or a dependency can be inspected within authority. It stops when
evidence is sufficient and additional work is unlikely to change confidence
materially, the item is outside scope, authority is unavailable, a permitted
non-destructive boundary would be exceeded, a dependency is unavailable, a
client limitation prevents further proof, or the issue is immaterial to the
engagement. The stopping reason and residual limitation are recorded.

## AI and human boundary

AI may suggest process areas, questions, inspection items, evidence gaps,
contradictions, evidence groupings, observations, root-cause hypotheses,
additional evidence, and possible findings. AI may not widen scope or grants,
declare unsupported claims true, independently verify root cause, finalize
material findings, or authorize implementation/deployment. Trusted human
authority remains authoritative.
