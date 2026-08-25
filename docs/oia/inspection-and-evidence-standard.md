# OIA Inspection, Process Mapping, and Evidence Standard

## Bounded inspection lenses

The vocabulary is closed and versioned as part of the methodology. An item may
use multiple lenses, but new tags require a methodology revision.

| Lens | Examine | Typical failure signals | Supporting evidence |
|---|---|---|---|
| PROCESS | intended/current steps, decisions, controls | rework, ambiguity, missing step | workflow map, sequence evidence, procedure |
| PEOPLE_AND_ACCOUNTABILITY | roles, ownership, skills, escalation | orphaned work, conflicting ownership | roster/role configuration, interview corroboration, timestamps |
| SYSTEMS_AND_CONFIGURATION | tools, states, settings, limits | manual workaround, unsafe default | configuration snapshot, screen/document reference |
| DATA_AND_INFORMATION | definitions, completeness, lineage, quality | duplicate, stale, lost, inconsistent data | metric snapshot, sanitized record reference, map |
| INTEGRATIONS_AND_HANDOFFS | interfaces, queues, transfers, acknowledgements | dropped handoff, duplicate entry, no retry | workflow/system map, logs/metrics reference, sequence evidence |
| ACCESS_AND_CONTROL | least privilege, approvals, preventive/detective controls | excess access, unreviewed change | permission/access or security configuration |
| TIMING_AND_CAPACITY | latency, deadlines, volume, bottlenecks | backlog, missed SLA, saturation | metrics, timestamps, operational sequence |
| EXCEPTIONS_AND_RESILIENCE | failure paths, recovery, continuity | silent failure, unsafe fallback | sequence evidence, configuration, compliance evidence |
| CUSTOMER_AND_FINANCIAL_OUTCOME | customer friction, leakage, service result | abandonment, avoidable cost, disputed outcome | outcome metric, sanitized reference, interview corroboration |
| MEASUREMENT_AND_VISIBILITY | definitions, observability, reporting fitness | no owner, unmeasured work, conflicting reports | metric snapshot, dashboard reference, workflow map |

## Process-map minimum

Each meaningful step records trigger, input, responsible actor, system/tool,
action, decision, handoff, expected timing, observed timing where available,
output, next step, exception path, control/checkpoint, and measurable result.
This is a diagnostic representation, not BPMN or a workflow designer. It is
used to reveal delay, ownership gaps, manual dependence, fragmentation,
duplicate work, missing controls/automation, lost information, unobservable
work, and failure paths.

## Evidence expectations

An expectation is plan intent, not an `OIAEvidenceItem`. It contains an
inspection objective; closed evidence category/type compatible with current
Phase 5B types; target and diagnostic action; why it matters; minimum useful
characteristics (time window, fields or state, provenance, digest/reference);
optional corroboration; constraints; and collection status. Current evidence
types remain authoritative (`CONFIGURATION_SNAPSHOT`, `LOG_EXCERPT_REFERENCE`,
`METRIC_SNAPSHOT`, `WORKFLOW_OR_SYSTEM_MAP`, permission/network/security/
compliance evidence, operational sequence, interview corroboration, and
screen/document reference). Any future category needing a new contract is an
explicit contract-impact decision, not an informal tag.

## Sufficiency and source boundary

Sufficiency is a reasoned state, not a universal count. The assessor evaluates:

- direct support and independent corroboration;
- source reliability and whether the source is contemporaneous;
- time window, sample selection, representativeness, and repeatability;
- contradictory or missing evidence;
- system evidence versus human statement;
- confidence and materiality of the proposed conclusion.

Sampling is context-dependent. The plan records the population, selection
rationale, exclusions, and why the sample is sufficient for the claim. A
material claim normally requires direct system/sequence evidence where
reasonably available, plus corroboration or a documented reason it is
unavailable. A small or biased sample may support a hypothesis but cannot be
presented as a complete rate or universal condition.

## Human statement boundary

Evidence provenance is classified `REPORTED`, `OBSERVED`,
`SYSTEM_SUPPORTED`, or `VERIFIED` (the latter is a reviewed conclusion state,
not a new evidence type). Interviews can expose undocumented processes,
exceptions, dependencies, and useful sampling targets. They receive
attributable source, role, time, and corroboration metadata. A statement does
not become a verified material finding when objective corroboration is
reasonably available but absent. Interview-only conclusions must state that
limitation.

## Coverage is not proof

Inspection coverage states are bounded: `NOT_STARTED`, `IN_PROGRESS`,
`PARTIALLY_EVIDENCED`, `SUFFICIENTLY_EVIDENCED`, `BLOCKED`, and
`NOT_APPLICABLE`. Coverage describes whether planned work was addressed;
evidence sufficiency describes whether a particular claim is supported. A
checked/ resolved item never proves a conclusion by itself.
