# OIA Finding Priority Policy v1

**Policy identity:** `oia-finding-priority`
**Policy version:** `1.0.0`
**Normative artifact:** `contracts/policies/oia-finding-priority-policy.v1.json`

## Purpose and authority

This policy deterministically derives an `OIAFinding` priority after the runtime
has validated the authoritative diagnostic support chain. Callers supply the
existing bounded `priority_inputs`; they never supply authoritative `priority`.
The policy uses no model, randomness, time, external service, numeric weighting,
or discretionary tie-breaking. `OIAFinding` contract v1 is normatively bound to
policy version `1.0.0`; no additional Finding field is introduced. A future
policy must not reinterpret v1 and requires an explicit versioned contract
decision. An unversioned `latest` reference is never authoritative.

## Frozen inputs and output

The only inputs are `impact`, `urgency`, `operational_criticality`, `confidence`,
and `dependency_blocking` from `oia-common/v1#/$defs/priorityInputs`.

- `impact`, `urgency`, and `operational_criticality` are ordered
  `LOW < MEDIUM < HIGH < CRITICAL`.
- `confidence` is epistemic and ordered `LOW < MEDIUM < HIGH`.
- `dependency_blocking` is ordered `false < true` solely for monotonicity.
- The output is exactly one of `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.

Materiality informs the authoritative inputs but is not itself priority.
Confidence constrains justified classification; it does not create severity.

## Normative evaluation

The runtime MUST evaluate these steps in order:

1. Validate all five inputs and the Finding diagnostic support chain.
2. Set `consequence_base` to the more severe of `impact` and
   `operational_criticality`.
3. Map consequence to ordinary base priority: `LOW -> LOW`, `MEDIUM -> MEDIUM`,
   `HIGH -> HIGH`, and `CRITICAL -> HIGH`.
4. For urgency `HIGH` or `CRITICAL`, escalate the ordinary candidate by one
   tier; `LOW` and `MEDIUM` do not escalate. Ordinary escalation is capped at
   `HIGH`.
5. If `dependency_blocking` is true, escalate the ordinary candidate by one
   tier, also capped at `HIGH`. Dependency blocking cannot independently create
   `CRITICAL`.
6. Separately replace the candidate with `CRITICAL` only when all are true:
   `consequence_base == CRITICAL`, `urgency == CRITICAL`, `confidence == HIGH`,
   and the diagnostic support chain is valid.
7. Apply the confidence ceiling: `LOW -> MEDIUM`, `MEDIUM -> HIGH`, and
   `HIGH -> CRITICAL`.
8. Return the single remaining priority.

Pseudocode:

```text
require valid_priority_inputs and valid_diagnostic_support_chain
consequence = max_tier(impact, operational_criticality)
candidate = {LOW: LOW, MEDIUM: MEDIUM, HIGH: HIGH, CRITICAL: HIGH}[consequence]
if urgency in {HIGH, CRITICAL}: candidate = step_up(candidate, ceiling=HIGH)
if dependency_blocking: candidate = step_up(candidate, ceiling=HIGH)
if consequence == CRITICAL and urgency == CRITICAL and confidence == HIGH:
    candidate = CRITICAL
candidate = min_tier(candidate, confidence_ceiling[confidence])
return candidate
```

The evaluation order resolves every overlap. There is no discretionary tie.

## Classification semantics

- `CRITICAL` is exceptional and requires converging top-tier consequence,
  top-tier urgency, HIGH confidence, and valid diagnostic support.
- `HIGH` is materially severe or an escalated meaningful issue that does not
  satisfy the complete CRITICAL gate.
- `MEDIUM` warrants action but does not justify HIGH; it is also the LOW
  confidence ceiling for more severe candidates.
- `LOW` is lower-consequence priority with no legitimate escalation. HIGH
  confidence alone never elevates it.

## Normative examples

| Name | Impact | Urgency | Operational criticality | Confidence | Dependency blocking | Priority |
|---|---|---|---|---|---:|---|
| Low everything | LOW | LOW | LOW | LOW | false | LOW |
| Meaningful consequence | MEDIUM | MEDIUM | LOW | HIGH | false | MEDIUM |
| Severe without convergence | CRITICAL | HIGH | LOW | HIGH | false | HIGH |
| Complete convergence | CRITICAL | CRITICAL | LOW | HIGH | false | CRITICAL |
| Insufficient confidence | CRITICAL | CRITICAL | LOW | LOW | false | MEDIUM |
| Dependency escalation | LOW | HIGH | LOW | HIGH | true | HIGH |

Priority classifies diagnostic attention. It does not select an exact solution,
architecture, build plan, deployment sequence, Codex package, or production
authority; those remain outside Phase 5B.
