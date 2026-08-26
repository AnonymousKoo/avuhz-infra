#!/usr/bin/env python3
"""Exhaustively validate frozen OIA Finding Priority Policy v1."""

import itertools
import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "contracts/policies/oia-finding-priority-policy.v1.json"
COMMON_PATH = ROOT / "contracts/schemas/v1/domain/oia-common.schema.json"
CREATE_PATH = ROOT / "contracts/schemas/v1/commands/create-oia-finding.payload.schema.json"
UPDATE_PATH = ROOT / "contracts/schemas/v1/commands/update-oia-finding-analysis.payload.schema.json"
FINALIZE_PATH = ROOT / "contracts/schemas/v1/commands/finalize-oia-finding.payload.schema.json"


def load(path):
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


policy = load(POLICY_PATH)
common = load(COMMON_PATH)["$defs"]
rules = policy["rules"]
fields = policy["input_contract"]["fields"]
priority_order = policy["output_contract"]["semantic_order_low_to_high"]
priority_rank = {value: index for index, value in enumerate(priority_order)}


def step_up(value):
    ceiling = rules["ordinary_escalation_ceiling"]
    return priority_order[min(priority_rank[value] + 1, priority_rank[ceiling])]


def derive(values, support_chain_valid=True):
    require(support_chain_valid, "diagnostic support chain must be valid before derivation")
    require(set(values) == set(fields), "policy consumes exactly the five frozen inputs")
    for name in ("impact", "urgency", "operational_criticality", "confidence"):
        require(values[name] in fields[name]["semantic_order_low_to_high"], f"invalid {name}")
    require(type(values["dependency_blocking"]) is bool, "invalid dependency_blocking")

    consequence_order = fields["impact"]["semantic_order_low_to_high"]
    consequence = max(
        (values["impact"], values["operational_criticality"]),
        key=consequence_order.index,
    )
    candidate = rules["base_priority_by_consequence"][consequence]
    if rules["urgency_escalation_by_tier"][values["urgency"]] == "ONE_TIER":
        candidate = step_up(candidate)
    blocking_key = str(values["dependency_blocking"]).lower()
    if rules["dependency_blocking_escalation"][blocking_key] == "ONE_TIER":
        candidate = step_up(candidate)
    if (
        consequence == "CRITICAL"
        and values["urgency"] == "CRITICAL"
        and values["confidence"] == "HIGH"
    ):
        candidate = "CRITICAL"
    ceiling = rules["confidence_ceiling"][values["confidence"]]
    return priority_order[min(priority_rank[candidate], priority_rank[ceiling])]


def vector(impact, urgency, operational_criticality, confidence, dependency_blocking):
    return {
        "impact": impact,
        "urgency": urgency,
        "operational_criticality": operational_criticality,
        "confidence": confidence,
        "dependency_blocking": dependency_blocking,
    }


def main():
    require(policy["policy_id"] == "oia-finding-priority", "policy identity drifted")
    require(
        policy["policy_version"] == "1.0.0" and policy["status"] == "FROZEN",
        "policy version/status drifted",
    )
    require(set(policy) == {"policy_id", "policy_version", "status", "input_contract", "output_contract", "preconditions", "rules"}, "policy surface expanded")
    require(policy["input_contract"]["schema_reference"] == "urn:avuhz:schema:contracts:domain:oia-common:v1#/$defs/priorityInputs", "priority-input reference drifted")
    require(policy["output_contract"]["schema_reference"] == "urn:avuhz:schema:contracts:domain:oia-common:v1#/$defs/priority", "priority-output reference drifted")
    require(policy["preconditions"] == ["AUTHORITATIVE_PRIORITY_INPUTS_VALID", "DIAGNOSTIC_SUPPORT_CHAIN_VALID"], "policy preconditions drifted")
    require(rules["consequence_base"] == {"operator": "MAX_SEMANTIC_TIER", "inputs": ["impact", "operational_criticality"]}, "consequence rule drifted")
    require(rules["base_priority_by_consequence"] == {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "HIGH"}, "base-priority rule drifted")
    require(rules["urgency_escalation_by_tier"] == {"LOW": "NO_CHANGE", "MEDIUM": "NO_CHANGE", "HIGH": "ONE_TIER", "CRITICAL": "ONE_TIER"}, "urgency rule drifted")
    require(rules["dependency_blocking_escalation"] == {"false": "NO_CHANGE", "true": "ONE_TIER"}, "dependency-blocking rule drifted")
    require(rules["critical_gate"] == {"all": {"consequence_base": "CRITICAL", "urgency": "CRITICAL", "confidence": "HIGH", "diagnostic_support_chain": "VALID"}, "dependency_blocking_required": False}, "CRITICAL gate drifted")
    require(
        set(fields)
        == {"impact", "urgency", "operational_criticality", "confidence", "dependency_blocking"},
        "priority inputs expanded",
    )
    require(
        fields["impact"]["semantic_order_low_to_high"] == list(reversed(common["impact"]["enum"])),
        "impact order drifted",
    )
    require(
        fields["urgency"]["semantic_order_low_to_high"] == list(reversed(common["urgency"]["enum"])),
        "urgency order drifted",
    )
    require(
        fields["operational_criticality"]["semantic_order_low_to_high"]
        == list(reversed(common["operationalCriticality"]["enum"])),
        "operational criticality order drifted",
    )
    require(
        fields["confidence"]["semantic_order_low_to_high"]
        == list(reversed(common["confidence"]["enum"])),
        "confidence order drifted",
    )
    require(priority_order == list(reversed(common["priority"]["enum"])), "priority output drifted")
    require(rules["ordinary_escalation_ceiling"] == "HIGH", "ordinary escalation can reach CRITICAL")
    require(
        rules["confidence_ceiling"] == {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL"},
        "confidence ceilings drifted",
    )
    require(rules["evaluation_order"] == ["VALIDATE_INPUTS_AND_PRECONDITIONS", "DERIVE_CONSEQUENCE_BASE", "MAP_BASE_PRIORITY", "APPLY_URGENCY_ESCALATION_WITH_ORDINARY_CEILING", "APPLY_DEPENDENCY_ESCALATION_WITH_ORDINARY_CEILING", "EVALUATE_CRITICAL_GATE_SEPARATELY", "APPLY_CONFIDENCE_CEILING", "RETURN_ONE_PRIORITY"], "evaluation order drifted")
    require(rules["tie_behavior"] == "EVALUATION_ORDER_IS_AUTHORITATIVE", "tie behavior drifted")

    commands = (load(CREATE_PATH), load(UPDATE_PATH), load(FINALIZE_PATH))
    require(
        all("priority" not in command["properties"] for command in commands),
        "caller can submit authoritative priority",
    )
    domain = load(ROOT / "contracts/schemas/v1/domain/oia-finding.schema.json")
    require(domain["properties"]["priority"].get("readOnly") is True, "domain priority is not server-derived")

    names = ("impact", "urgency", "operational_criticality", "confidence", "dependency_blocking")
    domains = [fields[name]["semantic_order_low_to_high"] for name in names]
    combinations = [vector(*values) for values in itertools.product(*domains)]
    require(len(combinations) == 384, "Cartesian product is not exhaustive")
    outputs = [derive(values) for values in combinations]
    require(len(outputs) == len(combinations), "a valid tuple has no output")
    require(set(outputs) <= set(priority_order), "invalid priority literal produced")
    require(outputs == [derive(values) for values in combinations], "derivation is not deterministic")

    for values in combinations:
        current = priority_rank[derive(values)]
        for name in ("impact", "urgency", "operational_criticality", "confidence"):
            order = fields[name]["semantic_order_low_to_high"]
            index = order.index(values[name])
            if index + 1 < len(order):
                increased = dict(values)
                increased[name] = order[index + 1]
                require(priority_rank[derive(increased)] >= current, f"{name} is not monotone")
        if not values["dependency_blocking"]:
            blocking = dict(values)
            blocking["dependency_blocking"] = True
            require(priority_rank[derive(blocking)] >= current, "dependency blocking is not monotone")

    named = {
        "low_everything": (vector("LOW", "LOW", "LOW", "LOW", False), "LOW"),
        "meaningful_mid_consequence": (vector("MEDIUM", "MEDIUM", "LOW", "HIGH", False), "MEDIUM"),
        "severe_without_convergence": (vector("CRITICAL", "HIGH", "LOW", "HIGH", False), "HIGH"),
        "complete_critical_convergence": (vector("CRITICAL", "CRITICAL", "LOW", "HIGH", False), "CRITICAL"),
        "top_consequence_insufficient_urgency": (vector("CRITICAL", "HIGH", "LOW", "HIGH", True), "HIGH"),
        "top_consequence_insufficient_confidence": (vector("CRITICAL", "CRITICAL", "LOW", "MEDIUM", True), "HIGH"),
        "dependency_escalates": (vector("LOW", "HIGH", "LOW", "HIGH", True), "HIGH"),
        "dependency_alone_not_critical": (vector("LOW", "LOW", "LOW", "HIGH", True), "MEDIUM"),
        "high_confidence_alone": (vector("LOW", "LOW", "LOW", "HIGH", False), "LOW"),
        "low_confidence_ceiling": (vector("CRITICAL", "CRITICAL", "LOW", "LOW", True), "MEDIUM"),
        "medium_confidence_ceiling": (vector("CRITICAL", "CRITICAL", "LOW", "MEDIUM", True), "HIGH"),
    }
    for name, (values, expected) in named.items():
        require(derive(values) == expected, f"named vector failed: {name}")

    consequence_order = fields["impact"]["semantic_order_low_to_high"]
    for values, output in zip(combinations, outputs):
        consequence = max(
            (values["impact"], values["operational_criticality"]),
            key=consequence_order.index,
        )
        if output == "CRITICAL":
            require(
                consequence == "CRITICAL"
                and values["urgency"] == "CRITICAL"
                and values["confidence"] == "HIGH",
                "CRITICAL gate bypassed",
            )
    require(
        derive(vector("LOW", "CRITICAL", "LOW", "HIGH", False)) != "CRITICAL",
        "urgency alone created CRITICAL",
    )

    distribution = Counter(outputs)
    print(
        "oia-finding-priority-policy validation: PASS "
        f"({len(combinations)} exhaustive tuples; "
        + ", ".join(f"{priority}={distribution[priority]}" for priority in priority_order)
        + "; monotonicity, CRITICAL gate, caller boundary, and determinism verified)"
    )


if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        print(f"oia-finding-priority-policy validation: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
