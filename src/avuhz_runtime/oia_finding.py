"""Versioned, client-safe OIA Finding analysis and finalization."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .oia_observation import OIAObservationHandler


POLICY_ID = "oia-finding-priority"
POLICY_VERSION = "1.0.0"
POLICY_PATH = (
    Path(__file__).resolve().parents[2]
    / "contracts/policies/oia-finding-priority-policy.v1.json"
)
INTERVENTION_CATEGORIES = frozenset(
    {
        "CONFIGURATION_CHANGE",
        "PROCESS_CHANGE",
        "INTEGRATION_CHANGE",
        "ACCESS_OR_PERMISSION_CHANGE",
        "OBSERVABILITY_CHANGE",
        "SECURITY_HARDENING",
        "FURTHER_INVESTIGATION",
    }
)
ANALYSIS_FIELDS = (
    "title",
    "summary",
    "verified_operational_problem",
    "business_operational_impact",
    "system_process_category",
    "supporting_observation_ids",
    "supporting_evidence_ids",
    "root_cause_ids",
    "desired_outcome",
    "intervention_category",
    "priority_inputs",
    "confidence",
    "dependency_references",
)


class OIAFindingRejected(ValueError):
    """The proposed Finding transition is not supported by authoritative truth."""


class FindingPriorityPolicyV1:
    """Local, exact evaluator for frozen oia-finding-priority/1.0.0."""

    def __init__(self, policy_path=POLICY_PATH):
        with Path(policy_path).open(encoding="utf-8") as source:
            self.policy = json.load(source)
        if (
            self.policy.get("policy_id") != POLICY_ID
            or self.policy.get("policy_version") != POLICY_VERSION
            or self.policy.get("status") != "FROZEN"
        ):
            raise RuntimeError("the frozen Finding priority policy is unavailable")
        self.fields = self.policy["input_contract"]["fields"]
        self.rules = self.policy["rules"]
        self.order = self.policy["output_contract"]["semantic_order_low_to_high"]
        if set(self.fields) != {
            "impact",
            "urgency",
            "operational_criticality",
            "confidence",
            "dependency_blocking",
        } or self.order != ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            raise RuntimeError("the frozen Finding priority vocabulary drifted")
        self.rank = {value: index for index, value in enumerate(self.order)}

    def _step_up(self, value):
        ceiling = self.rules["ordinary_escalation_ceiling"]
        return self.order[min(self.rank[value] + 1, self.rank[ceiling])]

    def derive(self, values, diagnostic_support_chain_valid=True):
        if not diagnostic_support_chain_valid or set(values) != set(self.fields):
            raise OIAFindingRejected("valid authoritative priority inputs and support are required")
        for name in ("impact", "urgency", "operational_criticality", "confidence"):
            if values[name] not in self.fields[name]["semantic_order_low_to_high"]:
                raise OIAFindingRejected("Finding priority input is invalid")
        if type(values["dependency_blocking"]) is not bool:
            raise OIAFindingRejected("Finding dependency blocking input is invalid")

        consequence_order = self.fields["impact"]["semantic_order_low_to_high"]
        consequence = max(
            (values["impact"], values["operational_criticality"]),
            key=consequence_order.index,
        )
        candidate = self.rules["base_priority_by_consequence"][consequence]
        if self.rules["urgency_escalation_by_tier"][values["urgency"]] == "ONE_TIER":
            candidate = self._step_up(candidate)
        blocking_key = str(values["dependency_blocking"]).lower()
        if self.rules["dependency_blocking_escalation"][blocking_key] == "ONE_TIER":
            candidate = self._step_up(candidate)
        if consequence == "CRITICAL" and values["urgency"] == "CRITICAL" and values["confidence"] == "HIGH":
            candidate = "CRITICAL"
        ceiling = self.rules["confidence_ceiling"][values["confidence"]]
        return self.order[min(self.rank[candidate], self.rank[ceiling])]


def finding_content_digest(finding):
    content = {
        name: finding[name]
        for name in (
            "tenant_id",
            "oia_finding_id",
            "oia_assessment_id",
            "finding_revision",
            *ANALYSIS_FIELDS,
            "priority",
        )
        if name in finding
    }
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()


class OIAFindingHandler:
    """Create/revise draft analysis and finalize it without delivery or new access."""

    def __init__(self, repositories, priority_policy=None):
        self.repositories = repositories
        self.priority_policy = priority_policy or FindingPriorityPolicyV1()

    @staticmethod
    def _actor(trusted_context, capability):
        if (
            not trusted_context.tenant_id
            or capability not in trusted_context.capabilities
            or trusted_context.caller_type != "HUMAN"
            or not trusted_context.principal_id
            or not trusted_context.human_principal_reference
        ):
            raise OIAFindingRejected("trusted human Finding authority is required")
        return trusted_context.human_principal_reference

    def _assessment(self, tenant_id, assessment_id, engagement_id, allowed_states=("IN_PROGRESS",)):
        assessment = self.repositories.oia_assessments.get(tenant_id, assessment_id)
        engagement = self.repositories.engagements.get(tenant_id, engagement_id)
        if (
            not assessment
            or assessment.get("tenant_id") != tenant_id
            or assessment.get("engagement_id") != engagement_id
            or assessment.get("state") not in allowed_states
            or not engagement
            or engagement.get("engagement_state") != "OPEN"
        ):
            raise OIAFindingRejected("an in-progress correlated assessment is required")
        return assessment

    def _observations(self, tenant_id, assessment, observation_ids):
        observations = []
        observer = OIAObservationHandler(self.repositories)
        plan = observer._approved_plan(tenant_id, assessment)
        for observation_id in observation_ids:
            observation = self.repositories.oia_observations.get(tenant_id, observation_id)
            if (
                not observation
                or observation.get("tenant_id") != tenant_id
                or observation.get("oia_assessment_id") != assessment["oia_assessment_id"]
                or observation.get("state") != "RECORDED"
            ):
                raise OIAFindingRejected("Finding observations must be current and correlated")
            observer._supporting_items(tenant_id, assessment, plan, observation)
            observations.append(observation)
        return tuple(observations)

    def _evidence(self, tenant_id, assessment, observations, evidence_ids):
        cited = {
            evidence_id
            for observation in observations
            for evidence_id in observation.get("evidence_ids", ())
        }
        if set(evidence_ids) != cited:
            raise OIAFindingRejected("Finding evidence must exactly preserve observation provenance")
        for evidence_id in evidence_ids:
            evidence = self.repositories.oia_evidence_items.get(tenant_id, evidence_id)
            if (
                not evidence
                or evidence.get("tenant_id") != tenant_id
                or evidence.get("oia_assessment_id") != assessment["oia_assessment_id"]
            ):
                raise OIAFindingRejected("Finding evidence must be authoritative and correlated")

    def _root_causes(self, tenant_id, assessment, payload):
        root_causes = []
        observation_ids = set(payload["supporting_observation_ids"])
        evidence_ids = set(payload["supporting_evidence_ids"])
        for root_cause_id in payload.get("root_cause_ids", ()):
            root_cause = self.repositories.oia_root_causes.get(tenant_id, root_cause_id)
            if (
                not root_cause
                or root_cause.get("tenant_id") != tenant_id
                or root_cause.get("oia_assessment_id") != assessment["oia_assessment_id"]
                or root_cause.get("confidence") != "VERIFIED"
                or not set(root_cause.get("supporting_observation_ids", ())).issubset(observation_ids)
                or not set(root_cause.get("supporting_evidence_ids", ())).issubset(evidence_ids)
            ):
                raise OIAFindingRejected("causal Finding support requires a correlated VERIFIED root cause")
            root_causes.append(root_cause)
        return tuple(root_causes)

    def _validate_support(self, tenant_id, assessment, payload):
        if payload["confidence"] != payload["priority_inputs"]["confidence"]:
            raise OIAFindingRejected("Finding confidence must match its priority input")
        if payload["intervention_category"] not in INTERVENTION_CATEGORIES:
            raise OIAFindingRejected("Finding intervention category is not bounded")
        observations = self._observations(
            tenant_id, assessment, payload["supporting_observation_ids"]
        )
        self._evidence(
            tenant_id, assessment, observations, payload["supporting_evidence_ids"]
        )
        self._root_causes(tenant_id, assessment, payload)
        return self.priority_policy.derive(
            payload["priority_inputs"], diagnostic_support_chain_valid=True
        )

    @staticmethod
    def _analysis(payload):
        return {name: json.loads(json.dumps(payload[name])) for name in ANALYSIS_FIELDS if name in payload}

    def create(self, trusted_context, payload, engagement_id, created_at):
        actor = self._actor(trusted_context, "oia:finding:write")
        tenant_id = trusted_context.tenant_id
        assessment = self._assessment(tenant_id, payload["oia_assessment_id"], engagement_id)
        priority = self._validate_support(tenant_id, assessment, payload)
        finding = {
            "tenant_id": tenant_id,
            "oia_finding_id": payload["oia_finding_id"],
            "oia_assessment_id": assessment["oia_assessment_id"],
            "finding_revision": 1,
            "state": "DRAFT",
            **self._analysis(payload),
            "priority": priority,
            "created_by": actor,
            "created_at": created_at,
            "updated_at": created_at,
        }
        return self.repositories.oia_findings.create(finding)

    def update(self, trusted_context, payload, engagement_id, expected_revision, updated_at):
        actor = self._actor(trusted_context, "oia:finding:write")
        tenant_id = trusted_context.tenant_id
        current = self.repositories.oia_findings.get(tenant_id, payload["oia_finding_id"])
        if (
            not current
            or current.get("state") != "DRAFT"
            or current.get("finding_revision") != expected_revision
        ):
            raise OIAFindingRejected("only the current expected DRAFT revision can be updated")
        assessment = self._assessment(
            tenant_id, current["oia_assessment_id"], engagement_id,
            ("IN_PROGRESS", "READY_FOR_DELIVERY"),
        )
        if assessment["state"] == "READY_FOR_DELIVERY" and "supersedes_finding_revision" not in current:
            raise OIAFindingRejected("only a governed delivered-Finding correction may be revised")
        priority = self._validate_support(tenant_id, assessment, payload)
        replacement = {
            "tenant_id": tenant_id,
            "oia_finding_id": current["oia_finding_id"],
            "oia_assessment_id": current["oia_assessment_id"],
            "finding_revision": current["finding_revision"] + 1,
            "state": "DRAFT",
            **self._analysis(payload),
            "priority": priority,
            "supersedes_finding_revision": {
                "oia_finding_id": current["oia_finding_id"],
                "finding_revision": current["finding_revision"],
            },
            "created_by": actor,
            "created_at": updated_at,
            "updated_at": updated_at,
        }
        return self.repositories.oia_findings.revise(
            current, replacement, finding_content_digest(current), updated_at
        )

    def finalize(self, trusted_context, payload, engagement_id, expected_revision, finalized_at):
        actor = self._actor(trusted_context, "oia:finding:finalize")
        tenant_id = trusted_context.tenant_id
        current = self.repositories.oia_findings.get(tenant_id, payload["oia_finding_id"])
        if (
            not current
            or current.get("state") != "DRAFT"
            or current.get("finding_revision") != payload["finding_revision"]
            or current.get("finding_revision") != expected_revision
        ):
            raise OIAFindingRejected("only the current expected DRAFT revision can be finalized")
        assessment = self._assessment(
            tenant_id, current["oia_assessment_id"], engagement_id,
            ("IN_PROGRESS", "READY_FOR_DELIVERY"),
        )
        if assessment["state"] == "READY_FOR_DELIVERY" and "supersedes_finding_revision" not in current:
            raise OIAFindingRejected("only a governed delivered-Finding correction may be finalized")
        priority = self._validate_support(tenant_id, assessment, current)
        if current.get("priority") != priority:
            raise OIAFindingRejected("stored Finding priority does not match policy 1.0.0")
        final = dict(current)
        final.update(
            state="FINAL",
            priority=priority,
            finalized_by=actor,
            finalized_at=finalized_at,
            updated_at=finalized_at,
        )
        final["content_digest"] = finding_content_digest(final)
        return self.repositories.oia_findings.finalize(current, final)


def derive_finding_set_readiness(repositories, tenant_id, assessment_id):
    """Return bounded non-authoritative eligibility without advancing assessment state."""
    assessment = repositories.oia_assessments.get(tenant_id, assessment_id)
    reasons = []
    if not assessment or assessment.get("state") not in ("IN_PROGRESS", "READY_FOR_DELIVERY"):
        reasons.append("ASSESSMENT_NOT_ANALYTICALLY_OPEN")
    coverage = repositories.oia_inspection_items.coverage_for_current_assessment(
        tenant_id, assessment_id
    )
    if not coverage or not coverage.get("ready_for_observation_analysis"):
        reasons.append("DIAGNOSTIC_INVESTIGATION_UNRESOLVED")
    findings = repositories.oia_findings.list_current_by_assessment(tenant_id, assessment_id)
    if not findings:
        reasons.append("NO_FINDINGS")
    if any(finding.get("state") != "FINAL" for finding in findings):
        reasons.append("UNRESOLVED_FINDING_REVISION")
    if assessment and not reasons:
        handler = OIAFindingHandler(repositories)
        try:
            for finding in findings:
                handler._validate_support(tenant_id, assessment, finding)
        except OIAFindingRejected:
            reasons.append("FINDING_SUPPORT_INVALID")
    return {
        "readiness": "READY" if not reasons else "NOT_READY",
        "reason_codes": tuple(reasons),
        "current_finding_count": len(findings),
        "final_finding_count": sum(finding.get("state") == "FINAL" for finding in findings),
    }
