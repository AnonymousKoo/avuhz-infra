"""Authoritative in-memory OIA inspection planning and execution semantics."""

from __future__ import annotations

import copy

from .assessment_access_usability import evaluate_assessment_access_usability


class OIAInspectionItemRejected(ValueError):
    """Current authoritative truth cannot accept the inspection transition."""


class OIAInspectionItemHandler:
    """Execute an approved plan without treating plan content as access authority."""

    _TRANSITIONS = {
        "NOT_STARTED": frozenset(("IN_PROGRESS", "PARTIALLY_EVIDENCED", "NOT_APPLICABLE")),
        "IN_PROGRESS": frozenset(("PARTIALLY_EVIDENCED", "NOT_APPLICABLE")),
        "PARTIALLY_EVIDENCED": frozenset(("PARTIALLY_EVIDENCED", "SUFFICIENTLY_EVIDENCED", "NOT_APPLICABLE")),
        "BLOCKED": frozenset(("IN_PROGRESS", "PARTIALLY_EVIDENCED", "NOT_APPLICABLE")),
        "SUFFICIENTLY_EVIDENCED": frozenset(),
        "NOT_APPLICABLE": frozenset(),
    }
    _BLOCKABLE = frozenset(("NOT_STARTED", "IN_PROGRESS", "PARTIALLY_EVIDENCED"))
    _STOP_FOR_BLOCK = {
        "BLOCKED_BY_AUTHORITY": "AUTHORITY_UNAVAILABLE",
        "DEPENDENCY_UNAVAILABLE": "DEPENDENCY_UNAVAILABLE",
        "CLIENT_OR_SYSTEM_LIMITATION": "CLIENT_LIMITATION",
        "SCOPE_EXCLUSION": "OUTSIDE_SCOPE",
        "NON_DESTRUCTIVE_BOUNDARY": "NON_DESTRUCTIVE_BOUNDARY",
    }

    def __init__(self, repositories):
        self.repositories = repositories

    @staticmethod
    def _actor(trusted_context, human_only=False):
        if (
            not trusted_context.tenant_id
            or "oia:inspection:manage" not in trusted_context.capabilities
            or trusted_context.caller_type not in ("INTERNAL_SERVICE", "HUMAN")
            or not trusted_context.principal_id
        ):
            raise OIAInspectionItemRejected("trusted inspection authority is required")
        if human_only:
            if trusted_context.caller_type != "HUMAN" or not trusted_context.human_principal_reference:
                raise OIAInspectionItemRejected("trusted human inspection judgment is required")
            return trusted_context.human_principal_reference
        if trusted_context.caller_type == "HUMAN" and trusted_context.human_principal_reference:
            return trusted_context.human_principal_reference
        return trusted_context.principal_id

    def _foundation(self, tenant_id, engagement_id, assessment_id, plan_id, plan_version):
        engagement = self.repositories.engagements.get(tenant_id, engagement_id)
        assessment = self.repositories.oia_assessments.get(tenant_id, assessment_id)
        plan = self.repositories.oia_assessment_plans.get_version(tenant_id, plan_id, plan_version)
        current = self.repositories.oia_assessment_plans.get_current(tenant_id, plan_id)
        if not engagement or engagement.get("engagement_state") != "OPEN":
            raise OIAInspectionItemRejected("an active engagement is required")
        if not assessment or assessment.get("state") != "IN_PROGRESS" or assessment.get("engagement_id") != engagement_id:
            raise OIAInspectionItemRejected("an in-progress correlated assessment is required")
        if (
            not plan
            or not current
            or plan != current
            or plan.get("state") != "APPROVED"
            or plan.get("engagement_id") != engagement_id
            or plan.get("oia_assessment_id") != assessment_id
            or plan.get("plan_version") != plan_version
        ):
            raise OIAInspectionItemRejected("the current approved plan version is required")
        if (
            plan.get("diagnostic_scope_id") != assessment.get("diagnostic_scope_id")
            or plan.get("diagnostic_scope_version") != assessment.get("diagnostic_scope_version")
            or plan.get("canonical_scope_digest") != assessment.get("canonical_scope_digest")
        ):
            raise OIAInspectionItemRejected("plan assessment scope correlation is invalid")
        scope = self.repositories.diagnostic_scopes.get(tenant_id, assessment["diagnostic_scope_id"])
        if (
            not scope
            or scope.get("status") != "APPROVED"
            or scope.get("engagement_id") != engagement_id
            or scope.get("scope_version") != assessment.get("diagnostic_scope_version")
            or scope.get("canonical_scope_digest") != assessment.get("canonical_scope_digest")
        ):
            raise OIAInspectionItemRejected("assessment scope correlation is invalid")
        return assessment, plan, scope

    @staticmethod
    def _scope_allows(scope, planned_target_action):
        if planned_target_action is None:
            return
        target = planned_target_action["target_system_reference"]["system_reference_id"]
        action = planned_target_action["diagnostic_action"]
        targets = {value.get("system_reference_id") for value in scope.get("in_scope_systems", ())}
        actions = set(scope.get("permitted_actions", scope.get("permitted_diagnostic_actions", ())))
        if target not in targets or action not in actions:
            raise OIAInspectionItemRejected("planned target or action is outside DiagnosticScope")

    def _validate_planning_content(self, payload, plan, scope):
        if payload["objective_id"] not in {value["objective_id"] for value in plan["objectives"]}:
            raise OIAInspectionItemRejected("inspection objective is not present in the approved plan")
        if payload["process_area_id"] not in {value["process_area_id"] for value in plan["process_areas"]}:
            raise OIAInspectionItemRejected("inspection process area is not present in the approved plan")
        target_action = payload.get("planned_target_action")
        self._scope_allows(scope, target_action)
        for expectation in payload["expected_evidence"]:
            expected_target_action = expectation.get("planned_target_action")
            self._scope_allows(scope, expected_target_action)
            if expected_target_action is not None and expected_target_action != target_action:
                raise OIAInspectionItemRejected("evidence expectation target/action does not match the inspection item")

    def create(self, trusted_context, payload, created_at):
        actor = self._actor(trusted_context)
        tenant_id = trusted_context.tenant_id
        assessment, plan, scope = self._foundation(
            tenant_id, payload["engagement_id"], payload["oia_assessment_id"],
            payload["oia_assessment_plan_id"], payload["plan_version"],
        )
        self._validate_planning_content(payload, plan, scope)
        item = {
            "tenant_id": tenant_id,
            "oia_inspection_item_id": payload["oia_inspection_item_id"],
            "engagement_id": assessment["engagement_id"],
            "oia_assessment_id": assessment["oia_assessment_id"],
            "oia_assessment_plan_id": plan["oia_assessment_plan_id"],
            "plan_version": plan["plan_version"],
            "methodology_reference": copy.deepcopy(plan["methodology_reference"]),
            "objective_id": payload["objective_id"],
            "process_area_id": payload["process_area_id"],
            "what_to_inspect": payload["what_to_inspect"],
            "why_it_matters": payload["why_it_matters"],
            "inspection_lenses": copy.deepcopy(payload["inspection_lenses"]),
            "expected_evidence": copy.deepcopy(payload["expected_evidence"]),
            "required": payload["required"],
            "coverage_state": "NOT_STARTED",
            "sufficiency_evaluation": {
                "state": "NOT_EVALUATED", "direct_evidence": False,
                "corroborating_evidence": False, "source_reliability": "UNKNOWN",
                "representativeness": "NOT_ASSESSED", "contradiction_state": "NONE",
                "missing_material_evidence": True, "confidence": "LOW",
                "rationale": "No evidence has been evaluated for this inspection objective.",
            },
            "materiality": copy.deepcopy(payload["materiality"]),
            "limitations": copy.deepcopy(payload.get("limitations", [])),
            "linked_evidence_ids": [],
            "record_version": 1,
            "created_by": actor,
            "created_at": created_at,
            "updated_at": created_at,
        }
        for optional in ("vertical_template_reference",):
            if optional in plan:
                item[optional] = copy.deepcopy(plan[optional])
        for optional in ("planned_target_action", "sampling_strategy", "assessor_notes"):
            if optional in payload:
                item[optional] = copy.deepcopy(payload[optional])
        return self.repositories.oia_inspection_items.create(item)

    def _current_item(self, trusted_context, payload, expected_record_version):
        tenant_id = trusted_context.tenant_id
        item = self.repositories.oia_inspection_items.get(tenant_id, payload["oia_inspection_item_id"])
        if not item or item.get("record_version") != expected_record_version:
            raise OIAInspectionItemRejected("inspection item record version is stale")
        assessment, plan, scope = self._foundation(
            tenant_id, item["engagement_id"], item["oia_assessment_id"],
            item["oia_assessment_plan_id"], item["plan_version"],
        )
        return item, assessment, plan, scope

    def _current_access_allows(self, tenant_id, assessment, item, trusted_now):
        target_action = item.get("planned_target_action")
        if target_action is None:
            return
        grant_id = assessment.get("assessment_access_grant_id")
        usability = evaluate_assessment_access_usability(self.repositories, tenant_id, grant_id, trusted_now)
        grant = self.repositories.assessment_access_grants.get(tenant_id, grant_id)
        scope_reference = (grant or {}).get("diagnostic_scope_reference", {})
        if (
            not grant or grant.get("engagement_id") != assessment.get("engagement_id")
            or scope_reference.get("reference_id") != assessment.get("diagnostic_scope_id")
            or scope_reference.get("reference_version") != assessment.get("diagnostic_scope_version")
            or grant.get("canonical_scope_digest") != assessment.get("canonical_scope_digest")
        ):
            raise OIAInspectionItemRejected("assessment access binding is invalid")
        target = target_action["target_system_reference"]["system_reference_id"]
        action = target_action["diagnostic_action"]
        targets = {value.get("system_reference_id") for value in (grant or {}).get("target_system_references", ())}
        actions = set((grant or {}).get("permitted_actions", ()))
        if not usability.usable or target not in targets or action not in actions:
            raise OIAInspectionItemRejected("current access does not authorize inspection start")

    def _evidence(self, tenant_id, assessment_id, evidence_ids):
        records = []
        for evidence_id in evidence_ids:
            evidence = self.repositories.oia_evidence_items.get(tenant_id, evidence_id)
            if not evidence or evidence.get("oia_assessment_id") != assessment_id:
                raise OIAInspectionItemRejected("linked evidence is not correlated to this assessment")
            records.append(evidence)
        return records

    @staticmethod
    def _preserves(existing, replacement):
        return all(value in replacement for value in existing)

    def _validate_update(self, trusted_context, item, payload, evidence):
        target = payload["coverage_state"]
        if target not in self._TRANSITIONS[item["coverage_state"]]:
            raise OIAInspectionItemRejected("inspection coverage transition is invalid")
        if not self._preserves(item["linked_evidence_ids"], payload["linked_evidence_ids"]):
            raise OIAInspectionItemRejected("linked evidence history cannot be removed")
        if not self._preserves(item["limitations"], payload["limitations"]):
            raise OIAInspectionItemRejected("inspection limitations cannot be removed")
        expectation_types = {value["evidence_type"] for value in item["expected_evidence"]}
        if any(value.get("evidence_type") not in expectation_types for value in evidence):
            raise OIAInspectionItemRejected("linked evidence does not address an expectation")
        sufficiency = payload["sufficiency_evaluation"]
        if target == "PARTIALLY_EVIDENCED":
            if not evidence or sufficiency["state"] not in ("PARTIAL", "CONTRADICTORY") or not sufficiency["missing_material_evidence"]:
                raise OIAInspectionItemRejected("partial coverage requires truthful partial or contradictory evidence state")
        elif target == "SUFFICIENTLY_EVIDENCED":
            self._actor(trusted_context, human_only=True)
            if (
                not evidence or sufficiency["state"] != "SUFFICIENT"
                or not sufficiency["direct_evidence"] or sufficiency["missing_material_evidence"]
                or sufficiency["contradiction_state"] == "UNRESOLVED"
                or sufficiency["source_reliability"] not in ("MEDIUM", "HIGH")
                or sufficiency["representativeness"] not in ("REASONABLE", "STRONG")
                or sufficiency["confidence"] not in ("MEDIUM", "HIGH")
                or payload.get("stop_reason") not in ("EVIDENCE_SUFFICIENT", "ADDITIONAL_EVIDENCE_UNLIKELY_TO_CHANGE_CONFIDENCE")
                or "stop_rationale" not in payload
            ):
                raise OIAInspectionItemRejected("sufficient coverage requires supported human judgment")
        elif target == "NOT_APPLICABLE":
            self._actor(trusted_context, human_only=True)
            if payload.get("stop_reason") not in ("OUTSIDE_SCOPE", "LOW_MATERIALITY"):
                raise OIAInspectionItemRejected("not applicable requires a legitimate non-blocking rationale")
            if sufficiency["state"] == "SUFFICIENT" or sufficiency["contradiction_state"] == "UNRESOLVED":
                raise OIAInspectionItemRejected("not applicable cannot hide sufficient or contradictory evidence")
        elif target == "IN_PROGRESS":
            if sufficiency["state"] == "SUFFICIENT":
                raise OIAInspectionItemRejected("in-progress coverage cannot assert sufficient evidence")
            if item["coverage_state"] == "NOT_STARTED" and (evidence or sufficiency["state"] != "NOT_EVALUATED"):
                raise OIAInspectionItemRejected("initial inspection start cannot fabricate evidence progress")
            if payload.get("stop_reason") is not None or payload.get("stop_rationale") is not None or payload.get("intervention_class") is not None:
                raise OIAInspectionItemRejected("active inspection cannot assert a stop or intervention")
        else:
            if payload.get("stop_reason") is not None or payload.get("stop_rationale") is not None or payload.get("intervention_class") is not None:
                raise OIAInspectionItemRejected("active inspection cannot assert a stop or intervention")
        if ("stop_reason" in payload) != ("stop_rationale" in payload):
            raise OIAInspectionItemRejected("stop reason and rationale must be paired")
        if payload.get("intervention_class") is not None and target != "SUFFICIENTLY_EVIDENCED":
            raise OIAInspectionItemRejected("intervention class requires sufficient inspection coverage")

    def update(self, trusted_context, payload, expected_record_version, updated_at):
        actor = self._actor(trusted_context)
        item, assessment, _plan, _scope = self._current_item(trusted_context, payload, expected_record_version)
        if payload["coverage_state"] == "IN_PROGRESS":
            self._current_access_allows(trusted_context.tenant_id, assessment, item, updated_at)
        evidence = self._evidence(trusted_context.tenant_id, assessment["oia_assessment_id"], payload["linked_evidence_ids"])
        self._validate_update(trusted_context, item, payload, evidence)
        return self.repositories.oia_inspection_items.update(item, payload, actor, updated_at)

    def block(self, trusted_context, payload, expected_record_version, blocked_at):
        actor = self._actor(trusted_context)
        item, assessment, _plan, _scope = self._current_item(trusted_context, payload, expected_record_version)
        if item["coverage_state"] not in self._BLOCKABLE:
            raise OIAInspectionItemRejected("inspection item cannot enter BLOCKED from its current state")
        if payload["blocked_reason"] == "BLOCKED_BY_AUTHORITY":
            if item.get("planned_target_action") is None:
                raise OIAInspectionItemRejected("authority blocking requires a planned target/action")
            try:
                self._current_access_allows(trusted_context.tenant_id, assessment, item, blocked_at)
            except OIAInspectionItemRejected:
                pass
            else:
                raise OIAInspectionItemRejected("current authority is usable; authority block is not truthful")
        return self.repositories.oia_inspection_items.block(
            item, payload, actor, blocked_at, self._STOP_FOR_BLOCK.get(payload["blocked_reason"]),
        )


def derive_assessment_coverage(items):
    """Derive bounded inspection coverage without advancing OIAAssessment state."""
    values = tuple(copy.deepcopy(item) for item in items)
    by_state = {
        state: tuple(item["oia_inspection_item_id"] for item in values if item["coverage_state"] == state)
        for state in ("NOT_STARTED", "IN_PROGRESS", "PARTIALLY_EVIDENCED", "SUFFICIENTLY_EVIDENCED", "BLOCKED", "NOT_APPLICABLE")
    }
    unresolved_required = tuple(
        item["oia_inspection_item_id"] for item in values
        if item["required"] and item["coverage_state"] in ("NOT_STARTED", "IN_PROGRESS", "PARTIALLY_EVIDENCED")
    )
    undocumented_blocks = tuple(
        item["oia_inspection_item_id"] for item in values
        if item["coverage_state"] == "BLOCKED" and (not item.get("blocked_reason") or not item.get("limitations"))
    )
    unresolved_contradictions = tuple(
        item["oia_inspection_item_id"] for item in values
        if item["sufficiency_evaluation"]["contradiction_state"] == "UNRESOLVED"
    )
    return {
        "total_items": len(values),
        "coverage_by_state": by_state,
        "required_unresolved_item_ids": unresolved_required,
        "blocked_item_ids": by_state["BLOCKED"],
        "not_applicable_item_ids": by_state["NOT_APPLICABLE"],
        "sufficiently_evidenced_item_ids": by_state["SUFFICIENTLY_EVIDENCED"],
        "ready_for_observation_analysis": bool(values) and not unresolved_required and not undocumented_blocks and not unresolved_contradictions,
    }
