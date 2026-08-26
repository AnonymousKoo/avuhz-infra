"""Authoritative, human-accepted OIA observation semantics."""

from __future__ import annotations


class OIAObservationRejected(ValueError):
    """Current authoritative analytical truth cannot accept the transition."""


class OIAObservationHandler:
    """Record evidence-supported conditions without creating causes or findings."""

    def __init__(self, repositories):
        self.repositories = repositories

    @staticmethod
    def _actor(trusted_context):
        if (
            not trusted_context.tenant_id
            or "oia:observation:record" not in trusted_context.capabilities
            or trusted_context.caller_type != "HUMAN"
            or not trusted_context.principal_id
            or not trusted_context.human_principal_reference
        ):
            raise OIAObservationRejected("trusted human observation authority is required")
        return trusted_context.human_principal_reference

    def _assessment(self, tenant_id, assessment_id, engagement_id):
        assessment = self.repositories.oia_assessments.get(tenant_id, assessment_id)
        engagement = self.repositories.engagements.get(tenant_id, engagement_id)
        if (
            not assessment
            or assessment.get("tenant_id") != tenant_id
            or assessment.get("state") != "IN_PROGRESS"
            or assessment.get("engagement_id") != engagement_id
            or not engagement
            or engagement.get("engagement_state") != "OPEN"
        ):
            raise OIAObservationRejected("an in-progress correlated assessment is required")
        return assessment

    def _approved_plan(self, tenant_id, assessment):
        plan = self.repositories.oia_assessment_plans.find_current_by_assessment(
            tenant_id, assessment["oia_assessment_id"]
        )
        if (
            not plan
            or plan.get("tenant_id") != tenant_id
            or plan.get("oia_assessment_id") != assessment.get("oia_assessment_id")
            or plan.get("state") != "APPROVED"
            or plan.get("engagement_id") != assessment.get("engagement_id")
            or plan.get("diagnostic_scope_id") != assessment.get("diagnostic_scope_id")
            or plan.get("diagnostic_scope_version") != assessment.get("diagnostic_scope_version")
            or plan.get("canonical_scope_digest") != assessment.get("canonical_scope_digest")
        ):
            raise OIAObservationRejected("the current approved methodology plan is required")
        return plan

    def _evidence(self, tenant_id, assessment, evidence_ids):
        records = []
        for evidence_id in evidence_ids:
            evidence = self.repositories.oia_evidence_items.get(tenant_id, evidence_id)
            if (
                not evidence
                or evidence.get("tenant_id") != tenant_id
                or evidence.get("oia_assessment_id") != assessment["oia_assessment_id"]
            ):
                raise OIAObservationRejected("observation evidence is not correlated to this assessment")
            records.append(evidence)
        return tuple(records)

    def _supporting_items(self, tenant_id, assessment, plan, payload):
        items = self.repositories.oia_inspection_items.list_by_plan(
            tenant_id, plan["oia_assessment_plan_id"], plan["plan_version"]
        )
        process_areas = {
            area["process_area_id"]: area["name"] for area in plan.get("process_areas", ())
        }
        objective_ids = {
            objective["objective_id"] for objective in plan.get("objectives", ())
        }
        for evidence_id in payload["evidence_ids"]:
            supported = False
            for item in items:
                sufficiency = item.get("sufficiency_evaluation", {})
                area_matches = payload["system_process_area"] in (
                    item.get("process_area_id"), process_areas.get(item.get("process_area_id"))
                )
                if (
                    evidence_id in item.get("linked_evidence_ids", ())
                    and item.get("tenant_id") == tenant_id
                    and item.get("engagement_id") == assessment.get("engagement_id")
                    and item.get("oia_assessment_id") == assessment["oia_assessment_id"]
                    and item.get("oia_assessment_plan_id") == plan["oia_assessment_plan_id"]
                    and item.get("plan_version") == plan["plan_version"]
                    and item.get("methodology_reference") == plan.get("methodology_reference")
                    and item.get("vertical_template_reference")
                    == plan.get("vertical_template_reference")
                    and item.get("objective_id") in objective_ids
                    and item.get("process_area_id") in process_areas
                    and item.get("coverage_state") == "SUFFICIENTLY_EVIDENCED"
                    and sufficiency.get("state") == "SUFFICIENT"
                    and sufficiency.get("direct_evidence") is True
                    and sufficiency.get("missing_material_evidence") is False
                    and sufficiency.get("contradiction_state") != "UNRESOLVED"
                    and area_matches
                ):
                    supported = True
                    break
            if not supported:
                raise OIAObservationRejected("evidence lacks sufficient governed inspection support")

    def record(self, trusted_context, payload, engagement_id, recorded_at):
        actor = self._actor(trusted_context)
        tenant_id = trusted_context.tenant_id
        assessment = self._assessment(tenant_id, payload["oia_assessment_id"], engagement_id)
        plan = self._approved_plan(tenant_id, assessment)
        self._evidence(tenant_id, assessment, payload["evidence_ids"])
        self._supporting_items(tenant_id, assessment, plan, payload)
        observation = {
            "tenant_id": tenant_id,
            "oia_observation_id": payload["oia_observation_id"],
            "oia_assessment_id": assessment["oia_assessment_id"],
            "evidence_ids": list(payload["evidence_ids"]),
            "system_process_area": payload["system_process_area"],
            "observed_condition": payload["observed_condition"],
            "confidence": payload["confidence"],
            "state": "RECORDED",
            "record_version": 1,
            "created_by": actor,
            "created_at": recorded_at,
            "updated_at": recorded_at,
        }
        if "expected_condition" in payload:
            observation["expected_condition"] = payload["expected_condition"]
        return self.repositories.oia_observations.create(observation)

    def supersede(self, trusted_context, payload, engagement_id, expected_record_version, superseded_at):
        self._actor(trusted_context)
        tenant_id = trusted_context.tenant_id
        original = self.repositories.oia_observations.get(tenant_id, payload["oia_observation_id"])
        replacement = self.repositories.oia_observations.get(
            tenant_id, payload["replacement_oia_observation_id"]
        )
        if (
            not original
            or not replacement
            or original.get("tenant_id") != tenant_id
            or replacement.get("tenant_id") != tenant_id
            or original["oia_observation_id"] == replacement["oia_observation_id"]
            or original.get("state") != "RECORDED"
            or replacement.get("state") != "RECORDED"
            or original.get("record_version") != expected_record_version
            or original.get("oia_assessment_id") != replacement.get("oia_assessment_id")
        ):
            raise OIAObservationRejected("observation supersession correlation is invalid")
        self._assessment(tenant_id, original["oia_assessment_id"], engagement_id)
        return self.repositories.oia_observations.supersede(
            original, replacement, superseded_at
        )
