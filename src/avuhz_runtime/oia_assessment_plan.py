"""Trusted in-memory lifecycle core for versioned OIAAssessmentPlan records."""

from __future__ import annotations

import copy


class OIAAssessmentPlanRejected(ValueError):
    """Current authoritative truth cannot accept the requested plan transition."""


class TrustedMethodologyCatalog:
    """Injected provider-neutral catalog of immutable published knowledge references."""

    def __init__(self, methodologies=(), vertical_templates=()):
        self._methodologies = self._index(methodologies, "methodology_id")
        self._vertical_templates = self._index(vertical_templates, "template_id")

    @staticmethod
    def _index(references, identity_field):
        indexed = {}
        for reference in references:
            value = copy.deepcopy(dict(reference))
            key = (value[identity_field], value["version"])
            if key in indexed and indexed[key] != value["content_digest"]:
                raise ValueError("published knowledge reference conflicts")
            indexed[key] = value["content_digest"]
        return indexed

    def accepts_methodology(self, reference):
        return self._accepts(self._methodologies, reference, "methodology_id")

    def accepts_vertical_template(self, reference):
        return self._accepts(self._vertical_templates, reference, "template_id")

    @staticmethod
    def _accepts(catalog, reference, identity_field):
        return catalog.get((reference[identity_field], reference["version"])) == reference["content_digest"]


class OIAAssessmentPlanHandler:
    """Create and transition plans without creating or evaluating client-system access."""

    def __init__(self, repositories, methodology_catalog):
        self.repositories = repositories
        self.methodology_catalog = methodology_catalog

    @staticmethod
    def _actor(trusted_context, capability, human_only=False):
        if (
            not trusted_context.tenant_id
            or capability not in trusted_context.capabilities
            or trusted_context.caller_type not in ("INTERNAL_SERVICE", "HUMAN")
            or not trusted_context.principal_id
        ):
            raise OIAAssessmentPlanRejected("trusted plan authority is required")
        if human_only:
            if trusted_context.caller_type != "HUMAN" or not trusted_context.human_principal_reference:
                raise OIAAssessmentPlanRejected("trusted human plan authority is required")
            return trusted_context.human_principal_reference
        return trusted_context.human_principal_reference if trusted_context.caller_type == "HUMAN" and trusted_context.human_principal_reference else trusted_context.principal_id

    def _knowledge(self, methodology_reference, vertical_template_reference=None):
        if not self.methodology_catalog.accepts_methodology(methodology_reference):
            raise OIAAssessmentPlanRejected("methodology reference is not trusted")
        if vertical_template_reference is not None and not self.methodology_catalog.accepts_vertical_template(vertical_template_reference):
            raise OIAAssessmentPlanRejected("vertical template reference is not trusted")

    def _foundation(self, tenant_id, assessment_id, engagement_id):
        engagement = self.repositories.engagements.get(tenant_id, engagement_id)
        assessment = self.repositories.oia_assessments.get(tenant_id, assessment_id)
        if not engagement or engagement.get("engagement_state") != "OPEN":
            raise OIAAssessmentPlanRejected("an active engagement is required")
        if not assessment or assessment.get("engagement_id") != engagement_id or assessment.get("state") != "IN_PROGRESS":
            raise OIAAssessmentPlanRejected("an in-progress correlated OIA assessment is required")
        scope = self.repositories.diagnostic_scopes.get(tenant_id, assessment["diagnostic_scope_id"])
        if (
            not scope
            or scope.get("status") != "APPROVED"
            or scope.get("engagement_id") != engagement_id
            or scope.get("scope_version") != assessment.get("diagnostic_scope_version")
            or scope.get("canonical_scope_digest") != assessment.get("canonical_scope_digest")
        ):
            raise OIAAssessmentPlanRejected("assessment scope authority correlation is invalid")
        return assessment, scope

    def create(self, trusted_context, payload, created_at):
        actor = self._actor(trusted_context, "oia:plan:write")
        tenant_id = trusted_context.tenant_id
        assessment, scope = self._foundation(tenant_id, payload["oia_assessment_id"], payload["engagement_id"])
        if (
            payload["diagnostic_scope_id"] != assessment["diagnostic_scope_id"]
            or payload["diagnostic_scope_id"] != scope["diagnostic_scope_id"]
            or payload["diagnostic_scope_version"] != assessment["diagnostic_scope_version"]
            or payload["diagnostic_scope_version"] != scope["scope_version"]
            or payload["canonical_scope_digest"] != assessment["canonical_scope_digest"]
            or payload["canonical_scope_digest"] != scope["canonical_scope_digest"]
        ):
            raise OIAAssessmentPlanRejected("requested plan scope binding does not match authoritative truth")
        template = payload.get("vertical_template_reference")
        self._knowledge(payload["methodology_reference"], template)
        plan = {
            "tenant_id": tenant_id,
            "oia_assessment_plan_id": payload["oia_assessment_plan_id"],
            "engagement_id": assessment["engagement_id"],
            "oia_assessment_id": assessment["oia_assessment_id"],
            "diagnostic_scope_id": assessment["diagnostic_scope_id"],
            "diagnostic_scope_version": assessment["diagnostic_scope_version"],
            "canonical_scope_digest": assessment["canonical_scope_digest"],
            "methodology_reference": copy.deepcopy(payload["methodology_reference"]),
            "plan_version": 1,
            "state": "DRAFT",
            "objectives": copy.deepcopy(payload["objectives"]),
            "process_areas": copy.deepcopy(payload["process_areas"]),
            "completion_criteria": copy.deepcopy(payload["completion_criteria"]),
            "limitations": copy.deepcopy(payload["limitations"]),
            "record_version": 1,
            "created_by": actor,
            "created_at": created_at,
            "updated_at": created_at,
        }
        if template is not None:
            plan["vertical_template_reference"] = copy.deepcopy(template)
        return self.repositories.oia_assessment_plans.create_initial(plan)

    def revise(self, trusted_context, payload, expected_record_version, revised_at):
        actor = self._actor(trusted_context, "oia:plan:write")
        tenant_id = trusted_context.tenant_id
        current = self.repositories.oia_assessment_plans.get_current(tenant_id, payload["oia_assessment_plan_id"])
        if not current or current["record_version"] != expected_record_version:
            raise OIAAssessmentPlanRejected("plan record version is stale")
        self._foundation(tenant_id, current["oia_assessment_id"], current["engagement_id"])
        if payload["current_plan_version"] != current["plan_version"] or payload["replacement_plan_version"] != current["plan_version"] + 1:
            raise OIAAssessmentPlanRejected("plan revision lineage is invalid")
        template = payload.get("vertical_template_reference")
        self._knowledge(payload["methodology_reference"], template)
        replacement = {
            key: copy.deepcopy(current[key])
            for key in ("tenant_id", "oia_assessment_plan_id", "engagement_id", "oia_assessment_id", "diagnostic_scope_id", "diagnostic_scope_version", "canonical_scope_digest")
        }
        replacement.update({
            "methodology_reference": copy.deepcopy(payload["methodology_reference"]),
            "plan_version": payload["replacement_plan_version"],
            "supersedes_plan_version": current["plan_version"],
            "state": "DRAFT",
            "objectives": copy.deepcopy(payload["objectives"]),
            "process_areas": copy.deepcopy(payload["process_areas"]),
            "completion_criteria": copy.deepcopy(payload["completion_criteria"]),
            "limitations": copy.deepcopy(payload["limitations"]),
            "record_version": 1,
            "created_by": actor,
            "created_at": revised_at,
            "updated_at": revised_at,
        })
        if template is not None:
            replacement["vertical_template_reference"] = copy.deepcopy(template)
        return self.repositories.oia_assessment_plans.revise(current, replacement, revised_at)

    def review(self, trusted_context, payload, expected_record_version, reviewed_at):
        actor = self._actor(trusted_context, "oia:plan:review", human_only=True)
        current = self.repositories.oia_assessment_plans.get_current(trusted_context.tenant_id, payload["oia_assessment_plan_id"])
        if not current or current["plan_version"] != payload["plan_version"] or current["record_version"] != expected_record_version or current["state"] != "DRAFT":
            raise OIAAssessmentPlanRejected("plan is not reviewable")
        self._foundation(trusted_context.tenant_id, current["oia_assessment_id"], current["engagement_id"])
        return self.repositories.oia_assessment_plans.review(current, actor, reviewed_at)

    def approve(self, trusted_context, payload, expected_record_version, approved_at):
        actor = self._actor(trusted_context, "oia:plan:approve", human_only=True)
        current = self.repositories.oia_assessment_plans.get_current(trusted_context.tenant_id, payload["oia_assessment_plan_id"])
        if not current or current["plan_version"] != payload["plan_version"] or current["record_version"] != expected_record_version or current["state"] != "REVIEWED":
            raise OIAAssessmentPlanRejected("plan is not approvable")
        self._foundation(trusted_context.tenant_id, current["oia_assessment_id"], current["engagement_id"])
        return self.repositories.oia_assessment_plans.approve(current, actor, approved_at)
