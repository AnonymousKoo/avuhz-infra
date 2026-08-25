"""Trusted runtime core for immutable OIA evidence provenance."""

from .assessment_access_usability import evaluate_assessment_access_usability


class OIAEvidenceRejected(ValueError):
    """Current assessment and access authority cannot record the evidence."""


class RecordOIAEvidenceHandler:
    def __init__(self, repositories):
        self.repositories = repositories

    def record(self, trusted_context, payload, engagement_id, recorded_at):
        tenant_id = trusted_context.tenant_id
        if (
            not tenant_id
            or "oia:evidence:record" not in trusted_context.capabilities
            or trusted_context.caller_type not in ("INTERNAL_SERVICE", "HUMAN")
            or not trusted_context.principal_id
        ):
            raise OIAEvidenceRejected("trusted evidence capture authority is required")
        if payload["evidence_type"] == "HUMAN_INTERVIEW_CORROBORATION" and trusted_context.caller_type != "HUMAN":
            raise OIAEvidenceRejected("human interview evidence requires a trusted human")

        assessment = self.repositories.oia_assessments.get(tenant_id, payload["oia_assessment_id"])
        if not assessment or assessment.get("state") != "IN_PROGRESS" or assessment.get("engagement_id") != engagement_id:
            raise OIAEvidenceRejected("an in-progress assessment is required")
        grant_id = assessment["assessment_access_grant_id"]
        grant = self.repositories.assessment_access_grants.get(tenant_id, grant_id)
        scope_reference = (grant or {}).get("diagnostic_scope_reference", {})
        if (
            not grant
            or grant.get("engagement_id") != assessment.get("engagement_id")
            or scope_reference.get("reference_id") != assessment.get("diagnostic_scope_id")
            or scope_reference.get("reference_version") != assessment.get("diagnostic_scope_version")
            or grant.get("canonical_scope_digest") != assessment.get("canonical_scope_digest")
        ):
            raise OIAEvidenceRejected("assessment access binding is invalid")
        usability = evaluate_assessment_access_usability(self.repositories, tenant_id, grant_id, recorded_at)
        if not usability.usable:
            raise OIAEvidenceRejected("current assessment access is not usable")
        targets = {item.get("system_reference_id") for item in grant.get("target_system_references", ())}
        if payload["source_system_reference"] not in targets:
            raise OIAEvidenceRejected("evidence target is outside assessment authority")
        if payload["scope_action"] not in set(grant.get("permitted_actions", ())):
            raise OIAEvidenceRejected("evidence action is outside assessment authority")

        evidence = {
            "tenant_id": tenant_id,
            "oia_evidence_id": payload["oia_evidence_id"],
            "oia_assessment_id": assessment["oia_assessment_id"],
            "source_system_reference": payload["source_system_reference"],
            "evidence_type": payload["evidence_type"],
            "captured_at": payload["captured_at"],
            "captured_by": trusted_context.principal_id,
            "scope_action": payload["scope_action"],
            "secure_object_reference": payload["secure_object_reference"],
            "content_digest": payload["content_digest"],
            "sensitivity": payload["sensitivity"],
            "retention_status": "AVAILABLE",
            "created_at": recorded_at,
        }
        if "excerpt_character_count" in payload:
            evidence["excerpt_character_count"] = payload["excerpt_character_count"]
        return self.repositories.oia_evidence_items.create(evidence)
