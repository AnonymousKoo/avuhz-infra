"""Trusted-human runtime core for assessment access proposal approvals."""

from __future__ import annotations

from .guards import GuardPipeline


class AssessmentAccessApprovalRejected(ValueError):

    pass
class RecordAssessmentAccessApprovalHandler:
    """Records one attributable ACTIVE approval for one exact OPEN proposal."""

    def __init__(self, repositories, guard_pipeline=None):
        self.repositories = repositories
        self.guard_pipeline = guard_pipeline or GuardPipeline()

    def record(self, trusted_context, payload, evaluated_at, approval_id, correlation_id, idempotency_key):
        tenant_id = trusted_context.tenant_id
        authority_role = payload["authority_role"]
        authority_failure = self.guard_pipeline.human_approval_authority(trusted_context, authority_role)
        if authority_failure:
            raise AssessmentAccessApprovalRejected(authority_failure.message)
        proposal = self.repositories.assessment_access_proposals.get(tenant_id, payload["assessment_access_proposal_id"])
        if not proposal:
            raise AssessmentAccessApprovalRejected("authoritative proposal is unavailable")
        if proposal.get("status") != "OPEN":
            raise AssessmentAccessApprovalRejected("proposal is not open")
        digest = proposal.get("assessment_access_authority_digest")
        category = "CLIENT_AUTHORITY" if authority_role == "CLIENT_DECISION_AUTHORITY" else "SEKINFRA_AUTHORITY"
        if not digest:
            raise AssessmentAccessApprovalRejected("proposal authority digest is unavailable")
        if self.repositories.human_approvals.find_active_assessment_access_binding(tenant_id, proposal["assessment_access_proposal_id"], digest, authority_role):
            raise AssessmentAccessApprovalRejected("active authority approval already exists")
        approval = {"approval_id": approval_id, "tenant_id": tenant_id, "engagement_id": proposal["engagement_id"], "subject_type": "ASSESSMENT_ACCESS_PROPOSAL", "subject_id": proposal["assessment_access_proposal_id"], "approval_category": "ASSESSMENT_ACCESS", "authority_category": category, "actor_identity": trusted_context.human_principal_reference, "actor_organization": trusted_context.human_organization_reference, "actor_role": authority_role, "decision": "APPROVE", "assessment_access": {"assessment_access_proposal_id": proposal["assessment_access_proposal_id"], "assessment_access_authority_digest": digest}, "conditions": [], "effective_at": evaluated_at, "evidence_reference": {"reference_type": "COMMAND", "reference_id": approval_id}, "status": "ACTIVE", "correlation_id": correlation_id, "idempotency_key": idempotency_key, "created_at": evaluated_at}
        self.repositories.human_approvals.record_assessment_access(approval)
        return approval
