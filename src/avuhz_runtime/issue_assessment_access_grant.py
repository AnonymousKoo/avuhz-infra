"""Trusted in-memory core for issuing an APPROVED assessment access grant."""

from __future__ import annotations

from .assessment_access_dual_approval import evaluate_assessment_access_dual_approval
from .assessment_eligibility import evaluate_assessment_eligibility


class AssessmentAccessGrantRejected(ValueError):
    pass


class IssueAssessmentAccessGrantHandler:
    def __init__(self, repositories):
        self.repositories = repositories

    @staticmethod
    def _reference(record, identifier, reference, reference_type):
        return bool(record and reference.get("reference_type") == reference_type and reference.get("reference_id") == record.get(identifier) and reference.get("reference_version") == record.get("record_version"))

    def issue(self, trusted_context, payload, evaluated_at):
        tenant_id = trusted_context.tenant_id
        if not tenant_id or "assessment_access:issue" not in trusted_context.capabilities:
            raise AssessmentAccessGrantRejected("trusted issuance authority is required")
        proposal_id = payload["assessment_access_proposal_id"]
        proposal = self.repositories.assessment_access_proposals.get(tenant_id, proposal_id)
        if not proposal:
            raise AssessmentAccessGrantRejected("authoritative proposal is unavailable")
        if proposal.get("status") != "OPEN":
            raise AssessmentAccessGrantRejected("proposal is not open")
        approvals = evaluate_assessment_access_dual_approval(self.repositories, tenant_id, proposal_id)
        if not approvals.satisfied:
            raise AssessmentAccessGrantRejected("exact dual approval is not satisfied")
        engagement = self.repositories.engagements.get(tenant_id, proposal.get("engagement_id"))
        scope_ref = proposal.get("diagnostic_scope_reference", {})
        scope = self.repositories.diagnostic_scopes.get(tenant_id, scope_ref.get("reference_id"))
        agreement_ref = proposal.get("diagnostic_agreement_authority_reference", {})
        payment_ref = proposal.get("diagnostic_payment_verification_reference", {})
        agreement = self.repositories.diagnostic_agreement_authorities.get(tenant_id, agreement_ref.get("reference_id"))
        payment = self.repositories.diagnostic_payment_verifications.get(tenant_id, payment_ref.get("reference_id"))
        if not engagement or not scope or scope.get("engagement_id") != proposal.get("engagement_id") or scope_ref.get("reference_type") != "DIAGNOSTIC_SCOPE" or scope_ref.get("reference_version") != scope.get("scope_version") or proposal.get("canonical_scope_digest") != scope.get("canonical_scope_digest") or proposal.get("action_set_version") != scope.get("action_set_version"):
            raise AssessmentAccessGrantRejected("proposal scope authority is not current")
        if not self._reference(agreement, "diagnostic_agreement_authority_id", agreement_ref, "DIAGNOSTIC_AGREEMENT_AUTHORITY") or not self._reference(payment, "diagnostic_payment_verification_id", payment_ref, "DIAGNOSTIC_PAYMENT_VERIFICATION"):
            raise AssessmentAccessGrantRejected("proposal commercial reference is not current")
        if not evaluate_assessment_eligibility(tenant_id, engagement, scope, agreement, payment, evaluated_at).eligible:
            raise AssessmentAccessGrantRejected("commercial eligibility is not satisfied")
        targets = {item.get("system_reference_id") for item in proposal.get("target_system_references", ())}
        approved_targets = {item.get("system_reference_id") for item in scope.get("in_scope_systems", ())}
        actions = set(proposal.get("permitted_actions", ()))
        approved_actions = set(scope.get("permitted_actions", scope.get("permitted_diagnostic_actions", ())))
        if not targets or not targets <= approved_targets or not actions or not actions <= approved_actions:
            raise AssessmentAccessGrantRejected("proposal authority exceeds approved scope")
        grant = {"assessment_access_grant_id": payload["assessment_access_grant_id"], "tenant_id": tenant_id, "engagement_id": proposal["engagement_id"], "source_assessment_access_proposal_reference": {"reference_type": "ASSESSMENT_ACCESS_PROPOSAL", "reference_id": proposal_id, "reference_version": proposal["record_version"]}, "diagnostic_scope_reference": proposal["diagnostic_scope_reference"], "canonical_scope_digest": proposal["canonical_scope_digest"], "assessment_access_authority_digest": proposal["assessment_access_authority_digest"], "action_set_version": proposal["action_set_version"], "diagnostic_agreement_authority_reference": proposal["diagnostic_agreement_authority_reference"], "diagnostic_payment_verification_reference": proposal["diagnostic_payment_verification_reference"], "target_system_references": proposal["target_system_references"], "permitted_actions": proposal["permitted_actions"], "status": "APPROVED", "approved_at": evaluated_at, "record_version": 1}
        created = self.repositories.assessment_access_grants.create(grant)
        self.repositories.assessment_access_proposals.consume(tenant_id, proposal_id, proposal["assessment_access_authority_digest"], evaluated_at)
        return created
