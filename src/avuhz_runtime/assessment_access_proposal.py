"""Trusted runtime core for creating immutable assessment access proposals."""

from __future__ import annotations

from .assessment_access_authority import compute_assessment_access_authority_digest
from .assessment_eligibility import evaluate_assessment_eligibility


class AssessmentAccessProposalRejected(ValueError):
    """The authoritative inputs cannot produce an OPEN proposal."""


class CreateAssessmentAccessProposalHandler:
    """Creates one narrowed proposal from trusted context and authoritative records."""

    def __init__(self, repositories):
        self.repositories = repositories

    @staticmethod
    def _exact_reference(record, identifier_field, reference, reference_type):
        return (
            record
            and reference.get("reference_type") == reference_type
            and reference.get("reference_id") == record.get(identifier_field)
            and reference.get("reference_version") == record.get("record_version")
        )

    @staticmethod
    def _target_ids(targets):
        values = [target.get("system_reference_id") for target in targets if isinstance(target, dict)]
        if not values or len(values) != len(targets) or len(set(values)) != len(values):
            raise AssessmentAccessProposalRejected("requested targets must be a non-empty semantic set")
        return tuple(sorted(values))

    @staticmethod
    def _actions(actions):
        if not actions or any(not isinstance(action, str) for action in actions) or len(set(actions)) != len(actions):
            raise AssessmentAccessProposalRejected("requested actions must be a non-empty semantic set")
        return tuple(sorted(actions))

    def create(self, trusted_context, payload, evaluated_at):
        tenant_id = trusted_context.tenant_id
        if not tenant_id:
            raise AssessmentAccessProposalRejected("trusted tenant context is required")
        repositories = self.repositories
        engagement = repositories.engagements.get(tenant_id, payload["engagement_id"])
        scope = repositories.diagnostic_scopes.get(tenant_id, payload["diagnostic_scope_id"])
        if not engagement or not scope or scope.get("engagement_id") != engagement.get("engagement_id"):
            raise AssessmentAccessProposalRejected("authoritative engagement and scope are required")
        if scope.get("scope_version") != payload["scope_version"] or scope.get("status") != "APPROVED":
            raise AssessmentAccessProposalRejected("exact approved scope is required")
        agreement_ref = payload["diagnostic_agreement_authority_reference"]
        payment_ref = payload["diagnostic_payment_verification_reference"]
        agreement = repositories.diagnostic_agreement_authorities.get(tenant_id, agreement_ref["reference_id"])
        payment = repositories.diagnostic_payment_verifications.get(tenant_id, payment_ref["reference_id"])
        if not self._exact_reference(agreement, "diagnostic_agreement_authority_id", agreement_ref, "DIAGNOSTIC_AGREEMENT_AUTHORITY"):
            raise AssessmentAccessProposalRejected("exact agreement authority is required")
        if not self._exact_reference(payment, "diagnostic_payment_verification_id", payment_ref, "DIAGNOSTIC_PAYMENT_VERIFICATION"):
            raise AssessmentAccessProposalRejected("exact payment verification is required")
        eligibility = evaluate_assessment_eligibility(tenant_id, engagement, scope, agreement, payment, evaluated_at)
        if not eligibility.eligible:
            raise AssessmentAccessProposalRejected("commercial eligibility is not satisfied")
        target_ids = self._target_ids(payload["target_system_references"])
        approved_target_ids = {target.get("system_reference_id") for target in scope.get("in_scope_systems", ())}
        if not set(target_ids) <= approved_target_ids:
            raise AssessmentAccessProposalRejected("requested target is outside approved scope")
        actions = self._actions(payload["permitted_actions"])
        approved_actions = set(scope.get("permitted_actions", scope.get("permitted_diagnostic_actions", ())))
        if not set(actions) <= approved_actions:
            raise AssessmentAccessProposalRejected("requested action is outside approved scope")
        proposal = {"assessment_access_proposal_id": payload["assessment_access_proposal_id"], "tenant_id": tenant_id, "engagement_id": engagement["engagement_id"], "diagnostic_scope_reference": {"reference_type": "DIAGNOSTIC_SCOPE", "reference_id": scope["diagnostic_scope_id"], "reference_version": scope["scope_version"]}, "canonical_scope_digest": scope["canonical_scope_digest"], "action_set_version": scope["action_set_version"], "diagnostic_agreement_authority_reference": agreement_ref, "diagnostic_payment_verification_reference": payment_ref, "target_system_references": [{"system_reference_id": target_id} for target_id in target_ids], "permitted_actions": list(actions), "status": "OPEN", "created_at": evaluated_at, "record_version": 1}
        proposal["assessment_access_authority_digest"] = compute_assessment_access_authority_digest(proposal)
        return repositories.assessment_access_proposals.create(proposal)
