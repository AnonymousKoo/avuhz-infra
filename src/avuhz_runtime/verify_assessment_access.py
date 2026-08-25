"""Trusted in-memory core for the one-way APPROVED to ACTIVE grant transition."""

from datetime import datetime, timedelta, timezone

from .assessment_access_verification import AssessmentAccessVerificationRequest
from .assessment_eligibility import evaluate_assessment_eligibility

class AssessmentAccessVerificationRejected(ValueError):
    pass

class VerifyAssessmentAccessHandler:
    def __init__(self, repositories, verifier):
        self.repositories = repositories
        self.verifier = verifier

    @staticmethod
    def _reference(record, identifier, reference, reference_type):
        return bool(record and reference.get("reference_type") == reference_type and reference.get("reference_id") == record.get(identifier) and reference.get("reference_version") == record.get("record_version"))

    @staticmethod
    def _expiry(verified_at, agreement):
        verified = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
        ttl_expiry = verified + timedelta(days=30)
        end = agreement.get("ends_at")
        if end:
            agreement_end = datetime.fromisoformat(end.replace("Z", "+00:00"))
            if agreement_end < ttl_expiry:
                return end
        return ttl_expiry.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def verify(self, trusted_context, payload, verified_at):
        tenant_id = trusted_context.tenant_id
        if not tenant_id or "assessment_access:verify" not in trusted_context.capabilities:
            raise AssessmentAccessVerificationRejected("trusted verification authority is required")
        grant = self.repositories.assessment_access_grants.get(tenant_id, payload["assessment_access_grant_id"])
        if not grant:
            raise AssessmentAccessVerificationRejected("authoritative grant is unavailable")
        if grant.get("status") != "APPROVED":
            raise AssessmentAccessVerificationRejected("grant is not approved")
        engagement = self.repositories.engagements.get(tenant_id, grant.get("engagement_id"))
        scope_ref = grant.get("diagnostic_scope_reference", {})
        agreement_ref = grant.get("diagnostic_agreement_authority_reference", {})
        payment_ref = grant.get("diagnostic_payment_verification_reference", {})
        scope = self.repositories.diagnostic_scopes.get(tenant_id, scope_ref.get("reference_id"))
        agreement = self.repositories.diagnostic_agreement_authorities.get(tenant_id, agreement_ref.get("reference_id"))
        payment = self.repositories.diagnostic_payment_verifications.get(tenant_id, payment_ref.get("reference_id"))
        if not engagement or not scope or scope.get("engagement_id") != grant.get("engagement_id") or scope_ref.get("reference_type") != "DIAGNOSTIC_SCOPE" or scope_ref.get("reference_version") != scope.get("scope_version") or grant.get("canonical_scope_digest") != scope.get("canonical_scope_digest") or grant.get("action_set_version") != scope.get("action_set_version"):
            raise AssessmentAccessVerificationRejected("grant scope authority is not current")
        if not self._reference(agreement, "diagnostic_agreement_authority_id", agreement_ref, "DIAGNOSTIC_AGREEMENT_AUTHORITY") or not self._reference(payment, "diagnostic_payment_verification_id", payment_ref, "DIAGNOSTIC_PAYMENT_VERIFICATION"):
            raise AssessmentAccessVerificationRejected("grant commercial reference is not current")
        if not evaluate_assessment_eligibility(tenant_id, engagement, scope, agreement, payment, verified_at).eligible:
            raise AssessmentAccessVerificationRejected("commercial eligibility is not satisfied")
        targets = {item.get("system_reference_id") for item in grant.get("target_system_references", ())}
        approved_targets = {item.get("system_reference_id") for item in scope.get("in_scope_systems", ())}
        actions = set(grant.get("permitted_actions", ()))
        approved_actions = set(scope.get("permitted_actions", scope.get("permitted_diagnostic_actions", ())))
        if not targets or not targets <= approved_targets or not actions or not actions <= approved_actions:
            raise AssessmentAccessVerificationRejected("grant authority exceeds approved scope")
        request = AssessmentAccessVerificationRequest.from_grant(grant)
        result = self.verifier.verify(request)
        verified_targets = {target.target_system_reference for target in result.target_results if target.success}
        if not result.success or verified_targets != set(request.target_system_references) or len(result.target_results) != len(request.target_system_references):
            raise AssessmentAccessVerificationRejected("technical verification did not succeed")
        return self.repositories.assessment_access_grants.activate(tenant_id, grant["assessment_access_grant_id"], grant["assessment_access_authority_digest"], verified_at, self._expiry(verified_at, agreement))
