"""Read-only, fail-closed assessment access usability predicate."""

from dataclasses import dataclass

from .assessment_eligibility import evaluate_assessment_eligibility

@dataclass(frozen=True)
class AssessmentAccessUsabilityResult:
    usable: bool
    reason: str | None = None

def _reference(record, identifier, reference, reference_type):
    return bool(record and reference.get("reference_type") == reference_type and reference.get("reference_id") == record.get(identifier) and reference.get("reference_version") == record.get("record_version"))

def evaluate_assessment_access_usability(repositories, trusted_tenant_id, assessment_access_grant_id, trusted_now):
    grant = repositories.assessment_access_grants.get(trusted_tenant_id, assessment_access_grant_id)
    if not grant: return AssessmentAccessUsabilityResult(False, "GRANT_NOT_FOUND")
    if grant.get("status") != "ACTIVE": return AssessmentAccessUsabilityResult(False, "GRANT_NOT_ACTIVE")
    if trusted_now < grant.get("active_from", ""): return AssessmentAccessUsabilityResult(False, "ACCESS_NOT_YET_ACTIVE")
    if trusted_now >= grant.get("expires_at", ""): return AssessmentAccessUsabilityResult(False, "ACCESS_EXPIRED")
    engagement = repositories.engagements.get(trusted_tenant_id, grant.get("engagement_id"))
    scope_ref = grant.get("diagnostic_scope_reference", {}); agreement_ref = grant.get("diagnostic_agreement_authority_reference", {}); payment_ref = grant.get("diagnostic_payment_verification_reference", {})
    scope = repositories.diagnostic_scopes.get(trusted_tenant_id, scope_ref.get("reference_id")); agreement = repositories.diagnostic_agreement_authorities.get(trusted_tenant_id, agreement_ref.get("reference_id")); payment = repositories.diagnostic_payment_verifications.get(trusted_tenant_id, payment_ref.get("reference_id"))
    if not engagement or not scope or scope.get("engagement_id") != grant.get("engagement_id") or scope_ref.get("reference_type") != "DIAGNOSTIC_SCOPE" or scope_ref.get("reference_version") != scope.get("scope_version") or grant.get("canonical_scope_digest") != scope.get("canonical_scope_digest") or grant.get("action_set_version") != scope.get("action_set_version"):
        return AssessmentAccessUsabilityResult(False, "AUTHORITY_BINDING_MISMATCH")
    if not _reference(agreement, "diagnostic_agreement_authority_id", agreement_ref, "DIAGNOSTIC_AGREEMENT_AUTHORITY") or not _reference(payment, "diagnostic_payment_verification_id", payment_ref, "DIAGNOSTIC_PAYMENT_VERIFICATION"):
        return AssessmentAccessUsabilityResult(False, "AUTHORITY_BINDING_MISMATCH")
    targets = {item.get("system_reference_id") for item in grant.get("target_system_references", ())}; approved_targets = {item.get("system_reference_id") for item in scope.get("in_scope_systems", ())}
    actions = set(grant.get("permitted_actions", ())); approved_actions = set(scope.get("permitted_actions", scope.get("permitted_diagnostic_actions", ())))
    if not targets or not targets <= approved_targets or not actions or not actions <= approved_actions:
        return AssessmentAccessUsabilityResult(False, "AUTHORITY_BINDING_MISMATCH")
    if not evaluate_assessment_eligibility(trusted_tenant_id, engagement, scope, agreement, payment, trusted_now).eligible:
        return AssessmentAccessUsabilityResult(False, "COMMERCIAL_AUTHORITY_INVALID")
    return AssessmentAccessUsabilityResult(True)
