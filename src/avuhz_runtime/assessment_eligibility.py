from dataclasses import dataclass
@dataclass(frozen=True)
class AssessmentEligibilityResult:
 eligible:bool; reasons:tuple[str,...]
def evaluate_assessment_eligibility(tenant_id,engagement,scope,agreement,payment):
 r=[]
 if not engagement or engagement.get("tenant_id")!=tenant_id or engagement.get("engagement_state") not in ("OPEN","ONBOARDING"):r.append("ENGAGEMENT_NOT_ELIGIBLE")
 if not scope or scope.get("tenant_id")!=tenant_id or scope.get("engagement_id")!=getattr(engagement,"get",lambda *_:None)("engagement_id") or scope.get("status")!="APPROVED" or not scope.get("canonical_scope_digest"):r.append("SCOPE_NOT_APPROVED")
 if not agreement:r.append("AGREEMENT_MISSING")
 elif agreement.get("tenant_id")!=tenant_id or agreement.get("engagement_id")!=engagement.get("engagement_id") or agreement.get("status")!="VERIFIED_ACTIVE" or agreement.get("scope_reference",{}).get("reference_id")!=scope.get("diagnostic_scope_id") or agreement.get("canonical_scope_digest")!=scope.get("canonical_scope_digest"):r.append("AGREEMENT_NOT_VALID")
 if not payment:r.append("PAYMENT_MISSING")
 elif payment.get("tenant_id")!=tenant_id or payment.get("engagement_id")!=engagement.get("engagement_id") or payment.get("verification_status")!="VERIFIED" or payment.get("payment_purpose")!="DIAGNOSTIC_OIA" or payment.get("diagnostic_agreement_authority_reference",{}).get("reference_id")!= (agreement or {}).get("diagnostic_agreement_authority_id"):r.append("PAYMENT_NOT_VERIFIED")
 return AssessmentEligibilityResult(not r,tuple(r))
