from dataclasses import dataclass
from datetime import datetime
@dataclass(frozen=True)
class AssessmentEligibilityResult:
 eligible:bool; reasons:tuple[str,...]
def evaluate_assessment_eligibility(tenant_id,engagement,scope,agreement,payment,evaluated_at):
 r=[]
 if not engagement or engagement.get('tenant_id')!=tenant_id or engagement.get('engagement_state') not in ('OPEN','ONBOARDING'):r.append('ENGAGEMENT_NOT_ELIGIBLE')
 if not scope or scope.get('tenant_id')!=tenant_id or not engagement or scope.get('engagement_id')!=engagement.get('engagement_id') or scope.get('status')!='APPROVED' or not scope.get('canonical_scope_digest'):r.append('SCOPE_NOT_APPROVED')
 if not agreement:r.append('AGREEMENT_MISSING')
 else:
  ref=agreement.get('scope_reference',{}); bad=agreement.get('tenant_id')!=tenant_id or not engagement or agreement.get('engagement_id')!=engagement.get('engagement_id') or not scope or ref.get('reference_id')!=scope.get('diagnostic_scope_id') or ref.get('reference_version')!=scope.get('scope_version') or agreement.get('canonical_scope_digest')!=scope.get('canonical_scope_digest')
  if bad:r.append('AGREEMENT_BINDING_MISMATCH')
  elif agreement.get('status')!='VERIFIED_ACTIVE' or evaluated_at<agreement.get('effective_at','') or (agreement.get('ends_at') and evaluated_at>=agreement['ends_at']):r.append('AGREEMENT_NOT_VALID')
 if not payment:r.append('PAYMENT_MISSING')
 elif payment.get('tenant_id')!=tenant_id or not engagement or payment.get('engagement_id')!=engagement.get('engagement_id') or payment.get('diagnostic_agreement_authority_reference',{}).get('reference_id')!=(agreement or {}).get('diagnostic_agreement_authority_id'):r.append('PAYMENT_BINDING_MISMATCH')
 elif payment.get('payment_purpose')!='DIAGNOSTIC_OIA' or payment.get('verification_status')!='VERIFIED':r.append('PAYMENT_NOT_VERIFIED')
 return AssessmentEligibilityResult(not r,tuple(r))
