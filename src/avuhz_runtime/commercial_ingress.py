"""Trusted provider-neutral in-memory commercial authority ingress."""
class CommercialIngressRejected(ValueError): pass
class DiagnosticCommercialIngressHandler:
 def __init__(self,repositories):self.repositories=repositories
 def _trusted(self,context,capability):
  if not context.tenant_id or capability not in context.capabilities:raise CommercialIngressRejected()
  return context.tenant_id
 def record_agreement(self,context,payload,trusted_now):
  tenant=self._trusted(context,"diagnostic_agreement:record");r=self.repositories;engagement=r.engagements.get(tenant,payload["engagement_id"]);scope=r.diagnostic_scopes.get(tenant,payload["diagnostic_scope_id"])
  if not engagement or not scope or scope.get("engagement_id")!=engagement.get("engagement_id") or scope.get("scope_version")!=payload["scope_version"] or scope.get("status")!="APPROVED" or not scope.get("canonical_scope_digest"):raise CommercialIngressRejected()
  if payload.get("ends_at") and payload["ends_at"]<=payload["effective_at"]:raise CommercialIngressRejected()
  record={"diagnostic_agreement_authority_id":payload["diagnostic_agreement_authority_id"],"tenant_id":tenant,"engagement_id":engagement["engagement_id"],"agreement_type":"DIAGNOSTIC_OIA","agreement_reference":payload["agreement_reference"],"status":"VERIFIED_ACTIVE","scope_reference":{"reference_type":"DIAGNOSTIC_SCOPE","reference_id":scope["diagnostic_scope_id"],"reference_version":scope["scope_version"]},"canonical_scope_digest":scope["canonical_scope_digest"],"effective_at":payload["effective_at"],"verified_at":trusted_now,"recorded_at":trusted_now,"record_version":1}
  if payload.get("ends_at"):record["ends_at"]=payload["ends_at"]
  try:return r.diagnostic_agreement_authorities.create(record)
  except ValueError as error:raise CommercialIngressRejected() from error
 def record_payment(self,context,payload,trusted_now):
  tenant=self._trusted(context,"diagnostic_payment:record");r=self.repositories;engagement=r.engagements.get(tenant,payload["engagement_id"]);ref=payload["diagnostic_agreement_authority_reference"];agreement=r.diagnostic_agreement_authorities.get(tenant,ref["reference_id"])
  if not engagement or not agreement or agreement.get("engagement_id")!=engagement.get("engagement_id") or ref.get("reference_type")!="DIAGNOSTIC_AGREEMENT_AUTHORITY" or ref.get("reference_version")!=agreement.get("record_version"):raise CommercialIngressRejected()
  record={"diagnostic_payment_verification_id":payload["diagnostic_payment_verification_id"],"tenant_id":tenant,"engagement_id":engagement["engagement_id"],"diagnostic_agreement_authority_reference":{"reference_type":"DIAGNOSTIC_AGREEMENT_AUTHORITY","reference_id":agreement["diagnostic_agreement_authority_id"],"reference_version":agreement["record_version"]},"payment_purpose":"DIAGNOSTIC_OIA","verification_status":"VERIFIED","provider_reference":payload["provider_reference"],"amount_minor":payload["amount_minor"],"currency":payload["currency"],"verified_at":trusted_now,"record_version":1}
  try:return r.diagnostic_payment_verifications.create(record)
  except ValueError as error:raise CommercialIngressRejected() from error
 def invalidate_payment(self,context,payload,trusted_now):
  tenant=self._trusted(context,"diagnostic_payment:invalidate")
  try:return self.repositories.diagnostic_payment_verifications.invalidate(tenant,payload["diagnostic_payment_verification_id"],trusted_now)
  except ValueError as error:raise CommercialIngressRejected() from error
