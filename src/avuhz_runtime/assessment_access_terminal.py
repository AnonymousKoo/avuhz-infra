"""Trusted in-memory terminal reconciliation cores."""
class AssessmentAccessTerminalRejected(ValueError): pass
class AssessmentAccessTerminalHandler:
 def __init__(self,repositories):self.repositories=repositories
 def expire(self,context,payload,trusted_now):
  if not context.tenant_id or "assessment_access:expire" not in context.capabilities:raise AssessmentAccessTerminalRejected()
  try:return self.repositories.assessment_access_grants.expire(context.tenant_id,payload["assessment_access_grant_id"],trusted_now)
  except ValueError as error:raise AssessmentAccessTerminalRejected() from error
 def revoke(self,context,payload,trusted_now):
  if not context.tenant_id or "assessment_access:revoke" not in context.capabilities:raise AssessmentAccessTerminalRejected()
  try:return self.repositories.assessment_access_grants.revoke(context.tenant_id,payload["assessment_access_grant_id"],trusted_now)
  except ValueError as error:raise AssessmentAccessTerminalRejected() from error
 def close_for_agreement_end(self,context,payload,trusted_now):
  if not context.tenant_id or "assessment_access:close" not in context.capabilities:raise AssessmentAccessTerminalRejected()
  grant=self.repositories.assessment_access_grants.get(context.tenant_id,payload["assessment_access_grant_id"])
  if not grant:raise AssessmentAccessTerminalRejected()
  reference=grant.get("diagnostic_agreement_authority_reference",{});agreement=self.repositories.diagnostic_agreement_authorities.get(context.tenant_id,reference.get("reference_id"))
  if not agreement or reference.get("reference_type")!="DIAGNOSTIC_AGREEMENT_AUTHORITY" or reference.get("reference_version")!=agreement.get("record_version") or not agreement.get("ends_at") or trusted_now<agreement["ends_at"]:raise AssessmentAccessTerminalRejected()
  try:return self.repositories.assessment_access_grants.close_for_agreement_end(context.tenant_id,grant["assessment_access_grant_id"],trusted_now)
  except ValueError as error:raise AssessmentAccessTerminalRejected() from error
