"""Pure deterministic AssessmentAccessGrant authority projection helpers."""
import hashlib
from .canonical_scope import canonical_json_bytes
_FIELDS=("assessment_access_grant_id","tenant_id","engagement_id","diagnostic_scope_reference","canonical_scope_digest","action_set_version","diagnostic_agreement_authority_reference","diagnostic_payment_verification_reference")
def _unique_sorted(values, key):
    normalized=sorted(values,key=key)
    if len({key(value) for value in normalized})!=len(normalized): raise ValueError("duplicate authority collection member")
    return normalized
def build_assessment_access_authority_projection(grant):
    projection={field:grant[field] for field in _FIELDS}
    projection["target_system_references"] = _unique_sorted([{"system_reference_id": value["system_reference_id"]} for value in grant["target_system_references"]], lambda value: value["system_reference_id"])
    projection["permitted_actions"]=_unique_sorted(list(grant["permitted_actions"]),lambda value:value)
    return projection
def compute_assessment_access_authority_digest(grant):
    return "sha256:"+hashlib.sha256(canonical_json_bytes(build_assessment_access_authority_projection(grant))).hexdigest()
