"""Deterministic approval-bound DiagnosticScope digest helpers."""
import hashlib, json

_FIELDS = ("diagnostic_scope_id", "scope_version", "engagement_id", "tenant_id", "target_outcome", "in_scope_systems", "excluded_systems", "permitted_diagnostic_actions", "prohibited_actions", "assumptions", "constraints")

def build_canonical_scope_projection(scope):
    return {field: scope[field] for field in _FIELDS}

def canonical_json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def compute_canonical_scope_digest(scope):
    return "sha256:" + hashlib.sha256(canonical_json_bytes(build_canonical_scope_projection(scope))).hexdigest()
