"""Sanitized diagnostics for DEVELOPMENT positive-auth lifecycle failures.

This module deliberately accepts only a safe error code, never an exception,
provider payload, credential, token, identity, or PII. Unknown values collapse
to AUTHORITY_INVALID/unknown so callers cannot accidentally turn diagnostics
into a secret or provider-response logging channel.
"""
from __future__ import annotations

from typing import Final

SAFE_FAILURE_STAGE_BY_CODE: Final[dict[str, str]] = {
    "APPROVAL_INVALID": "authorization_preflight",
    "AUTHORITY_INVALID": "authorization_preflight",
    "AUTHORIZATION_WINDOW_INACTIVE": "authorization_preflight",
    "PLAN_STATE_INVALID": "authorization_preflight",
    "PROJECT_MISMATCH": "authorization_preflight",
    "WORKFLOW_BINDING_MISMATCH": "authorization_preflight",
    "CREDENTIAL_UNAVAILABLE": "credential_resolution",
    "RECOVERY_CREDENTIAL_UNAVAILABLE": "recovery_generate",
    "RECOVERY_GENERATE_IDENTITY_MISMATCH": "recovery_generate",
    "RECOVERY_GENERATE_PROVIDER_REJECTED": "recovery_generate",
    "RECOVERY_GENERATE_REQUEST_FAILED": "recovery_generate",
    "RECOVERY_GENERATE_RESPONSE_INVALID": "recovery_generate",
    "RECOVERY_GENERATE_RESPONSE_SHAPE_INVALID": "recovery_generate",
    "RECOVERY_VERIFICATION_PROVIDER_REJECTED": "recovery_verify",
    "RECOVERY_VERIFICATION_REQUEST_FAILED": "recovery_verify",
    "RECOVERY_VERIFICATION_RESPONSE_INVALID": "recovery_verify",
    "RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID": "recovery_verify",
    "ACCESS_JWT_VALIDATION_FAILED": "jwt_validation",
    "LIVE_AUTH_PROBE_FAILED": "live_runtime_probe",
    "GLOBAL_SESSION_LOGOUT_PROVIDER_REJECTED": "global_logout",
    "GLOBAL_SESSION_LOGOUT_REQUEST_FAILED": "global_logout",
    "GLOBAL_SESSION_LOGOUT_RESPONSE_INVALID": "global_logout",
    "POSITIVE_AUTH_FAILED_LOGOUT_UNVERIFIED": "cleanup_logout",
}

SAFE_ERROR_CODES: Final[frozenset[str]] = frozenset(SAFE_FAILURE_STAGE_BY_CODE)


def sanitized_positive_auth_failure(
    safe_error_code: str | None,
    *,
    provider_mutation_attempted: bool,
) -> dict[str, object]:
    """Return bounded failure telemetry without accepting sensitive material."""
    code = safe_error_code if safe_error_code in SAFE_ERROR_CODES else "AUTHORITY_INVALID"
    return {
        "classification": "PROVIDER_ADAPTER_POSITIVE_AUTH_UNVERIFIED",
        "safe_error_code": code,
        "failure_stage": SAFE_FAILURE_STAGE_BY_CODE.get(code, "unknown"),
        "provider_mutation_attempted": provider_mutation_attempted,
        "cleanup_verified": False,
        "ordinary_later_steps_authorized": False,
        "retry_authorized": False,
        "credential_material_retained": False,
        "token_material_retained": False,
        "provider_payload_retained": False,
        "pii_retained": False,
    }
