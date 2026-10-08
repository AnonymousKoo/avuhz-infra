"""Source-bound, injection-only DEVELOPMENT synthetic handoff lifecycle.

NO CLI, default provider transport, configured secrets, or live authority.
A future trusted executor must first validate an exact owner-approved
authorization plan/progress with authorization_plan.py, then supply callbacks
for the exact AUTH / DATA steps. Callback truth alone does not establish
human approval. Nothing in this file grants provider mutation authority.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping

from avuhz_engineering.development_auth_token_lifecycle import (
    IssuedSession, RecoveryVerificationCredential,
)
from avuhz_engineering.development_one_shot_handoff_dispatch import (
    dispatch_one_synthetic_handoff,
)
from avuhz_engineering.development_synthetic_handoff_preflight import (
    CertifiedSyntheticCommand, SyntheticCommandPreflightStop,
    certify_synthetic_command,
)
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF,
)
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY,
)

REPOSITORY = "AnonymousKoo/avuhz-infra"
COMMAND_URL = "https://avuhz-command-dev.onrender.com/v1/commands"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_STAGES = ("AUTH_GENERATE", "AUTH_VERIFY", "DATA_COMMAND", "AUTH_GLOBAL_LOGOUT")


@dataclass(frozen=True)
class DevelopmentHandoffSource:
    repository: str
    canonical_main_sha: str
    authorization_plan_digest: str
    command_digest: str
    auth_project_ref: str
    data_project_ref: str
    command_url: str
    tenant_id: str


@dataclass(frozen=True)
class DevelopmentHandoffLifecycleResult:
    classification: str
    command_digest: str
    handoff_id: str
    generated_attempted: bool
    verification_attempted: bool
    command_attempted: bool
    global_logout_attempted: bool
    global_logout_accepted: bool
    data_readback_required: bool
    session_state_readback_required: bool
    credential_retirement_required: bool
    cleanup_verified: bool = False
    retry_authorized: bool = False
    token_material_retained: bool = False
    pii_retained: bool = False
    safe_error_code: str | None = None


def _stop(condition: bool, code: str) -> None:
    if not condition:
        raise SyntheticCommandPreflightStop(code)


def preflight_source_bound_handoff(
    request: Mapping[str, object],
    *,
    source: DevelopmentHandoffSource,
    observed_main_sha: str,
    at_utc: datetime,
) -> CertifiedSyntheticCommand:
    """Pure checks; observed_main_sha must come from trusted source verification."""
    _stop(type(source) is DevelopmentHandoffSource, "HANDOFF_SOURCE_INVALID")
    _stop(
        source.repository == REPOSITORY
        and type(source.canonical_main_sha) is str
        and _SHA.fullmatch(source.canonical_main_sha) is not None
        and source.canonical_main_sha == observed_main_sha
        and type(source.authorization_plan_digest) is str
        and _DIGEST.fullmatch(source.authorization_plan_digest) is not None
        and source.auth_project_ref == DEVELOPMENT_AUTH_PROJECT_REF
        and source.data_project_ref == DEVELOPMENT_DATA_PROJECT_REF
        and source.auth_project_ref != source.data_project_ref
        and source.command_url == COMMAND_URL
        and source.tenant_id == DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY.tenant_id,
        "HANDOFF_SOURCE_BINDING_MISMATCH",
    )
    candidate = certify_synthetic_command(request, at_utc=at_utc)
    _stop(
        candidate.tenant_id == source.tenant_id
        and candidate.command_digest == source.command_digest,
        "HANDOFF_COMMAND_DIGEST_MISMATCH",
    )
    return candidate


def execute_source_bound_handoff(
    request: Mapping[str, object],
    *,
    source: DevelopmentHandoffSource,
    observed_main_sha: str,
    at_utc: datetime,
    authorize_stage: Callable[[str, str, DevelopmentHandoffSource], bool],
    admin_secret_supplier: Callable[[], str],
    publishable_key_supplier: Callable[[], str],
    existing_user_email_supplier: Callable[[], str],
    generate: Callable[..., RecoveryVerificationCredential],
    verify: Callable[..., IssuedSession],
    validate_jwt: Callable[[str], Any],
    logout_global: Callable[..., None],
    send_once: Callable[[dict, str], tuple[int, bytes]],
) -> DevelopmentHandoffLifecycleResult:
    """At most one recovery generation, verification, command, global logout.

    AUTH project operations and DATA command require separate exact stage
    authority. The caller must have independently verified each approval with
    the canonical authorization-plan engine before returning True. Each
    callback has no default and no network path is provided by this module.
    A combined lifecycle requires *explicit* cross-resource batch approval;
    this module does not manufacture one.
    """
    candidate = preflight_source_bound_handoff(
        request, source=source, observed_main_sha=observed_main_sha, at_utc=at_utc
    )
    _stop(callable(authorize_stage), "HANDOFF_STAGE_AUTHORITY_MISSING")
    for dependency in (
        admin_secret_supplier, publishable_key_supplier, existing_user_email_supplier,
        generate, verify, validate_jwt, logout_global, send_once,
    ):
        _stop(callable(dependency), "HANDOFF_DEPENDENCY_MISSING")

    # Require explicit cleanup permission before the first potentially
    # session-creating operation. Never resolve credentials before this check.
    for stage in ("AUTH_GLOBAL_LOGOUT", "AUTH_GENERATE", "AUTH_VERIFY", "DATA_COMMAND"):
        project = (
            DEVELOPMENT_DATA_PROJECT_REF if stage == "DATA_COMMAND"
            else DEVELOPMENT_AUTH_PROJECT_REF
        )
        try:
            allowed = authorize_stage(stage, project, source)
        except Exception:
            allowed = False
        _stop(allowed is True, "HANDOFF_STAGE_AUTHORITY_UNVERIFIED")

    credential = None
    session = None
    admin_secret = publishable_key = existing_user_email = None
    generated = verified = attempted = logout_attempted = logout_accepted = False
    classification = "SYNTHETIC_HANDOFF_NOT_ATTEMPTED"
    safe_code = None
    try:
        admin_secret = admin_secret_supplier()
        publishable_key = publishable_key_supplier()
        existing_user_email = existing_user_email_supplier()
        _stop(
            type(admin_secret) is str and admin_secret.startswith("sb_secret_")
            and len(admin_secret) >= 26
            and type(publishable_key) is str
            and publishable_key.startswith("sb_publishable_")
            and len(publishable_key) >= 31
            and type(existing_user_email) is str
            and existing_user_email.endswith("@example.invalid"),
            "HANDOFF_CREDENTIAL_BOUNDARY_INVALID",
        )
        generated = True
        credential = generate(
            project_ref=source.auth_project_ref,
            admin_secret=admin_secret,
            existing_user_email=existing_user_email,
            expected_user_id=None,
            expected_subject_digest=(
                DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY.subject_digest
            ),
        )
        _stop(
            isinstance(credential, RecoveryVerificationCredential),
            "HANDOFF_RECOVERY_CREDENTIAL_INVALID",
        )
        verified = True
        session = verify(
            project_ref=source.auth_project_ref,
            publishable_key=publishable_key,
            credential=credential,
            expected_user_id=None,
        )
        _stop(isinstance(session, IssuedSession), "HANDOFF_SESSION_INVALID")
        proof = validate_jwt(session._access_text())
        identity = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
        _stop(
            getattr(proof, "algorithm", None) == "ES256"
            and getattr(proof, "subject_digest", None) == identity.subject_digest
            and getattr(proof, "tenant_id", None) == identity.tenant_id
            and getattr(proof, "caller_type", None) == "PROVIDER_ADAPTER"
            and getattr(proof, "capabilities", None) == ("implementation_handoff:accept",)
            and getattr(proof, "authority_roles", None) == ()
            and getattr(proof, "role", None) == "authenticated",
            "HANDOFF_JWT_POLICY_INVALID",
        )
        # dispatch_one_synthetic_handoff independently checks the same
        # digest, caller, tenant and full v1 contract, then sends at most once.
        outcome = dispatch_one_synthetic_handoff(
            request, at_utc=at_utc, approved_command_digest=source.command_digest,
            authorization_check=lambda exact: exact == candidate,
            access_token=session._access_text(),
            send_once=send_once,
        )
        attempted = outcome.send_attempted
        classification = outcome.classification
        safe_code = outcome.safe_error_code
    except SyntheticCommandPreflightStop:
        classification = "SYNTHETIC_HANDOFF_UNVERIFIED"
        safe_code = "HANDOFF_PREFLIGHT_OR_AUTHORITY_STOP"
    except Exception:
        # Provider exceptions may contain secrets/PII. Never expose them.
        classification = "SYNTHETIC_HANDOFF_UNVERIFIED"
        safe_code = "HANDOFF_LIFECYCLE_UNVERIFIED"
    finally:
        if session is not None:
            logout_attempted = True
            try:
                logout_global(
                    project_ref=source.auth_project_ref,
                    publishable_key=publishable_key,
                    bearer_token=session._access_text(),
                )
                logout_accepted = True
            except Exception:
                safe_code = "HANDOFF_GLOBAL_LOGOUT_UNVERIFIED"
                classification = "SYNTHETIC_HANDOFF_CLEANUP_UNVERIFIED"
            finally:
                session.clear()
                session.user_id = ""
        if credential is not None and isinstance(credential, RecoveryVerificationCredential):
            credential.clear()
        admin_secret = publishable_key = existing_user_email = None

    return DevelopmentHandoffLifecycleResult(
        classification=classification,
        command_digest=candidate.command_digest,
        handoff_id=candidate.handoff_id,
        generated_attempted=generated,
        verification_attempted=verified,
        command_attempted=attempted,
        global_logout_attempted=logout_attempted,
        global_logout_accepted=logout_accepted,
        data_readback_required=attempted,
        session_state_readback_required=verified,
        credential_retirement_required=generated,
        safe_error_code=safe_code,
    )
