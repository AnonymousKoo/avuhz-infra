"""Offline approval-state preparation for one DEVELOPMENT handoff command.

This module is deliberately repository-local and side-effect free.  It does
not authenticate an owner, resolve credentials, persist progress, contact a
provider, or execute a command.  A future trusted runner must independently
verify source provenance and atomically consume each authorized stage before
performing any separately approved operation.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanError,
    AuthorizationPlanStop,
    authorize_step,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_runtime.models import ValidationSuccess
from avuhz_runtime.validation import CommandValidator
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_DATA_PROJECT_REF,
)

SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "contracts/schemas/v1"
EXPECTED_REPOSITORY = "AnonymousKoo/avuhz-infra"
EXPECTED_OWNER = "github:AnonymousKoo"
EXPECTED_ENVIRONMENT = "DEVELOPMENT"
EXPECTED_TENANT_ID = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
DEVELOPMENT_COMMAND_URL = "https://avuhz-command-dev.onrender.com/v1/commands"
EXPECTED_STAGES = (
    "AUTH_GLOBAL_LOGOUT",
    "AUTH_GENERATE",
    "AUTH_VERIFY",
    "DATA_COMMAND",
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# These operation names identify future, separately approved plan resources.
# Their presence here creates no provider or command authority.
EXPECTED_OPERATIONS = {
    "AUTH_GLOBAL_LOGOUT": "auth.provider-adapter.global-logout-once",
    "AUTH_GENERATE": "auth.provider-adapter.recovery-generate-once",
    "AUTH_VERIFY": "auth.provider-adapter.recovery-verify-once",
    "DATA_COMMAND": "api.accept-implementation-handoff.once",
}
REQUIRED_PROHIBITIONS = frozenset({
    "auth.session.retry",
    "auth.identity.modify",
    "production.target",
    "render.mutation",
    "n8n.operation",
    "billing.change",
})


class HandoffApprovalGateStop(ValueError):
    """Fixed failure category with no untrusted or provider data in messages."""


@dataclass(frozen=True)
class DevelopmentHandoffSource:
    """Exact non-secret source bindings supplied by a trusted outer workflow."""

    repository: str
    canonical_main_sha: str
    authorization_plan_digest: str
    command_digest: str
    tenant_id: str
    auth_project_ref: str
    data_project_ref: str
    command_url: str


@dataclass(frozen=True)
class StageAuthorizationDocuments:
    """Canonical authorization documents; values are copied before validation."""

    plan: dict
    approval: dict
    progress: dict
    credential_class: str


@dataclass(frozen=True)
class ProposedAuthorizationState:
    """A state proposal for separate atomic persistence, not an execution permit."""

    stage: str
    project_reference: str
    plan_digest: str
    approval_digest: str
    authorized_progress: dict


@dataclass(frozen=True)
class GatePreflightResult:
    classification: str
    source_sha: str
    stage_authorization_digest: str
    command_digest: str
    stage: ProposedAuthorizationState
    remote_execution_authorized: bool = False
    credentials_resolved: bool = False
    data_write_attempted: bool = False


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise HandoffApprovalGateStop(code)


def _preflight_source_bound_handoff(
    request: dict,
    *,
    source: DevelopmentHandoffSource,
    observed_main_sha: str,
) -> str:
    """Validate the real command contract and exact offline source bindings."""

    _require(type(source) is DevelopmentHandoffSource, "HANDOFF_SOURCE_INVALID")
    _require(
        source.repository == EXPECTED_REPOSITORY
        and SHA_RE.fullmatch(source.canonical_main_sha) is not None
        and observed_main_sha == source.canonical_main_sha
        and DIGEST_RE.fullmatch(source.command_digest) is not None
        and source.auth_project_ref == DEVELOPMENT_AUTH_PROJECT_REF
        and source.data_project_ref == DEVELOPMENT_DATA_PROJECT_REF
        and source.tenant_id == EXPECTED_TENANT_ID
        and source.command_url == DEVELOPMENT_COMMAND_URL,
        "HANDOFF_SOURCE_BINDING_INVALID",
    )
    _require(type(request) is dict, "HANDOFF_REQUEST_SOURCE_INVALID")
    prepared = CommandValidator(SCHEMA_ROOT).prepare(copy.deepcopy(request))
    _require(isinstance(prepared, ValidationSuccess), "HANDOFF_REQUEST_SOURCE_INVALID")
    command = prepared.prepared
    _require(
        command.command_type == "AcceptImplementationHandoff"
        and command.environment == EXPECTED_ENVIRONMENT
        and command.tenant_id == source.tenant_id
        and command.payload.get("tenant_id") == source.tenant_id
        and request.get("caller_type") == "PROVIDER_ADAPTER"
        and request.get("caller_identity", {}).get("environment") == EXPECTED_ENVIRONMENT
        and request.get("caller_identity", {}).get("tenant_ids") == [source.tenant_id]
        and request.get("caller_identity", {}).get("capabilities")
        == ["implementation_handoff:accept"],
        "HANDOFF_REQUEST_SOURCE_INVALID",
    )
    digest = canonical_digest(request)
    _require(digest == source.command_digest, "HANDOFF_REQUEST_SOURCE_INVALID")
    return digest


def _bound_stage_resource_digest(source: DevelopmentHandoffSource, stage: str) -> str:
    """Bind one stage to the command, repository source, tenant, and projects."""

    return canonical_digest({
        "repository": source.repository,
        "canonical_main_sha": source.canonical_main_sha,
        "command_digest": source.command_digest,
        "tenant_id": source.tenant_id,
        "auth_project_ref": source.auth_project_ref,
        "data_project_ref": source.data_project_ref,
        "command_url": source.command_url,
        "stage": stage,
        "project_ref": (
            source.data_project_ref if stage == "DATA_COMMAND"
            else source.auth_project_ref
        ),
    })


def stage_authorization_digest(
    stage: str,
    documents: StageAuthorizationDocuments,
) -> str:
    """Bind one stage to one exact plan and approval without batch authority."""

    _require(stage in EXPECTED_STAGES, "HANDOFF_APPROVAL_STAGE_INVALID")
    try:
        member = {
            "stage": stage,
            "plan_digest": documents.plan["plan_digest"],
            "approval_digest": documents.approval["approval_digest"],
        }
    except (AttributeError, KeyError, TypeError):
        raise HandoffApprovalGateStop("HANDOFF_APPROVAL_STAGE_INVALID") from None
    return canonical_digest(member)


def prepare_handoff_stage_approval_state(
    request: dict,
    *,
    source: DevelopmentHandoffSource,
    observed_main_sha: str,
    at_utc: datetime,
    stage: str,
    documents: StageAuthorizationDocuments,
    owner_source_verified: bool,
    observed_owner_identity: str,
    stage_authorization_attested_digest: str,
) -> GatePreflightResult:
    """Return one proposed authorization state without external side effects.

    Owner verification and the attested stage digest must originate from a
    separately trusted GitHub provenance verifier.  A caller-provided Boolean
    alone is never proof of owner authority.
    """

    _require(owner_source_verified is True and observed_owner_identity == EXPECTED_OWNER,
             "HANDOFF_APPROVAL_PROVENANCE_UNVERIFIED")
    _require(type(observed_main_sha) is str and SHA_RE.fullmatch(observed_main_sha) is not None,
             "HANDOFF_SOURCE_SHA_INVALID")
    _require(isinstance(at_utc, datetime) and at_utc.tzinfo is not None,
             "HANDOFF_AUTHORIZATION_TIME_INVALID")
    command_digest = _preflight_source_bound_handoff(
        request, source=source, observed_main_sha=observed_main_sha,
    )
    _require(stage in EXPECTED_STAGES, "HANDOFF_APPROVAL_STAGE_INVALID")
    _require(type(documents) is StageAuthorizationDocuments,
             "HANDOFF_APPROVAL_STAGE_INVALID")
    authorization_digest = stage_authorization_digest(stage, documents)
    _require(
        documents.plan.get("plan_digest") == source.authorization_plan_digest
        and authorization_digest == stage_authorization_attested_digest,
        "HANDOFF_APPROVAL_BINDING_MISMATCH",
    )
    now = at_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    plan, approval, progress = (
        copy.deepcopy(documents.plan),
        copy.deepcopy(documents.approval),
        copy.deepcopy(documents.progress),
    )
    _require(type(plan) is dict and type(approval) is dict and type(progress) is dict,
             "HANDOFF_APPROVAL_STAGE_INVALID")
    _require(
        type(plan.get("target")) is dict
        and type(plan.get("steps")) is list
        and len(plan["steps"]) == 1
        and type(plan["steps"][0]) is dict,
        "HANDOFF_APPROVAL_STAGE_INVALID",
    )
    project = (
        DEVELOPMENT_DATA_PROJECT_REF if stage == "DATA_COMMAND"
        else DEVELOPMENT_AUTH_PROJECT_REF
    )
    responsibility = "DATA" if stage == "DATA_COMMAND" else "AUTH"
    _require(
        plan.get("environment") == EXPECTED_ENVIRONMENT
        and plan.get("owner_identity") == EXPECTED_OWNER
        and plan.get("authority_effect") == "NONE_UNTIL_SEPARATELY_APPROVED"
        and plan["target"].get("provider_reference") == "supabase"
        and plan["target"].get("project_reference") == project
        and plan["target"].get("responsibility") == responsibility
        and approval.get("owner_identity") == EXPECTED_OWNER
        and approval.get("decision") == "APPROVE"
        and approval.get("status") == "ACTIVE"
        and approval.get("authority_scope") == "EXACT_PLAN_ONLY"
        and type(progress.get("step_states")) is list
        and len(progress["step_states"]) == 1,
        "HANDOFF_APPROVAL_SCOPE_INVALID",
    )
    step = plan["steps"][0]
    resource = step.get("resource")
    _require(type(resource) is dict, "HANDOFF_APPROVAL_RESOURCE_MISMATCH")
    step_prohibitions = step.get("prohibited_actions")
    plan_prohibitions = plan.get("prohibited_actions")
    _require(
        step.get("operation") == EXPECTED_OPERATIONS[stage]
        and step.get("execution_class") == "PROVIDER_MUTATION"
        and resource.get("binding_state") == "BOUND"
        and resource.get("exact_digest") == _bound_stage_resource_digest(source, stage)
        and type(step_prohibitions) is list
        and all(type(item) is str for item in step_prohibitions)
        and REQUIRED_PROHIBITIONS <= set(step_prohibitions)
        and type(plan_prohibitions) is list
        and all(type(item) is str for item in plan_prohibitions)
        and REQUIRED_PROHIBITIONS <= set(plan_prohibitions)
        and not step.get("unresolved_bindings"),
        "HANDOFF_APPROVAL_RESOURCE_MISMATCH",
    )
    requirements = step.get("required_evidence", [])
    _require(
        type(requirements) is list
        and all(
            type(item) is dict
            and item.get("binding_state") == "BOUND"
            and item.get("source_step_id") is None
            and item.get("exact_digest") is not None
            for item in requirements
        ),
        "HANDOFF_APPROVAL_EVIDENCE_INVALID",
    )
    try:
        auth_request = {
            "plan_id": plan["plan_id"],
            "plan_version": plan["plan_version"],
            "plan_digest": plan["plan_digest"],
            "environment": plan["environment"],
            "provider_reference": plan["target"]["provider_reference"],
            "project_reference": plan["target"]["project_reference"],
            "responsibility": plan["target"]["responsibility"],
            "issuer_reference": plan["target"]["issuer_reference"],
            "audience_reference": plan["target"]["audience_reference"],
            "step_id": step["step_id"],
            "resource_reference": resource["resource_reference"],
            "resource_version": resource["exact_version"],
            "resource_digest": resource["exact_digest"],
            "operation": step["operation"],
            "execution_class": step["execution_class"],
            "credential_class": documents.credential_class,
            "required_evidence": [
                {
                    "evidence_type": item["evidence_type"],
                    "evidence_digest": item["exact_digest"],
                }
                for item in requirements
            ],
            "prior_evidence_digests": [],
            "unexpected_remote_state": False,
            "extra_privileges": False,
            "unauthorized_migration_surface": False,
            "scope_expansion": False,
        }
    except (KeyError, TypeError):
        raise HandoffApprovalGateStop("HANDOFF_APPROVAL_STAGE_INVALID") from None
    try:
        updated = authorize_step(plan, approval, progress, auth_request, SCHEMA_ROOT, now)
    except (AuthorizationPlanError, AuthorizationPlanStop):
        raise HandoffApprovalGateStop("HANDOFF_AUTHORIZATION_ENGINE_DENIED") from None
    except Exception:
        raise HandoffApprovalGateStop("HANDOFF_AUTHORIZATION_ENGINE_UNVERIFIED") from None
    try:
        verified = (
            updated["step_states"][0]["authorization_state"] == "AUTHORIZED"
            and updated["step_states"][0]["authorization_consumed"] is False
        )
    except (KeyError, IndexError, TypeError):
        verified = False
    _require(verified, "HANDOFF_AUTHORIZATION_ENGINE_UNVERIFIED")
    proposed = ProposedAuthorizationState(
        stage=stage,
        project_reference=project,
        plan_digest=plan["plan_digest"],
        approval_digest=approval["approval_digest"],
        authorized_progress=updated,
    )

    return GatePreflightResult(
        classification="OFFLINE_SINGLE_STAGE_AUTHORIZATION_PREPARED_PENDING_ATOMIC_CONSUMPTION",
        source_sha=observed_main_sha,
        stage_authorization_digest=authorization_digest,
        command_digest=command_digest,
        stage=proposed,
    )
