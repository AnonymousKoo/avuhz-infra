"""Phase 5D-D4 exact bounded deployment authority; never deployment execution."""
from __future__ import annotations

import copy
import re

from .implementation_handoff import canonical_digest
from .phase5d_brief import reference
from .phase5d_client_acceptance import (
    ClientAcceptanceReadService,
    _exact_sources as _exact_acceptance_sources,
)


DEPLOYMENT_AUTHORIZATION_COMMANDS = (
    "ProposeDeploymentAuthorization",
    "ReviseDeploymentAuthorization",
    "RecordDeploymentAuthorizationApproval",
    "ActivateDeploymentAuthorization",
    "RevokeDeploymentAuthorization",
)
DEPLOYMENT_AUTHORIZATION_CAPABILITIES = {
    "ProposeDeploymentAuthorization": "deployment_authorization:propose",
    "ReviseDeploymentAuthorization": "deployment_authorization:propose",
    "RecordDeploymentAuthorizationApproval": "deployment_authorization:approve",
    "ActivateDeploymentAuthorization": "deployment_authorization:activate",
    "RevokeDeploymentAuthorization": "deployment_authorization:revoke",
}
DEPLOYMENT_AUTHORIZATION_EVENTS = {
    "ProposeDeploymentAuthorization": "deployment_authorization.proposed",
    "ReviseDeploymentAuthorization": "deployment_authorization.revised",
    "RecordDeploymentAuthorizationApproval": "deployment_authorization.approval_recorded",
    "ActivateDeploymentAuthorization": "deployment_authorization.activated",
    "RevokeDeploymentAuthorization": "deployment_authorization.revoked",
}
DEPLOYMENT_AUTHORIZATION_CALLERS = {
    "ProposeDeploymentAuthorization": frozenset({"HUMAN", "INTERNAL_SERVICE"}),
    "ReviseDeploymentAuthorization": frozenset({"HUMAN", "INTERNAL_SERVICE"}),
    "RecordDeploymentAuthorizationApproval": frozenset({"HUMAN"}),
    "ActivateDeploymentAuthorization": frozenset({"INTERNAL_SERVICE"}),
    "RevokeDeploymentAuthorization": frozenset({"HUMAN"}),
}
DEPLOYMENT_AUTHORITY_ROLES = frozenset({
    "CLIENT_DEPLOYMENT_AUTHORITY",
    "PROVIDER_DEPLOYMENT_AUTHORITY",
})
PERMITTED_DEPLOYMENT_ACTIONS = frozenset({
    "DEPLOY_EXACT_ARTIFACT",
    "ROLLBACK_EXACT_ARTIFACT",
})
REQUIRED_PROHIBITED_DEPLOYMENT_ACTIONS = frozenset({
    "ARTIFACT_SUBSTITUTION",
    "TARGET_WIDENING",
    "ENVIRONMENT_WIDENING",
    "PERMISSION_WIDENING",
    "CREDENTIAL_ROTATION",
    "DATA_DELETION",
    "BILLING_CHANGE",
    "UNAUTHORIZED_PRODUCTION_CHANGE",
    "OUT_OF_SCOPE_NETWORK_CHANGE",
    "OUT_OF_SCOPE_SECURITY_CONTROL_CHANGE",
})
AUTHORITY_BODY_FIELDS = (
    "deployment_authorization_id",
    "authorization_version",
    "implementation_authorization_reference",
    "implementation_authority_digest",
    "codex_build_package_reference",
    "package_digest",
    "build_execution_reference",
    "build_execution_digest",
    "qa_result_reference",
    "qa_result_digest",
    "client_acceptance_reference",
    "client_acceptance_digest",
    "artifact_reference",
    "target_environment",
    "target_resources",
    "permitted_deployment_actions",
    "prohibited_deployment_actions",
    "rollback_recovery_requirement",
    "effective_at",
    "expires_at",
    "supersedes_deployment_authorization_reference",
)

_SECRET = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key)\s*[:=]\s*\S+|bearer\s+[a-z0-9._~+/=-]{8,}"
)
_AUTHENTICATED_URL = re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql)://[^\s/:]+:[^\s/@]+@")


def _walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _walk_strings(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_strings(child)


def _safe_payload(payload):
    if any(_SECRET.search(value) or _AUTHENTICATED_URL.search(value)
           for value in _walk_strings(payload)):
        raise ValueError("credential or secret-bearing deployment material is prohibited")


def deployment_authority_digest(payload):
    """Digest the exact immutable bounded authority body, excluding the digest itself."""
    return canonical_digest({
        field: copy.deepcopy(payload.get(field))
        for field in AUTHORITY_BODY_FIELDS
        if field in payload
    })


def _exact_prerequisites(uow, tenant_id, engagement_id, payload, now):
    build, package, qa = _exact_acceptance_sources(
        uow, tenant_id, engagement_id, payload, now
    )
    acceptance_ref = payload["client_acceptance_reference"]
    acceptance = uow.client_acceptances.get_version(
        tenant_id, acceptance_ref["reference_id"], acceptance_ref["reference_version"]
    )
    if (
        not acceptance
        or acceptance.get("engagement_id") != engagement_id
        or acceptance.get("decision") != "ACCEPTED"
        or acceptance.get("client_acceptance_digest")
        != payload["client_acceptance_digest"]
        or acceptance.get("codex_build_package_reference")
        != payload["codex_build_package_reference"]
        or acceptance.get("package_digest") != payload["package_digest"]
        or acceptance.get("build_execution_reference")
        != payload["build_execution_reference"]
        or acceptance.get("build_execution_digest")
        != payload["build_execution_digest"]
        or acceptance.get("qa_result_reference") != payload["qa_result_reference"]
        or acceptance.get("qa_result_digest") != payload["qa_result_digest"]
        or acceptance.get("artifact_reference") != payload["artifact_reference"]
    ):
        raise ValueError("exact accepted ClientAcceptance version and digest are required")
    acceptance_view = ClientAcceptanceReadService(uow).status(
        tenant_id,
        acceptance["client_acceptance_id"],
        acceptance["acceptance_version"],
        now,
    )
    if not acceptance_view or not acceptance_view["client_accepted"]:
        raise ValueError("stale or rejected ClientAcceptance cannot authorize deployment")
    implementation_ref = payload["implementation_authorization_reference"]
    if (
        build.get("implementation_authorization_reference") != implementation_ref
        or build.get("implementation_authority_digest")
        != payload["implementation_authority_digest"]
    ):
        raise ValueError("exact active ImplementationAuthorization is required")
    target_ids = {item["target_reference_id"] for item in payload["target_resources"]}
    package_ids = {item["target_reference_id"] for item in package["allowed_targets"]}
    if not target_ids or not target_ids <= package_ids:
        raise ValueError("deployment target exceeds the released package boundary")
    return build, package, qa, acceptance


def _validate_body(uow, tenant_id, engagement_id, payload, now):
    sources = _exact_prerequisites(uow, tenant_id, engagement_id, payload, now)
    if not set(payload["permitted_deployment_actions"]) <= PERMITTED_DEPLOYMENT_ACTIONS:
        raise ValueError("deployment action is not permitted")
    if set(payload["prohibited_deployment_actions"]) != REQUIRED_PROHIBITED_DEPLOYMENT_ACTIONS:
        raise ValueError("complete prohibited-deployment set is required")
    if payload["effective_at"] >= payload["expires_at"]:
        raise ValueError("deployment authority validity window is invalid")
    if payload["deployment_authority_digest"] != deployment_authority_digest(payload):
        raise ValueError("DeploymentAuthorization digest does not match exact authority")
    return sources


class DeploymentAuthorizationHandler:
    def __init__(self, uow):
        self.uow = uow

    @staticmethod
    def _require_caller(command_type, context):
        if context.caller_type not in DEPLOYMENT_AUTHORIZATION_CALLERS[command_type]:
            raise ValueError("caller type is not authoritative for deployment command")

    @staticmethod
    def _require_human(context, requested_role=None):
        if (
            context.caller_type != "HUMAN"
            or not context.human_principal_reference
            or not context.human_organization_reference
            or context.human_authority_role not in DEPLOYMENT_AUTHORITY_ROLES
            or (requested_role is not None and context.human_authority_role != requested_role)
        ):
            raise ValueError("trusted deployment human authority is required")

    def execute(self, command_type, prepared, context, now, command_id):
        self._require_caller(command_type, context)
        _safe_payload(prepared.payload)
        return getattr(self, command_type)(prepared, context, now, command_id)

    @staticmethod
    def _record(prepared, now):
        return {
            "tenant_id": prepared.tenant_id,
            "engagement_id": prepared.engagement_id,
            **copy.deepcopy(prepared.payload),
            "state": "PROPOSED",
            "record_version": 1,
            "created_at": now,
            "updated_at": now,
        }

    def ProposeDeploymentAuthorization(self, prepared, context, now, command_id):
        payload = prepared.payload
        _validate_body(self.uow, prepared.tenant_id, prepared.engagement_id, payload, now)
        if payload["authorization_version"] != 1:
            raise ValueError("initial DeploymentAuthorization version must be one")
        if self.uow.deployment_authorizations.get_current(
            prepared.tenant_id, prepared.subject_id
        ):
            raise ValueError("DeploymentAuthorization identity already exists")
        return self.uow.deployment_authorizations.create_initial(
            self._record(prepared, now)
        )

    def ReviseDeploymentAuthorization(self, prepared, context, now, command_id):
        payload = prepared.payload
        _validate_body(self.uow, prepared.tenant_id, prepared.engagement_id, payload, now)
        current = self.uow.deployment_authorizations.get_current(
            prepared.tenant_id, prepared.subject_id
        )
        supersedes = payload["supersedes_deployment_authorization_reference"]
        if (
            not current
            or current.get("state") not in {"ACTIVE", "REVOKED"}
            or current.get("engagement_id") != prepared.engagement_id
            or current.get("record_version") != prepared.expected_record_version
            or payload["authorization_version"] != current["authorization_version"] + 1
            or supersedes != reference(
                "DEPLOYMENT_AUTHORIZATION",
                current["deployment_authorization_id"],
                current["authorization_version"],
            )
        ):
            raise ValueError("exact current terminal or active deployment authority is required")
        return self.uow.deployment_authorizations.revise(
            current, self._record(prepared, now), now
        )

    def RecordDeploymentAuthorizationApproval(self, prepared, context, now, command_id):
        payload = prepared.payload
        self._require_human(context, payload["authority_role"])
        current = self.uow.deployment_authorizations.get_version(
            prepared.tenant_id, prepared.subject_id, payload["subject_version"]
        )
        if (
            not current
            or current.get("state") != "PROPOSED"
            or current.get("engagement_id") != prepared.engagement_id
            or current.get("record_version") != prepared.expected_record_version
            or current.get("deployment_authority_digest") != payload["authority_digest"]
        ):
            raise ValueError("exact proposed DeploymentAuthorization is required")
        if self.uow.human_approvals.find_active_phase5d_binding(
            prepared.tenant_id,
            "DEPLOYMENT_AUTHORIZATION",
            current["deployment_authorization_id"],
            current["authorization_version"],
            current["deployment_authority_digest"],
            payload["authority_role"],
        ):
            raise ValueError("duplicate active deployment authority approval")
        approval = {
            "approval_id": command_id,
            "tenant_id": prepared.tenant_id,
            "engagement_id": prepared.engagement_id,
            "subject_type": "DEPLOYMENT_AUTHORIZATION",
            "subject_id": current["deployment_authorization_id"],
            "subject_version": current["authorization_version"],
            "approval_category": "DEPLOYMENT_AUTHORIZATION",
            "authority_category": (
                "CLIENT_AUTHORITY"
                if payload["authority_role"] == "CLIENT_DEPLOYMENT_AUTHORITY"
                else "PROVIDER_AUTHORITY"
            ),
            "actor_identity": context.human_principal_reference,
            "actor_organization": context.human_organization_reference,
            "actor_role": payload["authority_role"],
            "decision": "APPROVE",
            "phase5d_authority": {
                "subject_id": current["deployment_authorization_id"],
                "authority_digest": current["deployment_authority_digest"],
            },
            "conditions": [],
            "effective_at": now,
            "evidence_reference": {
                "reference_type": "DEPLOYMENT_AUTHORIZATION",
                "reference_id": current["deployment_authorization_id"],
            },
            "status": "ACTIVE",
            "correlation_id": prepared.correlation_id,
            "idempotency_key": prepared.idempotency_key,
            "created_at": now,
        }
        self.uow.human_approvals.record_phase5d(approval)
        return {"record": current, "approval": approval}

    @staticmethod
    def _approval_matches(approval, current, role):
        return bool(
            approval
            and approval.get("status") == "ACTIVE"
            and approval.get("decision") == "APPROVE"
            and approval.get("actor_role") == role
            and approval.get("subject_type") == "DEPLOYMENT_AUTHORIZATION"
            and approval.get("subject_id") == current["deployment_authorization_id"]
            and approval.get("subject_version") == current["authorization_version"]
            and approval.get("phase5d_authority", {}).get("authority_digest")
            == current["deployment_authority_digest"]
        )

    def _resolve_approval(self, tenant_id, approval_reference, current, role):
        approval = self.uow.human_approvals.get(
            tenant_id, approval_reference["reference_id"]
        )
        if (
            approval_reference.get("reference_version") != 1
            or not self._approval_matches(approval, current, role)
        ):
            raise ValueError("active exact dual deployment approvals are required")
        return approval

    def ActivateDeploymentAuthorization(self, prepared, context, now, command_id):
        payload = prepared.payload
        current = self.uow.deployment_authorizations.get_version(
            prepared.tenant_id,
            payload["deployment_authorization_id"],
            payload["authorization_version"],
        )
        if (
            not current
            or current.get("state") != "PROPOSED"
            or current.get("engagement_id") != prepared.engagement_id
            or current.get("record_version") != prepared.expected_record_version
            or current.get("deployment_authority_digest")
            != payload["deployment_authority_digest"]
            or payload["client_approval_reference"] == payload["provider_approval_reference"]
        ):
            raise ValueError("exact proposed DeploymentAuthorization is not activatable")
        _validate_body(
            self.uow, prepared.tenant_id, prepared.engagement_id, current, now
        )
        if not (current["effective_at"] <= now < current["expires_at"]):
            raise ValueError("DeploymentAuthorization is outside its validity window")
        approvals = [
            self._resolve_approval(prepared.tenant_id, payload[field], current, role)
            for role, field in (
                ("CLIENT_DEPLOYMENT_AUTHORITY", "client_approval_reference"),
                ("PROVIDER_DEPLOYMENT_AUTHORITY", "provider_approval_reference"),
            )
        ]
        return self.uow.deployment_authorizations.activate(
            current,
            reference("HUMAN_APPROVAL", approvals[0]["approval_id"], 1),
            reference("HUMAN_APPROVAL", approvals[1]["approval_id"], 1),
            now,
        )

    def RevokeDeploymentAuthorization(self, prepared, context, now, command_id):
        self._require_human(context)
        payload = prepared.payload
        current = self.uow.deployment_authorizations.get_version(
            prepared.tenant_id,
            payload["deployment_authorization_id"],
            payload["authorization_version"],
        )
        if (
            not current
            or current.get("state") not in {"PROPOSED", "ACTIVE"}
            or current.get("engagement_id") != prepared.engagement_id
            or current.get("record_version") != prepared.expected_record_version
            or current.get("deployment_authority_digest")
            != payload["deployment_authority_digest"]
        ):
            raise ValueError("exact revocable DeploymentAuthorization is required")
        return self.uow.deployment_authorizations.revoke(
            current, payload["revocation_reason"], now
        )


class DeploymentAuthorizationReadService:
    def __init__(self, uow):
        self.uow = uow

    def status(self, tenant_id, authorization_id, authorization_version, generated_at):
        record = self.uow.deployment_authorizations.get_version(
            tenant_id, authorization_id, authorization_version
        )
        if not record:
            return None
        prerequisites_exact = True
        try:
            _exact_prerequisites(
                self.uow, tenant_id, record["engagement_id"], record, generated_at
            )
        except ValueError:
            prerequisites_exact = False
        approvals_active = all(
            DeploymentAuthorizationHandler._approval_matches(
                self.uow.human_approvals.find_active_phase5d_binding(
                    tenant_id,
                    "DEPLOYMENT_AUTHORIZATION",
                    authorization_id,
                    authorization_version,
                    record["deployment_authority_digest"],
                    role,
                ),
                record,
                role,
            )
            for role in DEPLOYMENT_AUTHORITY_ROLES
        )
        within_window = record["effective_at"] <= generated_at < record["expires_at"]
        state = (
            "EXPIRED"
            if record["state"] == "ACTIVE" and generated_at >= record["expires_at"]
            else record["state"]
        )
        reasons = []
        if not prerequisites_exact:
            reasons.append("PREREQUISITE_INVALID")
        if not approvals_active:
            reasons.append("APPROVAL_INVALID")
        if not within_window:
            reasons.append("OUTSIDE_VALIDITY_WINDOW")
        if state != "ACTIVE":
            reasons.append("AUTHORIZATION_NOT_ACTIVE")
        deployment_authorized = bool(
            state == "ACTIVE"
            and prerequisites_exact
            and approvals_active
            and within_window
        )
        target_ids = {item["target_reference_id"] for item in record["target_resources"]}
        return {
            "deployment_authorization_reference": reference(
                "DEPLOYMENT_AUTHORIZATION", authorization_id, authorization_version
            ),
            "implementation_authorization_reference": copy.deepcopy(
                record["implementation_authorization_reference"]
            ),
            "package_reference": copy.deepcopy(record["codex_build_package_reference"]),
            "build_execution_reference": copy.deepcopy(record["build_execution_reference"]),
            "qa_result_reference": copy.deepcopy(record["qa_result_reference"]),
            "client_acceptance_reference": copy.deepcopy(
                record["client_acceptance_reference"]
            ),
            "state": state,
            "prerequisites_exact": prerequisites_exact,
            "approvals_active": approvals_active,
            "within_validity_window": within_window,
            "deployment_authorized": deployment_authorized,
            "production_target_exact": bool(
                target_ids and (
                    record["target_environment"] != "PRODUCTION"
                    or prerequisites_exact
                )
            ),
            "deployment_completed": False,
            "reasons": reasons,
            "tenant_id": tenant_id,
            "engagement_id": record["engagement_id"],
            "generated_at": generated_at,
        }
