"""Phase 5D ImplementationAuthorization runtime policy.

An ImplementationAuthorization is separate bounded non-production build authority.
It is not access authority, deployment authority, or production-change authority.
"""
from __future__ import annotations

import copy

from .phase5c import canonical_digest, reference
from .phase5d_brief import (
    IMPLEMENTATION_BRIEF_ROLES,
    ImplementationBriefReadService,
    REQUIRED_PROHIBITED_CHANGES,
    resolve_implementation_brief_sources,
)


IMPLEMENTATION_AUTHORIZATION_COMMANDS = (
    "ProposeImplementationAuthorization",
    "ReviseImplementationAuthorization",
    "RecordImplementationAuthorizationApproval",
    "ActivateImplementationAuthorization",
    "RevokeImplementationAuthorization",
)

IMPLEMENTATION_AUTHORIZATION_CAPABILITIES = {
    "ProposeImplementationAuthorization": "implementation_authorization:propose",
    "ReviseImplementationAuthorization": "implementation_authorization:propose",
    "RecordImplementationAuthorizationApproval": "implementation_authorization:approve",
    "ActivateImplementationAuthorization": "implementation_authorization:activate",
    "RevokeImplementationAuthorization": "implementation_authorization:revoke",
}

IMPLEMENTATION_AUTHORIZATION_EVENTS = {
    "ProposeImplementationAuthorization": "implementation_authorization.proposed",
    "ReviseImplementationAuthorization": "implementation_authorization.revised",
    "RecordImplementationAuthorizationApproval": "implementation_authorization.approval_recorded",
    "ActivateImplementationAuthorization": "implementation_authorization.activated",
    "RevokeImplementationAuthorization": "implementation_authorization.revoked",
}

IMPLEMENTATION_AUTHORIZATION_CALLERS = {
    "ProposeImplementationAuthorization": frozenset({"HUMAN", "INTERNAL_SERVICE"}),
    "ReviseImplementationAuthorization": frozenset({"HUMAN", "INTERNAL_SERVICE"}),
    "RecordImplementationAuthorizationApproval": frozenset({"HUMAN"}),
    "ActivateImplementationAuthorization": frozenset({"INTERNAL_SERVICE"}),
    "RevokeImplementationAuthorization": frozenset({"HUMAN"}),
}

PERMITTED_BUILD_ACTIONS = frozenset({
    "READ_REPOSITORY",
    "CREATE_CODE",
    "MODIFY_CODE",
    "CREATE_TEST",
    "MODIFY_TEST",
    "RUN_TEST",
    "CREATE_DOCUMENTATION",
    "MODIFY_DOCUMENTATION",
    "BUILD_NON_PRODUCTION_ARTIFACT",
})

SOURCE_REFERENCE_FIELDS = (
    "source_conversion_decision_reference",
    "source_ongoing_agreement_reference",
    "source_ongoing_payment_reference",
    "source_ongoing_access_reference",
)

AUTHORITY_BODY_FIELDS = (
    "implementation_authorization_id",
    "authorization_version",
    "implementation_brief_reference",
    "implementation_brief_digest",
    "authorized_scope_digest",
    "target_references",
    "permitted_action_classes",
    "prohibited_action_classes",
    "effective_at",
    "expires_at",
    "supersedes_implementation_authorization_reference",
)


def implementation_authorization_scope_digest(brief: dict) -> str:
    """Digest only the exact structured, approved brief scope boundary."""
    projection = {
        "implementation_brief_reference": reference(
            "IMPLEMENTATION_BRIEF",
            brief["implementation_brief_id"],
            brief["implementation_brief_version"],
        ),
        "implementation_brief_digest": brief["implementation_brief_digest"],
        "approved_scope": copy.deepcopy(brief["approved_scope"]),
        "excluded_scope": copy.deepcopy(brief["excluded_scope"]),
        "known_constraints": copy.deepcopy(brief["known_constraints"]),
        "approved_integrations": copy.deepcopy(brief["approved_integrations"]),
        "allowed_access_level": brief["allowed_access_level"],
        "prohibited_changes": copy.deepcopy(brief["prohibited_changes"]),
    }
    return canonical_digest(projection)


def implementation_authority_digest(payload: dict) -> str:
    """Digest the complete requested immutable authority body, excluding itself."""
    return canonical_digest({
        key: copy.deepcopy(value)
        for key, value in payload.items()
        if key in AUTHORITY_BODY_FIELDS
    })


def _approved_target_ids(brief: dict) -> frozenset[str]:
    """Return exact structured identifiers already governed by the approved brief."""
    return frozenset(
        [item["scope_item_id"] for item in brief["approved_scope"]]
        + [item["scope_item_id"] for item in brief["implementation_requirements"]]
        + [item["integration_reference"] for item in brief["approved_integrations"]]
    )


def _targets_match_brief(brief: dict, target_references: list[dict]) -> bool:
    allowed = _approved_target_ids(brief)
    return bool(target_references) and all(
        target["target_reference_id"] in allowed for target in target_references
    )


def _exact_brief(uow, tenant_id, engagement_id, payload, now):
    brief_ref = payload["implementation_brief_reference"]
    brief = uow.implementation_briefs.get_version(
        tenant_id, brief_ref["reference_id"], brief_ref["reference_version"]
    )
    if (
        not brief
        or brief.get("engagement_id") != engagement_id
        or brief.get("state") != "APPROVED"
        or brief.get("implementation_brief_digest") != payload["implementation_brief_digest"]
        or brief_ref != reference(
            "IMPLEMENTATION_BRIEF",
            brief["implementation_brief_id"],
            brief["implementation_brief_version"],
        )
    ):
        raise ValueError("exact approved ImplementationBrief version and digest are required")
    resolve_implementation_brief_sources(uow, tenant_id, engagement_id, brief, now)
    readiness = ImplementationBriefReadService(uow).readiness(
        tenant_id, brief["implementation_brief_id"], brief["implementation_brief_version"], now
    )
    if not readiness or not readiness["implementation_brief_ready"]:
        raise ValueError("exact approved ImplementationBrief is not currently ready")
    return brief


def _scope_and_authority_match(payload: dict, brief: dict) -> None:
    if payload["authorized_scope_digest"] != implementation_authorization_scope_digest(brief):
        raise ValueError("authorized scope does not match the exact approved brief")
    if not _targets_match_brief(brief, payload["target_references"]):
        raise ValueError("authorization target exceeds the exact approved brief")
    if not set(payload["permitted_action_classes"]) <= PERMITTED_BUILD_ACTIONS:
        raise ValueError("implementation action class is not permitted")
    if set(payload["prohibited_action_classes"]) != REQUIRED_PROHIBITED_CHANGES:
        raise ValueError("complete prohibited-change set is required")
    if set(brief["prohibited_changes"]) != REQUIRED_PROHIBITED_CHANGES:
        raise ValueError("approved brief prohibited-change boundary is invalid")
    if payload["effective_at"] >= payload["expires_at"]:
        raise ValueError("authorization validity window is invalid")
    if payload["implementation_authority_digest"] != implementation_authority_digest(payload):
        raise ValueError("ImplementationAuthorization digest does not match exact immutable body")


class ImplementationAuthorizationHandler:
    def __init__(self, uow):
        self.uow = uow

    @staticmethod
    def _require_caller(command_type, context):
        if context.caller_type not in IMPLEMENTATION_AUTHORIZATION_CALLERS[command_type]:
            raise ValueError("caller type is not authoritative for ImplementationAuthorization command")

    @staticmethod
    def _require_human(context, requested_role=None):
        if (
            context.caller_type != "HUMAN"
            or not context.human_principal_reference
            or not context.human_organization_reference
            or context.human_authority_role not in IMPLEMENTATION_BRIEF_ROLES
            or (requested_role is not None and context.human_authority_role != requested_role)
        ):
            raise ValueError("trusted Phase 5D human authority is required")

    def execute(self, command_type, prepared, context, now, command_id):
        self._require_caller(command_type, context)
        return getattr(self, command_type)(prepared, context, now, command_id)

    def _validate_body(self, prepared, now):
        payload = prepared.payload
        brief = _exact_brief(
            self.uow, prepared.tenant_id, prepared.engagement_id, payload, now
        )
        _scope_and_authority_match(payload, brief)
        return brief

    @staticmethod
    def _record(prepared, brief, now):
        payload = prepared.payload
        return {
            "tenant_id": prepared.tenant_id,
            "engagement_id": prepared.engagement_id,
            **copy.deepcopy(payload),
            **{field: copy.deepcopy(brief[field]) for field in SOURCE_REFERENCE_FIELDS},
            "state": "PROPOSED",
            "record_version": 1,
            "created_at": now,
            "updated_at": now,
        }

    def ProposeImplementationAuthorization(self, prepared, context, now, command_id):
        brief = self._validate_body(prepared, now)
        if prepared.payload["authorization_version"] != 1:
            raise ValueError("initial ImplementationAuthorization version must be one")
        if self.uow.implementation_authorizations.get_current(
            prepared.tenant_id, prepared.subject_id
        ):
            raise ValueError("ImplementationAuthorization identity already exists")
        return self.uow.implementation_authorizations.create_initial(
            self._record(prepared, brief, now)
        )

    def ReviseImplementationAuthorization(self, prepared, context, now, command_id):
        brief = self._validate_body(prepared, now)
        payload = prepared.payload
        current = self.uow.implementation_authorizations.get_current(
            prepared.tenant_id, prepared.subject_id
        )
        supersedes = payload["supersedes_implementation_authorization_reference"]
        if (
            not current
            or current.get("engagement_id") != prepared.engagement_id
            or current.get("state") != "ACTIVE"
            or current.get("record_version") != prepared.expected_record_version
            or payload["authorization_version"] != current["authorization_version"] + 1
            or supersedes != reference(
                "IMPLEMENTATION_AUTHORIZATION",
                current["implementation_authorization_id"],
                current["authorization_version"],
            )
        ):
            raise ValueError("exact current active ImplementationAuthorization version is required")
        return self.uow.implementation_authorizations.revise(
            current, self._record(prepared, brief, now), now
        )

    def RecordImplementationAuthorizationApproval(self, prepared, context, now, command_id):
        payload = prepared.payload
        self._require_human(context, payload["authority_role"])
        current = self.uow.implementation_authorizations.get_version(
            prepared.tenant_id, prepared.subject_id, payload["subject_version"]
        )
        if (
            not current
            or current.get("state") != "PROPOSED"
            or current.get("engagement_id") != prepared.engagement_id
            or current.get("record_version") != prepared.expected_record_version
            or current.get("implementation_authority_digest") != payload["authority_digest"]
        ):
            raise ValueError("exact proposed ImplementationAuthorization is required")
        if self.uow.human_approvals.find_active_phase5d_binding(
            prepared.tenant_id,
            "IMPLEMENTATION_AUTHORIZATION",
            current["implementation_authorization_id"],
            current["authorization_version"],
            current["implementation_authority_digest"],
            payload["authority_role"],
        ):
            raise ValueError("duplicate active Phase 5D authority")
        approval = {
            "approval_id": command_id,
            "tenant_id": prepared.tenant_id,
            "engagement_id": prepared.engagement_id,
            "subject_type": "IMPLEMENTATION_AUTHORIZATION",
            "subject_id": current["implementation_authorization_id"],
            "subject_version": current["authorization_version"],
            "approval_category": "IMPLEMENTATION_AUTHORIZATION",
            "authority_category": (
                "CLIENT_AUTHORITY"
                if payload["authority_role"] == "CLIENT_IMPLEMENTATION_AUTHORITY"
                else "SEKINFRA_AUTHORITY"
            ),
            "actor_identity": context.human_principal_reference,
            "actor_organization": context.human_organization_reference,
            "actor_role": payload["authority_role"],
            "decision": "APPROVE",
            "phase5d_authority": {
                "subject_id": current["implementation_authorization_id"],
                "authority_digest": current["implementation_authority_digest"],
            },
            "conditions": [],
            "effective_at": now,
            "evidence_reference": {
                "reference_type": "IMPLEMENTATION_BRIEF",
                "reference_id": current["implementation_brief_reference"]["reference_id"],
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
            and approval.get("subject_type") == "IMPLEMENTATION_AUTHORIZATION"
            and approval.get("subject_id") == current["implementation_authorization_id"]
            and approval.get("subject_version") == current["authorization_version"]
            and approval.get("phase5d_authority", {}).get("authority_digest")
            == current["implementation_authority_digest"]
        )

    def _resolve_approval(self, tenant_id, approval_reference, current, role):
        approval = self.uow.human_approvals.get(
            tenant_id, approval_reference["reference_id"]
        )
        if (
            approval_reference.get("reference_version") != 1
            or not self._approval_matches(approval, current, role)
        ):
            raise ValueError("active exact dual ImplementationAuthorization approvals are required")
        return approval

    def ActivateImplementationAuthorization(self, prepared, context, now, command_id):
        payload = prepared.payload
        current = self.uow.implementation_authorizations.get_version(
            prepared.tenant_id,
            payload["implementation_authorization_id"],
            payload["authorization_version"],
        )
        if (
            not current
            or current.get("state") != "PROPOSED"
            or current.get("engagement_id") != prepared.engagement_id
            or current.get("record_version") != prepared.expected_record_version
            or current.get("implementation_authority_digest")
            != payload["implementation_authority_digest"]
            or payload["client_approval_reference"] == payload["sekinfra_approval_reference"]
        ):
            raise ValueError("exact proposed ImplementationAuthorization is not activatable")
        brief = _exact_brief(
            self.uow, prepared.tenant_id, prepared.engagement_id, current, now
        )
        _scope_and_authority_match(current, brief)
        if not (current["effective_at"] <= now < current["expires_at"]):
            raise ValueError("ImplementationAuthorization is outside its validity window")
        approvals = [
            self._resolve_approval(
                prepared.tenant_id,
                payload[field],
                current,
                role,
            )
            for role, field in (
                ("CLIENT_IMPLEMENTATION_AUTHORITY", "client_approval_reference"),
                ("SEKINFRA_IMPLEMENTATION_AUTHORITY", "sekinfra_approval_reference"),
            )
        ]
        return self.uow.implementation_authorizations.activate(
            current,
            reference("HUMAN_APPROVAL", approvals[0]["approval_id"], 1),
            reference("HUMAN_APPROVAL", approvals[1]["approval_id"], 1),
            now,
        )

    def RevokeImplementationAuthorization(self, prepared, context, now, command_id):
        self._require_human(context)
        current = self.uow.implementation_authorizations.get_current(
            prepared.tenant_id, prepared.payload["implementation_authorization_id"]
        )
        if (
            not current
            or current.get("state") not in {"PROPOSED", "ACTIVE"}
            or current.get("engagement_id") != prepared.engagement_id
            or current.get("record_version") != prepared.expected_record_version
        ):
            raise ValueError("exact revocable ImplementationAuthorization is required")
        return self.uow.implementation_authorizations.revoke(
            current, prepared.payload["revocation_reason"], now
        )


class ImplementationAuthorizationReadService:
    """Tenant-bounded deterministic status; deployment and production stay false."""
    def __init__(self, uow):
        self.uow = uow

    def status(self, tenant_id, authorization_id, authorization_version, generated_at):
        authorization_record = self.uow.implementation_authorizations.get_version(
            tenant_id, authorization_id, authorization_version
        )
        if not authorization_record:
            return None
        brief_ref = authorization_record["implementation_brief_reference"]
        brief = self.uow.implementation_briefs.get_version(
            tenant_id, brief_ref["reference_id"], brief_ref["reference_version"]
        )
        brief_status = ImplementationBriefReadService(self.uow).readiness(
            tenant_id, brief_ref["reference_id"], brief_ref["reference_version"], generated_at
        )
        brief_ready = bool(
            brief
            and brief_status
            and brief_status["implementation_brief_ready"]
            and brief.get("implementation_brief_digest")
            == authorization_record["implementation_brief_digest"]
        )
        scope_matches = bool(
            brief
            and authorization_record["authorized_scope_digest"]
            == implementation_authorization_scope_digest(brief)
        )
        targets_match = bool(
            brief and _targets_match_brief(brief, authorization_record["target_references"])
        )
        scope_and_targets_match = scope_matches and targets_match
        approvals = []
        for role in IMPLEMENTATION_BRIEF_ROLES:
            approval = self.uow.human_approvals.find_active_phase5d_binding(
                tenant_id,
                "IMPLEMENTATION_AUTHORIZATION",
                authorization_id,
                authorization_version,
                authorization_record["implementation_authority_digest"],
                role,
            )
            approvals.append(
                ImplementationAuthorizationHandler._approval_matches(
                    approval, authorization_record, role
                )
            )
        approvals_active = all(approvals)
        commercial_valid_now = bool(
            brief_status and brief_status["commercial_authority_valid"]
        )
        access_usable = bool(brief_status and brief_status["ongoing_access_usable"])
        offboarding = bool(
            self.uow.ongoing_offboardings.find_by_engagement(
                tenant_id, authorization_record["engagement_id"]
            )
        )
        within_window = authorization_record["effective_at"] <= generated_at < authorization_record["expires_at"]
        stored_state = authorization_record["state"]
        state = (
            "EXPIRED"
            if stored_state == "ACTIVE" and generated_at >= authorization_record["expires_at"]
            else stored_state
        )
        ready = all((
            brief_ready,
            commercial_valid_now,
            access_usable,
            within_window,
            scope_and_targets_match,
            approvals_active,
            not offboarding,
            state not in {"EXPIRED", "REVOKED", "SUPERSEDED"},
        ))
        usable = ready and state == "ACTIVE"
        reasons = []
        if state not in {"ACTIVE", "EXPIRED", "REVOKED", "SUPERSEDED"}:
            reasons.append("AUTHORIZATION_NOT_ACTIVE")
        if not brief_ready:
            reasons.append("BRIEF_NOT_READY")
        if not commercial_valid_now:
            reasons.append("COMMERCIAL_AUTHORITY_INVALID")
        if not access_usable:
            reasons.append("ONGOING_ACCESS_UNUSABLE")
        if not within_window:
            reasons.append("OUTSIDE_VALIDITY_WINDOW")
        if not scope_matches:
            reasons.append("SCOPE_MISMATCH")
        if not targets_match:
            reasons.append("TARGET_MISMATCH")
        if not approvals_active:
            reasons.append("APPROVAL_INVALID")
        if offboarding:
            reasons.append("OFFBOARDING_ACTIVE")
        if state in {"EXPIRED", "REVOKED", "SUPERSEDED"}:
            reasons.append("AUTHORIZATION_TERMINAL")
        return {
            "tenant_id": tenant_id,
            "engagement_id": authorization_record["engagement_id"],
            "implementation_authorization_reference": reference(
                "IMPLEMENTATION_AUTHORIZATION", authorization_id, authorization_version
            ),
            "state": state,
            "brief_ready": brief_ready,
            "commercial_authority_valid": commercial_valid_now,
            "ongoing_access_usable": access_usable,
            "within_validity_window": within_window,
            "scope_and_targets_match": scope_and_targets_match,
            "approvals_active": approvals_active,
            "implementation_authorization_ready": ready,
            "implementation_authorization_usable": usable,
            "reasons": reasons,
            "deployment_authorized": False,
            "production_change_authorized": False,
            "generated_at": generated_at,
        }
