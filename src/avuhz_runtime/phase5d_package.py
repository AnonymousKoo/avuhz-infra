"""Phase 5D CodexBuildPackage runtime policy.

A package is an immutable executor-ready description inside separately approved
ImplementationAuthorization.  It creates no implementation, deployment, or
production-change authority.
"""
from __future__ import annotations

import copy
import re

from .phase5c import canonical_digest, reference
from .phase5d_authorization import ImplementationAuthorizationReadService
from .phase5d_brief import (
    IMPLEMENTATION_BRIEF_ROLES,
    ImplementationBriefReadService,
    REQUIRED_PROHIBITED_CHANGES,
)


CODEX_BUILD_PACKAGE_COMMANDS = (
    "DraftCodexBuildPackage",
    "ReviseCodexBuildPackage",
    "RecordCodexBuildPackageApproval",
    "ReleaseCodexBuildPackage",
)

CODEX_BUILD_PACKAGE_CAPABILITIES = {
    "DraftCodexBuildPackage": "codex_build_package:draft",
    "ReviseCodexBuildPackage": "codex_build_package:draft",
    "RecordCodexBuildPackageApproval": "codex_build_package:approve",
    "ReleaseCodexBuildPackage": "codex_build_package:release",
}

CODEX_BUILD_PACKAGE_EVENTS = {
    "DraftCodexBuildPackage": "codex_build_package.drafted",
    "ReviseCodexBuildPackage": "codex_build_package.revised",
    "RecordCodexBuildPackageApproval": "codex_build_package.approval_recorded",
    "ReleaseCodexBuildPackage": "codex_build_package.released",
}

CODEX_BUILD_PACKAGE_CALLERS = {
    "DraftCodexBuildPackage": frozenset({"HUMAN", "INTERNAL_SERVICE"}),
    "ReviseCodexBuildPackage": frozenset({"HUMAN", "INTERNAL_SERVICE"}),
    "RecordCodexBuildPackageApproval": frozenset({"HUMAN"}),
    "ReleaseCodexBuildPackage": frozenset({"INTERNAL_SERVICE"}),
}

PACKAGE_CONTENT_FIELDS = (
    "authorized_build_scope",
    "problem_statement",
    "desired_outcome",
    "current_architecture_context",
    "required_integrations",
    "implementation_requirements",
    "acceptance_criteria",
    "constraints",
    "prohibited_changes",
    "allowed_targets",
    "test_obligations",
    "rollback_recovery_expectations",
)

PACKAGE_BODY_FIELDS = (
    "codex_build_package_id",
    "package_version",
    "implementation_brief_reference",
    "implementation_brief_digest",
    "implementation_authorization_reference",
    "implementation_authority_digest",
    *PACKAGE_CONTENT_FIELDS,
    "supersedes_codex_build_package_reference",
)


_SECRET_VALUE = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"authorization)\s*[:=]\s*\S+|bearer\s+[a-z0-9._~+/=-]{8,}"
)
_AUTHENTICATED_URL = re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql)://[^\s/:]+:[^\s/@]+@")
_RAW_DUMP = re.compile(r"(?i)\b(?:pg_dump|create\s+database|copy\s+public\.[a-z0-9_]+\s+from)\b")
_AUTHORITY_CLAIM = re.compile(
    r"(?i)\b(?:deployment|production(?:[- ]change)?)\s+(?:is\s+)?(?:authorized|approved|permitted)\b|"
    r"\b(?:deploy|release|cut(?:over)?|modify)\s+(?:to\s+)?production\b"
)
_PROHIBITED_INSTRUCTION = re.compile(
    r"(?i)\bdeploy\b|\bcutover\b|\brotate\s+(?:credentials?|keys?|tokens?)\b|"
    r"\bwiden\s+(?:access|permissions?)\b|\bdelete\s+(?:data|records?)\b|"
    r"\bchange\s+billing\b|\b(?:modify|change|disable)\s+(?:network|security controls?)\b"
)


def _walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _walk_strings(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_strings(child)


def codex_build_package_digest(payload: dict) -> str:
    """Digest the complete requested immutable package body, excluding itself."""
    return canonical_digest({
        name: copy.deepcopy(value)
        for name, value in payload.items()
        if name in PACKAGE_BODY_FIELDS
    })


def _identity_map(values, identity_field):
    return {value[identity_field]: value for value in values}


def _subset_exact(requested, approved, identity_field):
    approved_by_id = _identity_map(approved, identity_field)
    identities = [item[identity_field] for item in requested]
    return len(identities) == len(set(identities)) and all(
        approved_by_id.get(item[identity_field]) == item for item in requested
    )


def _target_set(values):
    return {(value["target_reference_id"], value["target_class"]) for value in values}


def _validate_safe_content(payload):
    for field in PACKAGE_CONTENT_FIELDS:
        for value in _walk_strings(payload[field]):
            if _SECRET_VALUE.search(value) or _AUTHENTICATED_URL.search(value) or _RAW_DUMP.search(value):
                raise ValueError("credential, secret-bearing URL, or raw provider material is prohibited")
            if field != "prohibited_changes" and _AUTHORITY_CLAIM.search(value):
                raise ValueError("deployment or production-change authority claim is prohibited")
            if field != "prohibited_changes" and _PROHIBITED_INSTRUCTION.search(value):
                raise ValueError("deployment or prohibited action instruction is prohibited")


def _exact_sources(uow, tenant_id, engagement_id, payload, now):
    brief_ref = payload["implementation_brief_reference"]
    brief = uow.implementation_briefs.get_version(
        tenant_id, brief_ref["reference_id"], brief_ref["reference_version"]
    )
    if (
        not brief
        or brief.get("engagement_id") != engagement_id
        or brief.get("state") != "APPROVED"
        or brief_ref != reference(
            "IMPLEMENTATION_BRIEF",
            brief["implementation_brief_id"],
            brief["implementation_brief_version"],
        )
        or brief.get("implementation_brief_digest") != payload["implementation_brief_digest"]
    ):
        raise ValueError("exact approved ImplementationBrief version and digest are required")
    brief_status = ImplementationBriefReadService(uow).readiness(
        tenant_id, brief["implementation_brief_id"], brief["implementation_brief_version"], now
    )
    if not brief_status or not brief_status["implementation_brief_ready"]:
        raise ValueError("exact approved ImplementationBrief is not currently ready")

    authorization_ref = payload["implementation_authorization_reference"]
    implementation_authority = uow.implementation_authorizations.get_version(
        tenant_id, authorization_ref["reference_id"], authorization_ref["reference_version"]
    )
    if (
        not implementation_authority
        or implementation_authority.get("engagement_id") != engagement_id
        or implementation_authority.get("state") != "ACTIVE"
        or authorization_ref != reference(
            "IMPLEMENTATION_AUTHORIZATION",
            implementation_authority["implementation_authorization_id"],
            implementation_authority["authorization_version"],
        )
        or implementation_authority.get("implementation_authority_digest")
        != payload["implementation_authority_digest"]
        or implementation_authority.get("implementation_brief_reference") != brief_ref
        or implementation_authority.get("implementation_brief_digest")
        != payload["implementation_brief_digest"]
    ):
        raise ValueError("exact active ImplementationAuthorization version and digest are required")
    authorization_status = ImplementationAuthorizationReadService(uow).status(
        tenant_id,
        implementation_authority["implementation_authorization_id"],
        implementation_authority["authorization_version"],
        now,
    )
    if not authorization_status or not authorization_status["implementation_authorization_usable"]:
        raise ValueError("exact ImplementationAuthorization is not currently usable")
    return brief, implementation_authority


def _validate_package_boundary(payload, brief, implementation_authority):
    if payload["problem_statement"] != brief["approved_business_problem"]:
        raise ValueError("package problem statement exceeds the exact approved brief")
    if payload["desired_outcome"] != brief["desired_business_outcome"]:
        raise ValueError("package desired outcome exceeds the exact approved brief")
    if payload["authorized_build_scope"] != brief["approved_scope"]:
        raise ValueError("authorized build scope must equal the exact approved brief scope")
    if not _subset_exact(
        payload["current_architecture_context"], brief["current_state_context"], "context_item_id"
    ):
        raise ValueError("package context exceeds the exact approved brief")
    if any(item not in brief["approved_integrations"] for item in payload["required_integrations"]):
        raise ValueError("package integration exceeds the exact approved brief")
    if not _subset_exact(
        payload["implementation_requirements"], brief["implementation_requirements"], "scope_item_id"
    ):
        raise ValueError("package requirement exceeds the exact approved brief")
    if not _subset_exact(
        payload["acceptance_criteria"], brief["acceptance_criteria"], "criterion_id"
    ):
        raise ValueError("package acceptance criterion exceeds the exact approved brief")
    if not any(item["category"] == "BUSINESS" for item in payload["acceptance_criteria"]):
        raise ValueError("at least one approved business acceptance criterion is required")
    if any(value not in brief["known_constraints"] for value in payload["constraints"]):
        raise ValueError("package constraint is not approved by the exact brief")
    if set(payload["prohibited_changes"]) != REQUIRED_PROHIBITED_CHANGES:
        raise ValueError("complete prohibited-change set is required")
    if set(brief["prohibited_changes"]) != REQUIRED_PROHIBITED_CHANGES:
        raise ValueError("approved brief prohibited-change boundary is invalid")
    if set(implementation_authority["prohibited_action_classes"]) != REQUIRED_PROHIBITED_CHANGES:
        raise ValueError("ImplementationAuthorization prohibited-change boundary is invalid")
    if _target_set(payload["allowed_targets"]) != _target_set(implementation_authority["target_references"]):
        raise ValueError("package targets must equal exact ImplementationAuthorization targets")
    approved_scope_ids = {item["scope_item_id"] for item in payload["authorized_build_scope"]}
    if any(not set(item["scope_item_ids"]) <= approved_scope_ids for item in payload["acceptance_criteria"]):
        raise ValueError("package acceptance criterion refers outside authorized build scope")
    if payload["package_digest"] != codex_build_package_digest(payload):
        raise ValueError("CodexBuildPackage digest does not match exact immutable body")


class CodexBuildPackageHandler:
    def __init__(self, uow):
        self.uow = uow

    @staticmethod
    def _require_caller(command_type, context):
        if context.caller_type not in CODEX_BUILD_PACKAGE_CALLERS[command_type]:
            raise ValueError("caller type is not authoritative for CodexBuildPackage command")

    @staticmethod
    def _require_human(context, requested_role):
        if (
            context.caller_type != "HUMAN"
            or not context.human_principal_reference
            or not context.human_organization_reference
            or context.human_authority_role != requested_role
            or requested_role not in IMPLEMENTATION_BRIEF_ROLES
        ):
            raise ValueError("trusted Phase 5D human authority is required")

    def execute(self, command_type, prepared, context, now, command_id):
        self._require_caller(command_type, context)
        return getattr(self, command_type)(prepared, context, now, command_id)

    def _validate_body(self, prepared, now):
        _validate_safe_content(prepared.payload)
        brief, implementation_authority = _exact_sources(
            self.uow, prepared.tenant_id, prepared.engagement_id, prepared.payload, now
        )
        _validate_package_boundary(prepared.payload, brief, implementation_authority)
        return brief, implementation_authority

    @staticmethod
    def _record(prepared, context, now):
        return {
            "tenant_id": prepared.tenant_id,
            "engagement_id": prepared.engagement_id,
            **copy.deepcopy(prepared.payload),
            "state": "DRAFT",
            "trusted_attribution": {
                "drafted_by": context.human_principal_reference or context.principal_id,
                "recorded_by": context.principal_id,
                "draft_assistance": "AI_ASSISTED" if context.caller_type == "INTERNAL_SERVICE" else "NONE",
            },
            "record_version": 1,
            "created_at": now,
            "updated_at": now,
        }

    def DraftCodexBuildPackage(self, prepared, context, now, command_id):
        self._validate_body(prepared, now)
        if prepared.payload["package_version"] != 1:
            raise ValueError("initial CodexBuildPackage version must be one")
        if self.uow.codex_build_packages.get_current(prepared.tenant_id, prepared.subject_id):
            raise ValueError("CodexBuildPackage identity already exists")
        return self.uow.codex_build_packages.create_initial(
            self._record(prepared, context, now)
        )

    def ReviseCodexBuildPackage(self, prepared, context, now, command_id):
        self._validate_body(prepared, now)
        payload = prepared.payload
        current = self.uow.codex_build_packages.get_current(
            prepared.tenant_id, prepared.subject_id
        )
        if (
            not current
            or current.get("engagement_id") != prepared.engagement_id
            or current.get("state") != "RELEASED"
            or current.get("record_version") != prepared.expected_record_version
            or payload["package_version"] != current["package_version"] + 1
            or payload["supersedes_codex_build_package_reference"] != reference(
                "CODEX_BUILD_PACKAGE",
                current["codex_build_package_id"],
                current["package_version"],
            )
        ):
            raise ValueError("exact current released CodexBuildPackage version is required")
        return self.uow.codex_build_packages.revise(
            current, self._record(prepared, context, now), now
        )

    def RecordCodexBuildPackageApproval(self, prepared, context, now, command_id):
        payload = prepared.payload
        self._require_human(context, payload["authority_role"])
        current = self.uow.codex_build_packages.get_version(
            prepared.tenant_id, prepared.subject_id, payload["subject_version"]
        )
        if (
            not current
            or current.get("state") != "DRAFT"
            or current.get("engagement_id") != prepared.engagement_id
            or current.get("record_version") != prepared.expected_record_version
            or current.get("package_digest") != payload["authority_digest"]
        ):
            raise ValueError("exact draft CodexBuildPackage is required")
        if self.uow.human_approvals.find_active_phase5d_binding(
            prepared.tenant_id,
            "CODEX_BUILD_PACKAGE",
            current["codex_build_package_id"],
            current["package_version"],
            current["package_digest"],
            payload["authority_role"],
        ):
            raise ValueError("duplicate active Phase 5D authority")
        approval = {
            "approval_id": command_id,
            "tenant_id": prepared.tenant_id,
            "engagement_id": prepared.engagement_id,
            "subject_type": "CODEX_BUILD_PACKAGE",
            "subject_id": current["codex_build_package_id"],
            "subject_version": current["package_version"],
            "approval_category": "CODEX_BUILD_PACKAGE",
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
                "subject_id": current["codex_build_package_id"],
                "authority_digest": current["package_digest"],
            },
            "conditions": [],
            "effective_at": now,
            "evidence_reference": {
                "reference_type": "IMPLEMENTATION_AUTHORIZATION",
                "reference_id": current["implementation_authorization_reference"]["reference_id"],
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
            and approval.get("subject_type") == "CODEX_BUILD_PACKAGE"
            and approval.get("subject_id") == current["codex_build_package_id"]
            and approval.get("subject_version") == current["package_version"]
            and approval.get("tenant_id") == current["tenant_id"]
            and approval.get("engagement_id") == current["engagement_id"]
            and approval.get("phase5d_authority", {}).get("subject_id")
            == current["codex_build_package_id"]
            and approval.get("phase5d_authority", {}).get("authority_digest")
            == current["package_digest"]
        )

    def ReleaseCodexBuildPackage(self, prepared, context, now, command_id):
        payload = prepared.payload
        current = self.uow.codex_build_packages.get_version(
            prepared.tenant_id,
            payload["codex_build_package_id"],
            payload["package_version"],
        )
        if (
            not current
            or current.get("state") != "DRAFT"
            or current.get("engagement_id") != prepared.engagement_id
            or current.get("record_version") != prepared.expected_record_version
            or current.get("package_digest") != payload["package_digest"]
            or payload["client_approval_reference"] == payload["sekinfra_approval_reference"]
        ):
            raise ValueError("exact draft CodexBuildPackage is not releasable")
        _validate_safe_content(current)
        brief, implementation_authority = _exact_sources(
            self.uow, prepared.tenant_id, prepared.engagement_id, current, now
        )
        _validate_package_boundary(current, brief, implementation_authority)
        approvals = []
        for role, field in (
            ("CLIENT_IMPLEMENTATION_AUTHORITY", "client_approval_reference"),
            ("SEKINFRA_IMPLEMENTATION_AUTHORITY", "sekinfra_approval_reference"),
        ):
            approval_ref = payload[field]
            approval = self.uow.human_approvals.get(
                prepared.tenant_id, approval_ref["reference_id"]
            )
            if (
                approval_ref.get("reference_version") != 1
                or not self._approval_matches(approval, current, role)
            ):
                raise ValueError("active exact dual CodexBuildPackage approvals are required")
            approvals.append(approval)
        return self.uow.codex_build_packages.release(
            current,
            reference("HUMAN_APPROVAL", approvals[0]["approval_id"], 1),
            reference("HUMAN_APPROVAL", approvals[1]["approval_id"], 1),
            now,
        )


class CodexBuildPackageReadService:
    """Tenant-bounded readiness; the package and deployment authority stay false."""
    def __init__(self, uow):
        self.uow = uow

    def readiness(self, tenant_id, package_id, package_version, generated_at):
        package = self.uow.codex_build_packages.get_version(
            tenant_id, package_id, package_version
        )
        if not package:
            return None
        brief_ref = package["implementation_brief_reference"]
        authorization_ref = package["implementation_authorization_reference"]
        brief = self.uow.implementation_briefs.get_version(
            tenant_id, brief_ref["reference_id"], brief_ref["reference_version"]
        )
        implementation_authority = self.uow.implementation_authorizations.get_version(
            tenant_id, authorization_ref["reference_id"], authorization_ref["reference_version"]
        )
        brief_status = ImplementationBriefReadService(self.uow).readiness(
            tenant_id, brief_ref["reference_id"], brief_ref["reference_version"], generated_at
        )
        authorization_status = ImplementationAuthorizationReadService(self.uow).status(
            tenant_id,
            authorization_ref["reference_id"],
            authorization_ref["reference_version"],
            generated_at,
        )
        brief_ready = bool(brief_status and brief_status["implementation_brief_ready"])
        authorization_usable = bool(
            authorization_status and authorization_status["implementation_authorization_usable"]
        )
        digests_match = bool(
            brief
            and implementation_authority
            and brief.get("implementation_brief_digest") == package["implementation_brief_digest"]
            and implementation_authority.get("implementation_brief_reference") == brief_ref
            and implementation_authority.get("implementation_brief_digest") == package["implementation_brief_digest"]
            and implementation_authority.get("implementation_authority_digest")
            == package["implementation_authority_digest"]
            and package["authorized_build_scope"] == brief["approved_scope"]
            and _target_set(package["allowed_targets"])
            == _target_set(implementation_authority["target_references"])
        )
        approvals_active = all(
            self._approval_active(tenant_id, package, role)
            for role in IMPLEMENTATION_BRIEF_ROLES
        )
        acceptance_complete = bool(
            package["acceptance_criteria"]
            and any(item["category"] == "BUSINESS" for item in package["acceptance_criteria"])
            and brief
            and _subset_exact(package["acceptance_criteria"], brief["acceptance_criteria"], "criterion_id")
        )
        prohibited_complete = bool(
            set(package["prohibited_changes"]) == REQUIRED_PROHIBITED_CHANGES
        )
        offboarding = bool(
            self.uow.ongoing_offboardings.find_by_engagement(
                tenant_id, package["engagement_id"]
            )
        )
        reasons = []
        for condition, reason in (
            (package.get("state") == "RELEASED", "PACKAGE_NOT_RELEASED"),
            (brief_ready, "BRIEF_NOT_READY"),
            (authorization_usable, "IMPLEMENTATION_AUTHORIZATION_UNUSABLE"),
            (digests_match, "DIGEST_MISMATCH"),
            (approvals_active, "APPROVAL_INVALID"),
            (acceptance_complete, "ACCEPTANCE_CRITERIA_INCOMPLETE"),
            (prohibited_complete, "PROHIBITED_CHANGES_INCOMPLETE"),
            (package.get("state") != "SUPERSEDED", "PACKAGE_SUPERSEDED"),
            (not offboarding, "OFFBOARDING_ACTIVE"),
        ):
            if not condition:
                reasons.append(reason)
        return {
            "tenant_id": tenant_id,
            "engagement_id": package["engagement_id"],
            "codex_build_package_reference": reference(
                "CODEX_BUILD_PACKAGE", package_id, package_version
            ),
            "implementation_brief_reference": copy.deepcopy(brief_ref),
            "implementation_authorization_reference": copy.deepcopy(authorization_ref),
            "package_state": package["state"],
            "brief_ready": brief_ready,
            "implementation_authorization_usable": authorization_usable,
            "digests_match": digests_match,
            "approvals_active": approvals_active,
            "acceptance_criteria_complete": acceptance_complete,
            "prohibited_changes_complete": prohibited_complete,
            "codex_build_package_ready": not reasons,
            "reasons": reasons,
            "package_grants_authority": False,
            "deployment_authorized": False,
            "production_change_authorized": False,
            "generated_at": generated_at,
        }

    def _approval_active(self, tenant_id, package, role):
        approval = self.uow.human_approvals.find_active_phase5d_binding(
            tenant_id,
            "CODEX_BUILD_PACKAGE",
            package["codex_build_package_id"],
            package["package_version"],
            package["package_digest"],
            role,
        )
        return CodexBuildPackageHandler._approval_matches(approval, package, role)
