"""Provider-neutral Phase 5D ImplementationBrief runtime policy.

An approved brief is derived from one exact approved ImplementationHandoff. It
grants no access, implementation, production-change, or deployment authority.
"""
from __future__ import annotations

import copy
import re

from .implementation_handoff import canonical_digest, handoff_reference


IMPLEMENTATION_BRIEF_COMMANDS = (
    "DraftImplementationBrief", "ReviseImplementationBrief",
    "RecordImplementationBriefApproval", "ApproveImplementationBrief",
)

IMPLEMENTATION_BRIEF_CAPABILITIES = {
    "DraftImplementationBrief": "implementation_brief:draft",
    "ReviseImplementationBrief": "implementation_brief:draft",
    "RecordImplementationBriefApproval": "implementation_brief:approve",
    "ApproveImplementationBrief": "implementation_brief:approve",
}

IMPLEMENTATION_BRIEF_EVENTS = {
    "DraftImplementationBrief": "implementation_brief.drafted",
    "ReviseImplementationBrief": "implementation_brief.revised",
    "RecordImplementationBriefApproval": "implementation_brief.approval_recorded",
    "ApproveImplementationBrief": "implementation_brief.approved",
}

IMPLEMENTATION_BRIEF_CALLERS = {
    "DraftImplementationBrief": frozenset({"HUMAN", "INTERNAL_SERVICE"}),
    "ReviseImplementationBrief": frozenset({"HUMAN", "INTERNAL_SERVICE"}),
    "RecordImplementationBriefApproval": frozenset({"HUMAN"}),
    "ApproveImplementationBrief": frozenset({"INTERNAL_SERVICE"}),
}

IMPLEMENTATION_BRIEF_ROLES = (
    "CLIENT_IMPLEMENTATION_AUTHORITY", "PROVIDER_IMPLEMENTATION_AUTHORITY",
)

REQUIRED_PROHIBITED_CHANGES = frozenset({
    "OUT_OF_SCOPE_SYSTEM_CHANGE", "PERMISSION_WIDENING", "DATA_DELETION",
    "CREDENTIAL_ROTATION", "PRODUCTION_DEPLOYMENT", "PRODUCTION_CHANGE",
    "BILLING_CHANGE", "OUT_OF_SCOPE_NETWORK_CHANGE",
    "OUT_OF_SCOPE_SECURITY_CONTROL_CHANGE",
})

CONTENT_FIELDS = (
    "approved_business_problem", "desired_business_outcome", "approved_scope",
    "excluded_scope", "known_constraints", "current_state_context",
    "approved_integrations", "risks", "implementation_requirements",
    "acceptance_criteria", "prohibited_changes", "dependencies",
    "assumptions_and_limitations",
)

_SECRET_VALUE = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"authorization)\s*[:=]\s*\S+|bearer\s+[a-z0-9._~+/=-]{8,}"
)
_AUTHENTICATED_URL = re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql)://[^\s/:]+:[^\s/@]+@")
_RAW_DUMP = re.compile(r"(?i)\b(?:pg_dump|create\s+database|copy\s+public\.[a-z0-9_]+\s+from)\b")


def reference(reference_type, reference_id, reference_version):
    return {"reference_type": reference_type, "reference_id": reference_id, "reference_version": reference_version}


def implementation_brief_source_truth_digest(payload: dict, *_ignored) -> str:
    return canonical_digest(payload["source_implementation_handoff_reference"])


def implementation_brief_digest(payload: dict) -> str:
    return canonical_digest({key: copy.deepcopy(value) for key, value in payload.items() if key != "implementation_brief_digest"})


def _walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _walk_strings(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_strings(child)


def _validate_safe_content(payload):
    for field in CONTENT_FIELDS:
        for value in _walk_strings(payload[field]):
            if _SECRET_VALUE.search(value) or _AUTHENTICATED_URL.search(value) or _RAW_DUMP.search(value):
                raise ValueError("credential, secret-bearing URL, or raw dump material is prohibited")


def _source_key(value):
    return (
        value["reference_type"], value["reference_id"],
        value.get("reference_version"), value.get("reference_digest"),
    )


def _validate_traceability(payload, handoff):
    authoritative = {_source_key(item) for item in handoff["source_artifact_references"]}
    scope_ids = [item["scope_item_id"] for item in payload["approved_scope"]]
    requirement_ids = [item["scope_item_id"] for item in payload["implementation_requirements"]]
    criterion_ids = [item["criterion_id"] for item in payload["acceptance_criteria"]]
    for values, label in ((scope_ids, "scope"), (requirement_ids, "requirement"), (criterion_ids, "criterion")):
        if len(values) != len(set(values)):
            raise ValueError(f"{label} identities must be unique")
    for collection in (payload["current_state_context"], payload["assumptions_and_limitations"]):
        identities = [item["context_item_id"] for item in collection]
        if len(identities) != len(set(identities)):
            raise ValueError("context identities must be unique")
    for collection in (
        payload["approved_scope"], payload["implementation_requirements"],
        payload["acceptance_criteria"], payload["current_state_context"],
        payload["assumptions_and_limitations"],
    ):
        for item in collection:
            trace = item.get("source_traceability")
            if trace is not None and (not trace or not {_source_key(value) for value in trace} <= authoritative):
                raise ValueError("brief content is not traceable to exact handoff source artifacts")
    approved_scope_ids = set(scope_ids)
    if any(not set(item["scope_item_ids"]) <= approved_scope_ids for item in payload["acceptance_criteria"]):
        raise ValueError("acceptance criterion refers outside approved scope")
    if set(payload["prohibited_changes"]) != REQUIRED_PROHIBITED_CHANGES:
        raise ValueError("complete prohibited-change set is required")


def _pairs(values, id_field, statement_field):
    return {(item[id_field], item[statement_field]) for item in values}


def _validate_handoff_boundary(payload, handoff):
    if payload["approved_business_problem"] != handoff["problem_statement"]:
        raise ValueError("problem statement must match the exact approved handoff")
    if payload["desired_business_outcome"] != handoff["desired_outcome"]:
        raise ValueError("desired outcome must match the exact approved handoff")
    if _pairs(payload["approved_scope"], "scope_item_id", "statement") != _pairs(handoff["approved_scope"], "scope_item_id", "description"):
        raise ValueError("brief scope must match the exact approved handoff")
    if payload["excluded_scope"] != handoff["excluded_scope"]:
        raise ValueError("excluded scope must be preserved exactly")
    if payload["known_constraints"] != handoff["constraints"]:
        raise ValueError("handoff constraints must be preserved exactly")
    if payload["allowed_access_level"] != handoff["allowed_access_level"]:
        raise ValueError("brief access level cannot differ from the approved handoff")
    if _pairs(payload["approved_integrations"], "integration_reference", "purpose") != _pairs(handoff["integrations"], "id", "statement"):
        raise ValueError("brief integrations must match the exact approved handoff")
    if payload["risks"] != [item["statement"] for item in handoff["risks"]]:
        raise ValueError("handoff risks must be preserved exactly")
    if _pairs(payload["implementation_requirements"], "scope_item_id", "statement") != _pairs(handoff["implementation_requirements"], "id", "statement"):
        raise ValueError("implementation requirements must match the exact approved handoff")
    criteria = {(item["criterion_id"], item["statement"], item["verification_method"]) for item in payload["acceptance_criteria"]}
    source_criteria = {(item["criterion_id"], item["expected_condition"], item["evidence_requirement"]) for item in handoff["acceptance_criteria"]}
    if criteria != source_criteria:
        raise ValueError("acceptance criteria must match the exact approved handoff")
    if payload["prohibited_changes"] != handoff["prohibited_changes"]:
        raise ValueError("prohibited changes must be preserved exactly")
    if payload["dependencies"] != [item["statement"] for item in handoff["dependencies"]]:
        raise ValueError("dependencies must match the exact approved handoff")
    if [item["statement"] for item in payload["assumptions_and_limitations"]] != handoff["assumptions_limitations"]:
        raise ValueError("assumptions and limitations must match the exact approved handoff")


def resolve_implementation_brief_sources(uow, tenant_id, engagement_id, payload, trusted_now):
    source = payload["source_implementation_handoff_reference"]
    handoff = uow.implementation_handoffs.get_version(tenant_id, source["reference_id"], source["reference_version"])
    current = uow.implementation_handoffs.get_current(tenant_id, source["reference_id"])
    if (
        not handoff or not current or handoff != current or handoff.get("state") != "APPROVED"
        or handoff.get("source_engagement_reference") != engagement_id
        or source != handoff_reference(handoff)
    ):
        raise ValueError("exact current approved ImplementationHandoff version/digest is required")
    if payload["source_truth_digest"] != implementation_brief_source_truth_digest(payload):
        raise ValueError("source-truth digest does not match the exact handoff binding")
    _validate_traceability(payload, handoff)
    _validate_handoff_boundary(payload, handoff)
    return {"implementation_handoff": handoff}


class ImplementationBriefHandler:
    def __init__(self, uow): self.uow = uow

    @staticmethod
    def _require_caller(command_type, context):
        if context.caller_type not in IMPLEMENTATION_BRIEF_CALLERS[command_type]:
            raise ValueError("caller type is not authoritative for ImplementationBrief command")

    @staticmethod
    def _require_human(context, role):
        if (context.caller_type != "HUMAN" or not context.human_principal_reference
                or not context.human_organization_reference or context.human_authority_role != role
                or role not in IMPLEMENTATION_BRIEF_ROLES):
            raise ValueError("trusted Phase 5D human authority is required")

    def execute(self, command_type, prepared, context, now, command_id):
        self._require_caller(command_type, context)
        return getattr(self, command_type)(prepared, context, now, command_id)

    def _validate_body(self, prepared, now):
        payload = prepared.payload
        _validate_safe_content(payload)
        sources = resolve_implementation_brief_sources(self.uow, prepared.tenant_id, prepared.engagement_id, payload, now)
        if payload["implementation_brief_digest"] != implementation_brief_digest(payload):
            raise ValueError("ImplementationBrief digest does not match exact immutable body")
        return sources

    @staticmethod
    def _record(prepared, context, now):
        return {
            "tenant_id": prepared.tenant_id, "engagement_id": prepared.engagement_id,
            **copy.deepcopy(prepared.payload), "state": "DRAFT",
            "trusted_attribution": {
                "drafted_by": context.human_principal_reference or context.principal_id,
                "recorded_by": context.principal_id,
                "draft_assistance": "AI_ASSISTED" if context.caller_type == "INTERNAL_SERVICE" else "NONE",
            },
            "record_version": 1, "created_at": now, "updated_at": now,
        }

    def DraftImplementationBrief(self, prepared, context, now, command_id):
        self._validate_body(prepared, now)
        if prepared.payload["implementation_brief_version"] != 1:
            raise ValueError("initial ImplementationBrief version must be one")
        if self.uow.implementation_briefs.get_current(prepared.tenant_id, prepared.subject_id):
            raise ValueError("ImplementationBrief identity already exists")
        return self.uow.implementation_briefs.create_initial(self._record(prepared, context, now))

    def ReviseImplementationBrief(self, prepared, context, now, command_id):
        self._validate_body(prepared, now); payload = prepared.payload
        current = self.uow.implementation_briefs.get_current(prepared.tenant_id, prepared.subject_id)
        if (not current or current["engagement_id"] != prepared.engagement_id or current.get("state") != "APPROVED"
                or current["record_version"] != prepared.expected_record_version
                or payload["implementation_brief_version"] != current["implementation_brief_version"] + 1
                or payload["supersedes_implementation_brief_reference"] != reference("IMPLEMENTATION_BRIEF", current["implementation_brief_id"], current["implementation_brief_version"])):
            raise ValueError("exact current ImplementationBrief version is required")
        return self.uow.implementation_briefs.revise(current, self._record(prepared, context, now), now)

    def RecordImplementationBriefApproval(self, prepared, context, now, command_id):
        payload = prepared.payload; self._require_human(context, payload["authority_role"])
        current = self.uow.implementation_briefs.get_version(prepared.tenant_id, prepared.subject_id, payload["subject_version"])
        if (not current or current.get("state") != "DRAFT" or current["engagement_id"] != prepared.engagement_id
                or current["record_version"] != prepared.expected_record_version
                or current["implementation_brief_digest"] != payload["authority_digest"]):
            raise ValueError("exact draft ImplementationBrief is required")
        if self.uow.human_approvals.find_active_phase5d_binding(prepared.tenant_id, "IMPLEMENTATION_BRIEF", current["implementation_brief_id"], current["implementation_brief_version"], current["implementation_brief_digest"], payload["authority_role"]):
            raise ValueError("duplicate active Phase 5D authority")
        source = current["source_implementation_handoff_reference"]
        approval = {
            "approval_id": command_id, "tenant_id": prepared.tenant_id, "engagement_id": prepared.engagement_id,
            "subject_type": "IMPLEMENTATION_BRIEF", "subject_id": current["implementation_brief_id"],
            "subject_version": current["implementation_brief_version"], "approval_category": "IMPLEMENTATION_BRIEF",
            "authority_category": "CLIENT_AUTHORITY" if payload["authority_role"] == "CLIENT_IMPLEMENTATION_AUTHORITY" else "PROVIDER_AUTHORITY",
            "actor_identity": context.human_principal_reference, "actor_organization": context.human_organization_reference,
            "actor_role": payload["authority_role"], "decision": "APPROVE",
            "phase5d_authority": {"subject_id": current["implementation_brief_id"], "authority_digest": current["implementation_brief_digest"]},
            "conditions": [], "effective_at": now,
            "evidence_reference": {"reference_type": source["reference_type"], "reference_id": source["reference_id"]},
            "status": "ACTIVE", "correlation_id": prepared.correlation_id,
            "idempotency_key": prepared.idempotency_key, "created_at": now,
        }
        self.uow.human_approvals.record_phase5d(approval)
        return {"record": current, "approval": approval}

    @staticmethod
    def _approval_matches(approval, current, role):
        return bool(approval and approval.get("status") == "ACTIVE" and approval.get("decision") == "APPROVE"
            and approval.get("actor_role") == role and approval.get("subject_type") == "IMPLEMENTATION_BRIEF"
            and approval.get("subject_id") == current["implementation_brief_id"]
            and approval.get("subject_version") == current["implementation_brief_version"]
            and approval.get("phase5d_authority", {}).get("authority_digest") == current["implementation_brief_digest"])

    def ApproveImplementationBrief(self, prepared, context, now, command_id):
        payload = prepared.payload
        current = self.uow.implementation_briefs.get_version(prepared.tenant_id, payload["implementation_brief_id"], payload["implementation_brief_version"])
        if (not current or current.get("state") != "DRAFT" or current["engagement_id"] != prepared.engagement_id
                or current["record_version"] != prepared.expected_record_version
                or current["implementation_brief_digest"] != payload["implementation_brief_digest"]
                or payload["client_approval_reference"] == payload["provider_approval_reference"]):
            raise ValueError("exact draft ImplementationBrief is not approvable")
        resolve_implementation_brief_sources(self.uow, prepared.tenant_id, prepared.engagement_id, current, now)
        approvals = []
        for role, field in (("CLIENT_IMPLEMENTATION_AUTHORITY", "client_approval_reference"), ("PROVIDER_IMPLEMENTATION_AUTHORITY", "provider_approval_reference")):
            approval_ref = payload[field]; approval = self.uow.human_approvals.get(prepared.tenant_id, approval_ref["reference_id"])
            if approval_ref.get("reference_version") != 1 or not self._approval_matches(approval, current, role):
                raise ValueError("active exact dual ImplementationBrief approvals are required")
            approvals.append(approval)
        return self.uow.implementation_briefs.approve(current, reference("HUMAN_APPROVAL", approvals[0]["approval_id"], 1), reference("HUMAN_APPROVAL", approvals[1]["approval_id"], 1), now)


class ImplementationBriefReadService:
    def __init__(self, uow): self.uow = uow

    def readiness(self, tenant_id, brief_id, brief_version, generated_at):
        brief = self.uow.implementation_briefs.get_version(tenant_id, brief_id, brief_version)
        if not brief: return None
        try:
            resolve_implementation_brief_sources(self.uow, tenant_id, brief["engagement_id"], brief, generated_at)
            source_exact = True
        except ValueError:
            source_exact = False
        approvals = {role: self.uow.human_approvals.find_active_phase5d_binding(tenant_id, "IMPLEMENTATION_BRIEF", brief_id, brief_version, brief["implementation_brief_digest"], role) for role in IMPLEMENTATION_BRIEF_ROLES}
        client_active = ImplementationBriefHandler._approval_matches(approvals[IMPLEMENTATION_BRIEF_ROLES[0]], brief, IMPLEMENTATION_BRIEF_ROLES[0])
        provider_active = ImplementationBriefHandler._approval_matches(approvals[IMPLEMENTATION_BRIEF_ROLES[1]], brief, IMPLEMENTATION_BRIEF_ROLES[1])
        reasons = []
        for condition, reason in ((brief.get("state") == "APPROVED", "BRIEF_NOT_APPROVED"), (source_exact, "HANDOFF_SOURCE_MISMATCH"), (client_active, "CLIENT_APPROVAL_MISSING"), (provider_active, "PROVIDER_APPROVAL_MISSING")):
            if not condition: reasons.append(reason)
        return {
            "tenant_id": tenant_id, "engagement_id": brief["engagement_id"],
            "implementation_brief_reference": reference("IMPLEMENTATION_BRIEF", brief_id, brief_version),
            "implementation_handoff_reference": copy.deepcopy(brief["source_implementation_handoff_reference"]),
            "source_truth_exact": source_exact, "client_approval_active": client_active,
            "provider_approval_active": provider_active, "implementation_brief_ready": not reasons,
            "reasons": reasons, "implementation_authorized": False,
            "deployment_authorized": False, "production_change_authorized": False,
            "generated_at": generated_at,
        }
