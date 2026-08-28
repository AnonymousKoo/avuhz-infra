"""Phase 5D ImplementationBrief runtime policy.

This module implements governed implementation truth only.  A brief, including an
approved brief, grants no access, implementation, deployment, production-change,
or managed-operations authority.
"""
from __future__ import annotations

import copy
import re

from .phase5c import canonical_digest, commercial_valid, ongoing_access_usability, reference


IMPLEMENTATION_BRIEF_COMMANDS = (
    "DraftImplementationBrief",
    "ReviseImplementationBrief",
    "RecordImplementationBriefApproval",
    "ApproveImplementationBrief",
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
    "CLIENT_IMPLEMENTATION_AUTHORITY",
    "SEKINFRA_IMPLEMENTATION_AUTHORITY",
)

REQUIRED_PROHIBITED_CHANGES = frozenset({
    "OUT_OF_SCOPE_SYSTEM_CHANGE",
    "PERMISSION_WIDENING",
    "DATA_DELETION",
    "CREDENTIAL_ROTATION",
    "PRODUCTION_DEPLOYMENT",
    "PRODUCTION_CHANGE",
    "BILLING_CHANGE",
    "OUT_OF_SCOPE_NETWORK_CHANGE",
    "OUT_OF_SCOPE_SECURITY_CONTROL_CHANGE",
})

SOURCE_FIELDS = (
    "source_oia_assessment_reference",
    "source_findings_delivery_reference",
    "source_finding_revisions",
    "source_conversion_decision_reference",
    "source_ongoing_agreement_reference",
    "source_ongoing_payment_reference",
    "source_ongoing_access_reference",
)

CONTENT_FIELDS = (
    "approved_business_problem",
    "desired_business_outcome",
    "approved_scope",
    "excluded_scope",
    "known_constraints",
    "current_state_context",
    "approved_integrations",
    "allowed_access_level",
    "risks",
    "implementation_requirements",
    "acceptance_criteria",
    "prohibited_changes",
    "dependencies",
    "assumptions_and_limitations",
)

_SECRET_VALUE = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"authorization)\s*[:=]\s*\S+|bearer\s+[a-z0-9._~+/=-]{8,}"
)
_AUTHENTICATED_URL = re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql)://[^\s/:]+:[^\s/@]+@")
_RAW_DUMP = re.compile(r"(?i)\b(?:pg_dump|create\s+database|copy\s+public\.[a-z0-9_]+\s+from)\b")


def implementation_brief_source_truth_digest(payload: dict, delivery_manifest_digest: str) -> str:
    """Digest the exact immutable source chain, including the delivery manifest."""
    projection = {name: copy.deepcopy(payload[name]) for name in SOURCE_FIELDS}
    projection["delivery_manifest_digest"] = delivery_manifest_digest
    return canonical_digest(projection)


def implementation_brief_digest(payload: dict) -> str:
    """Digest the complete requested immutable brief body, excluding only itself."""
    projection = {
        name: copy.deepcopy(value)
        for name, value in payload.items()
        if name != "implementation_brief_digest"
    }
    return canonical_digest(projection)


def _ref_matches(value, reference_type, identity, version):
    return value == reference(reference_type, identity, version)


def _finding_set(values):
    return {
        (value["oia_finding_id"], value["finding_revision"], value["content_digest"])
        for value in values
    }


def _resource_targets(values):
    return {value["resource_reference_id"] for value in values}


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


def _validate_traceability(payload):
    authoritative = _finding_set(payload["source_finding_revisions"])
    scope_ids = [item["scope_item_id"] for item in payload["approved_scope"]]
    if len(scope_ids) != len(set(scope_ids)):
        raise ValueError("approved scope identities must be unique")
    requirement_ids = [item["scope_item_id"] for item in payload["implementation_requirements"]]
    if len(requirement_ids) != len(set(requirement_ids)):
        raise ValueError("implementation requirement identities must be unique")
    criterion_ids = [item["criterion_id"] for item in payload["acceptance_criteria"]]
    if len(criterion_ids) != len(set(criterion_ids)):
        raise ValueError("acceptance criterion identities must be unique")
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
            trace = item.get("finding_traceability")
            if trace is not None and (not trace or not _finding_set(trace) <= authoritative):
                raise ValueError("brief content is not traceable to exact source Findings")
    approved_scope_ids = set(scope_ids)
    for criterion in payload["acceptance_criteria"]:
        if not set(criterion["scope_item_ids"]) <= approved_scope_ids:
            raise ValueError("acceptance criterion refers outside approved scope")
    if set(payload["prohibited_changes"]) != REQUIRED_PROHIBITED_CHANGES:
        raise ValueError("complete prohibited-change set is required")


def _active_engagement(uow, tenant_id, engagement_id):
    record = uow.engagements.get(tenant_id, engagement_id)
    return record if record and record.get("engagement_state") in {"OPEN", "ONBOARDING", "ACTIVE"} else None


def resolve_implementation_brief_sources(uow, tenant_id, engagement_id, payload, trusted_now):
    """Resolve and revalidate every exact Phase 5B/5C source reference."""
    if not _active_engagement(uow, tenant_id, engagement_id):
        raise ValueError("active tenant engagement is required")

    assessment_ref = payload["source_oia_assessment_reference"]
    assessment = uow.oia_assessments.get(tenant_id, assessment_ref["reference_id"])
    if (
        not assessment or assessment.get("engagement_id") != engagement_id
        or assessment.get("state") not in {"FINDINGS_DELIVERED", "CLOSED"}
        or not _ref_matches(assessment_ref, "OIA_ASSESSMENT", assessment["oia_assessment_id"], assessment["record_version"])
    ):
        raise ValueError("exact delivered OIAAssessment version is required")

    delivery_ref = payload["source_findings_delivery_reference"]
    delivery = uow.oia_findings_deliveries.get(tenant_id, delivery_ref["reference_id"])
    if (
        not delivery or delivery.get("oia_assessment_id") != assessment["oia_assessment_id"]
        or assessment.get("findings_delivery_id") != delivery["oia_findings_delivery_id"]
        or not _ref_matches(delivery_ref, "OIA_FINDINGS_DELIVERY", delivery["oia_findings_delivery_id"], delivery["delivery_sequence"])
    ):
        raise ValueError("exact current Findings Delivery is required")

    requested_findings = _finding_set(payload["source_finding_revisions"])
    delivered_findings = _finding_set(delivery["finding_revisions"])
    if not requested_findings or not requested_findings <= delivered_findings:
        raise ValueError("exact delivered Finding revisions are required")
    for finding_id, revision, digest in requested_findings:
        finding = uow.oia_findings.get_revision(tenant_id, finding_id, revision)
        if (
            not finding or finding.get("oia_assessment_id") != assessment["oia_assessment_id"]
            or finding.get("state") != "FINAL" or finding.get("content_digest") != digest
        ):
            raise ValueError("authoritative FINAL Finding revision/digest is required")

    conversion_ref = payload["source_conversion_decision_reference"]
    conversion = uow.oia_conversion_decisions.get_version(
        tenant_id, conversion_ref["reference_id"], conversion_ref["reference_version"]
    )
    if (
        not conversion or conversion.get("engagement_id") != engagement_id
        or conversion.get("state") != "ACCEPTED" or conversion.get("decision") != "PROCEED"
        or conversion.get("oia_assessment_id") != assessment["oia_assessment_id"]
        or conversion.get("oia_findings_delivery_id") != delivery["oia_findings_delivery_id"]
        or conversion.get("delivery_sequence") != delivery["delivery_sequence"]
        or _finding_set(conversion.get("selected_finding_revisions", ())) != requested_findings
    ):
        raise ValueError("exact accepted PROCEED conversion is required")

    agreement_ref = payload["source_ongoing_agreement_reference"]
    agreement = uow.ongoing_agreement_authorities.get_version(
        tenant_id, agreement_ref["reference_id"], agreement_ref["reference_version"]
    )
    agreement_findings = _finding_set((agreement or {}).get("service_scope", {}).get("selected_finding_revisions", ()))
    if (
        not agreement or agreement.get("engagement_id") != engagement_id
        or agreement.get("state") != "ACTIVE"
        or not _ref_matches(agreement.get("conversion_decision_reference"), "OIA_CONVERSION_DECISION", conversion["oia_conversion_decision_id"], conversion["decision_version"])
        or not _ref_matches(agreement.get("findings_delivery_reference"), "OIA_FINDINGS_DELIVERY", delivery["oia_findings_delivery_id"], delivery["delivery_sequence"])
        or agreement_findings != requested_findings
        or agreement.get("effective_at") > trusted_now
        or (agreement.get("ends_at") and trusted_now >= agreement["ends_at"])
    ):
        raise ValueError("exact active Agreement #2 is required")

    payment_ref = payload["source_ongoing_payment_reference"]
    payment = uow.ongoing_payment_verifications.get(tenant_id, payment_ref["reference_id"])
    if (
        not payment or payment.get("record_version") != payment_ref["reference_version"]
        or payment.get("engagement_id") != engagement_id
        or not commercial_valid(uow, payment, agreement, conversion, trusted_now)
    ):
        raise ValueError("exact current commercial authority is required")

    access_ref = payload["source_ongoing_access_reference"]
    access = uow.ongoing_access_grants.get(tenant_id, access_ref["reference_id"])
    if (
        not access or access.get("record_version") != access_ref["reference_version"]
        or access.get("engagement_id") != engagement_id
        or not _ref_matches(access.get("conversion_decision_reference"), "OIA_CONVERSION_DECISION", conversion["oia_conversion_decision_id"], conversion["decision_version"])
        or not _ref_matches(access.get("ongoing_agreement_reference"), "ONGOING_AGREEMENT_AUTHORITY", agreement["ongoing_agreement_authority_id"], agreement["agreement_version"])
        or not _ref_matches(access.get("ongoing_payment_verification_reference"), "ONGOING_PAYMENT_VERIFICATION", payment["ongoing_payment_verification_id"], payment["record_version"])
        or not ongoing_access_usability(uow, tenant_id, access["ongoing_access_grant_id"], trusted_now)["usable"]
    ):
        raise ValueError("exact usable ongoing access is required")
    if uow.ongoing_offboardings.find_by_engagement(tenant_id, engagement_id):
        raise ValueError("offboarding blocks a new ImplementationBrief")

    source_digest = implementation_brief_source_truth_digest(payload, delivery["manifest_digest"])
    if payload["source_truth_digest"] != source_digest:
        raise ValueError("source-truth digest does not match exact authoritative sources")
    return {
        "assessment": assessment, "delivery": delivery, "conversion": conversion,
        "agreement": agreement, "payment": payment, "access": access,
    }


class ImplementationBriefHandler:
    def __init__(self, uow):
        self.uow = uow

    @staticmethod
    def _require_caller(command_type, context):
        if context.caller_type not in IMPLEMENTATION_BRIEF_CALLERS[command_type]:
            raise ValueError("caller type is not authoritative for ImplementationBrief command")

    @staticmethod
    def _require_human(context, role):
        if (
            context.caller_type != "HUMAN"
            or not context.human_principal_reference
            or not context.human_organization_reference
            or context.human_authority_role != role
            or role not in IMPLEMENTATION_BRIEF_ROLES
        ):
            raise ValueError("trusted Phase 5D human authority is required")

    def execute(self, command_type, prepared, context, now, command_id):
        self._require_caller(command_type, context)
        return getattr(self, command_type)(prepared, context, now, command_id)

    def _validate_body(self, prepared, now):
        payload = prepared.payload
        _validate_safe_content(payload)
        _validate_traceability(payload)
        sources = resolve_implementation_brief_sources(
            self.uow, prepared.tenant_id, prepared.engagement_id, payload, now
        )
        if payload["implementation_brief_digest"] != implementation_brief_digest(payload):
            raise ValueError("ImplementationBrief digest does not match exact immutable body")
        return sources

    @staticmethod
    def _record(prepared, context, now):
        payload = prepared.payload
        record = {
            "tenant_id": prepared.tenant_id,
            "engagement_id": prepared.engagement_id,
            **copy.deepcopy(payload),
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
        return record

    def DraftImplementationBrief(self, prepared, context, now, command_id):
        self._validate_body(prepared, now)
        if prepared.payload["implementation_brief_version"] != 1:
            raise ValueError("initial ImplementationBrief version must be one")
        if self.uow.implementation_briefs.get_current(prepared.tenant_id, prepared.subject_id):
            raise ValueError("ImplementationBrief identity already exists")
        return self.uow.implementation_briefs.create_initial(self._record(prepared, context, now))

    def ReviseImplementationBrief(self, prepared, context, now, command_id):
        self._validate_body(prepared, now)
        payload = prepared.payload
        current = self.uow.implementation_briefs.get_current(prepared.tenant_id, prepared.subject_id)
        supersedes = payload["supersedes_implementation_brief_reference"]
        if (
            not current or current["engagement_id"] != prepared.engagement_id
            or current.get("state") != "APPROVED"
            or current["record_version"] != prepared.expected_record_version
            or payload["implementation_brief_version"] != current["implementation_brief_version"] + 1
            or not _ref_matches(supersedes, "IMPLEMENTATION_BRIEF", current["implementation_brief_id"], current["implementation_brief_version"])
        ):
            raise ValueError("exact current ImplementationBrief version is required")
        replacement = self._record(prepared, context, now)
        return self.uow.implementation_briefs.revise(current, replacement, now)

    def RecordImplementationBriefApproval(self, prepared, context, now, command_id):
        payload = prepared.payload
        self._require_human(context, payload["authority_role"])
        current = self.uow.implementation_briefs.get_version(
            prepared.tenant_id, prepared.subject_id, payload["subject_version"]
        )
        if (
            not current or current.get("state") != "DRAFT"
            or current["engagement_id"] != prepared.engagement_id
            or current["record_version"] != prepared.expected_record_version
            or current["implementation_brief_digest"] != payload["authority_digest"]
        ):
            raise ValueError("exact draft ImplementationBrief is required")
        if self.uow.human_approvals.find_active_phase5d_binding(
            prepared.tenant_id, "IMPLEMENTATION_BRIEF", current["implementation_brief_id"],
            current["implementation_brief_version"], current["implementation_brief_digest"],
            payload["authority_role"],
        ):
            raise ValueError("duplicate active Phase 5D authority")
        record = {
            "approval_id": command_id,
            "tenant_id": prepared.tenant_id,
            "engagement_id": prepared.engagement_id,
            "subject_type": "IMPLEMENTATION_BRIEF",
            "subject_id": current["implementation_brief_id"],
            "subject_version": current["implementation_brief_version"],
            "approval_category": "IMPLEMENTATION_BRIEF",
            "authority_category": "CLIENT_AUTHORITY" if payload["authority_role"] == "CLIENT_IMPLEMENTATION_AUTHORITY" else "SEKINFRA_AUTHORITY",
            "actor_identity": context.human_principal_reference,
            "actor_organization": context.human_organization_reference,
            "actor_role": payload["authority_role"],
            "decision": "APPROVE",
            "phase5d_authority": {
                "subject_id": current["implementation_brief_id"],
                "authority_digest": current["implementation_brief_digest"],
            },
            "conditions": [],
            "effective_at": now,
            "evidence_reference": {
                "reference_type": current["source_findings_delivery_reference"]["reference_type"],
                "reference_id": current["source_findings_delivery_reference"]["reference_id"],
            },
            "status": "ACTIVE",
            "correlation_id": prepared.correlation_id,
            "idempotency_key": prepared.idempotency_key,
            "created_at": now,
        }
        self.uow.human_approvals.record_phase5d(record)
        return {"record": current, "approval": record}

    @staticmethod
    def _approval_matches(approval, current, role):
        return bool(
            approval and approval.get("status") == "ACTIVE" and approval.get("decision") == "APPROVE"
            and approval.get("actor_role") == role
            and approval.get("subject_type") == "IMPLEMENTATION_BRIEF"
            and approval.get("subject_id") == current["implementation_brief_id"]
            and approval.get("subject_version") == current["implementation_brief_version"]
            and approval.get("phase5d_authority", {}).get("authority_digest") == current["implementation_brief_digest"]
        )

    def ApproveImplementationBrief(self, prepared, context, now, command_id):
        payload = prepared.payload
        current = self.uow.implementation_briefs.get_version(
            prepared.tenant_id, payload["implementation_brief_id"], payload["implementation_brief_version"]
        )
        if (
            not current or current.get("state") != "DRAFT"
            or current["engagement_id"] != prepared.engagement_id
            or current["record_version"] != prepared.expected_record_version
            or current["implementation_brief_digest"] != payload["implementation_brief_digest"]
            or payload["client_approval_reference"] == payload["sekinfra_approval_reference"]
        ):
            raise ValueError("exact draft ImplementationBrief is not approvable")
        # Approval is consequential: revalidate the exact source chain at trusted server time.
        resolve_implementation_brief_sources(
            self.uow, prepared.tenant_id, prepared.engagement_id, current, now
        )
        approvals = []
        for role, field in (
            ("CLIENT_IMPLEMENTATION_AUTHORITY", "client_approval_reference"),
            ("SEKINFRA_IMPLEMENTATION_AUTHORITY", "sekinfra_approval_reference"),
        ):
            approval_ref = payload[field]
            approval = self.uow.human_approvals.get(prepared.tenant_id, approval_ref["reference_id"])
            if approval_ref.get("reference_version") != 1 or not self._approval_matches(approval, current, role):
                raise ValueError("active exact dual ImplementationBrief approvals are required")
            approvals.append(approval)
        return self.uow.implementation_briefs.approve(
            current,
            reference("HUMAN_APPROVAL", approvals[0]["approval_id"], 1),
            reference("HUMAN_APPROVAL", approvals[1]["approval_id"], 1),
            now,
        )


class ImplementationBriefReadService:
    """Tenant-bounded deterministic readiness with authority fixed false."""
    def __init__(self, uow):
        self.uow = uow

    def readiness(self, tenant_id, brief_id, brief_version, generated_at):
        brief = self.uow.implementation_briefs.get_version(tenant_id, brief_id, brief_version)
        if not brief:
            return None
        source_exact = conversion_valid = agreement_valid_now = commercial_valid_now = access_usable = False
        offboarding = bool(self.uow.ongoing_offboardings.find_by_engagement(tenant_id, brief["engagement_id"]))
        try:
            sources = resolve_implementation_brief_sources(
                self.uow, tenant_id, brief["engagement_id"], brief, generated_at
            )
            source_exact = conversion_valid = agreement_valid_now = commercial_valid_now = access_usable = True
        except ValueError:
            conversion_ref = brief["source_conversion_decision_reference"]
            conversion = self.uow.oia_conversion_decisions.get_version(
                tenant_id, conversion_ref["reference_id"], conversion_ref["reference_version"]
            )
            conversion_valid = bool(conversion and conversion.get("state") == "ACCEPTED" and conversion.get("decision") == "PROCEED")
            agreement_ref = brief["source_ongoing_agreement_reference"]
            agreement = self.uow.ongoing_agreement_authorities.get_version(
                tenant_id, agreement_ref["reference_id"], agreement_ref["reference_version"]
            )
            agreement_valid_now = bool(
                agreement and agreement.get("state") == "ACTIVE"
                and agreement.get("effective_at") <= generated_at
                and (not agreement.get("ends_at") or generated_at < agreement["ends_at"])
            )
            payment_ref = brief["source_ongoing_payment_reference"]
            payment = self.uow.ongoing_payment_verifications.get(tenant_id, payment_ref["reference_id"])
            commercial_valid_now = bool(
                payment and payment.get("record_version") == payment_ref["reference_version"]
                and agreement and conversion
                and commercial_valid(self.uow, payment, agreement, conversion, generated_at)
            )
            access_ref = brief["source_ongoing_access_reference"]
            access = self.uow.ongoing_access_grants.get(tenant_id, access_ref["reference_id"])
            access_usable = bool(
                access and access.get("record_version") == access_ref["reference_version"]
                and ongoing_access_usability(self.uow, tenant_id, access_ref["reference_id"], generated_at)["usable"]
            )
        approvals = {}
        for role in IMPLEMENTATION_BRIEF_ROLES:
            approvals[role] = self.uow.human_approvals.find_active_phase5d_binding(
                tenant_id, "IMPLEMENTATION_BRIEF", brief_id, brief_version,
                brief["implementation_brief_digest"], role,
            )
        client_active = ImplementationBriefHandler._approval_matches(approvals[IMPLEMENTATION_BRIEF_ROLES[0]], brief, IMPLEMENTATION_BRIEF_ROLES[0])
        sekinfra_active = ImplementationBriefHandler._approval_matches(approvals[IMPLEMENTATION_BRIEF_ROLES[1]], brief, IMPLEMENTATION_BRIEF_ROLES[1])
        source_findings = _finding_set(brief["source_finding_revisions"])
        scope_traceable = all(_finding_set(item["finding_traceability"]) <= source_findings for item in brief["approved_scope"])
        criteria_traceable = all(
            _finding_set(item["finding_traceability"]) <= source_findings
            and set(item["scope_item_ids"]) <= {scope["scope_item_id"] for scope in brief["approved_scope"]}
            for item in brief["acceptance_criteria"]
        )
        prohibited_complete = set(brief["prohibited_changes"]) == REQUIRED_PROHIBITED_CHANGES
        reasons = []
        for condition, reason in (
            (brief.get("state") == "APPROVED", "BRIEF_NOT_APPROVED"),
            (source_exact, "SOURCE_TRUTH_MISMATCH"),
            (conversion_valid, "CONVERSION_INVALID"),
            (agreement_valid_now, "AGREEMENT_INVALID"),
            (commercial_valid_now, "COMMERCIAL_AUTHORITY_INVALID"),
            (access_usable, "ONGOING_ACCESS_UNUSABLE"),
            (client_active, "CLIENT_APPROVAL_MISSING"),
            (sekinfra_active, "SEKINFRA_APPROVAL_MISSING"),
            (scope_traceable, "SCOPE_UNTRACEABLE"),
            (criteria_traceable, "ACCEPTANCE_CRITERIA_UNTRACEABLE"),
            (prohibited_complete, "PROHIBITED_CHANGES_INCOMPLETE"),
            (not offboarding, "OFFBOARDING_ACTIVE"),
        ):
            if not condition:
                reasons.append(reason)
        return {
            "tenant_id": tenant_id,
            "engagement_id": brief["engagement_id"],
            "implementation_brief_reference": reference("IMPLEMENTATION_BRIEF", brief_id, brief_version),
            "source_truth_exact": source_exact,
            "conversion_accepted": conversion_valid,
            "ongoing_agreement_active": agreement_valid_now,
            "commercial_authority_valid": commercial_valid_now,
            "ongoing_access_usable": access_usable,
            "client_approval_active": client_active,
            "sekinfra_approval_active": sekinfra_active,
            "implementation_brief_ready": not reasons,
            "reasons": reasons,
            "implementation_authorized": False,
            "deployment_authorized": False,
            "production_change_authorized": False,
            "generated_at": generated_at,
        }
