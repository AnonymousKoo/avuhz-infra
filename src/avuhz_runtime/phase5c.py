"""Phase 5C conversion and ongoing-authority command/runtime policy.

The module is provider-neutral.  It operates only through repositories exposed by
the existing UnitOfWork and never treats an access channel as change authority.
"""
from __future__ import annotations

import copy
import hashlib
import json


PHASE5C_COMMANDS = (
    "RecordOIAConversionDecision", "AcceptOIAConversion",
    "ProposeOngoingAgreement", "RecordOngoingAgreementApproval",
    "ActivateOngoingAgreement", "TerminateOngoingAgreement",
    "RecordOngoingPaymentVerification", "InvalidateOngoingPaymentVerification",
    "ProposeOngoingAccessGrant", "RecordOngoingAccessApproval",
    "ApproveOngoingAccessGrant", "VerifyOngoingAccess",
    "RevokeOngoingAccess", "CloseOngoingAccess",
    "InitiateOngoingOffboarding", "VerifyOngoingAccessRevocation",
    "CompleteOngoingOffboarding",
)

PHASE5C_CAPABILITIES = {
    "RecordOIAConversionDecision": "conversion:decide",
    "AcceptOIAConversion": "conversion:accept",
    "ProposeOngoingAgreement": "ongoing_agreement:propose",
    "RecordOngoingAgreementApproval": "ongoing_agreement:approve",
    "ActivateOngoingAgreement": "ongoing_agreement:activate",
    "TerminateOngoingAgreement": "ongoing_agreement:terminate",
    "RecordOngoingPaymentVerification": "ongoing_payment:record",
    "InvalidateOngoingPaymentVerification": "ongoing_payment:invalidate",
    "ProposeOngoingAccessGrant": "ongoing_access:propose",
    "RecordOngoingAccessApproval": "ongoing_access:approve",
    "ApproveOngoingAccessGrant": "ongoing_access:approve",
    "VerifyOngoingAccess": "ongoing_access:activate",
    "RevokeOngoingAccess": "ongoing_access:revoke",
    "CloseOngoingAccess": "ongoing_access:close",
    "InitiateOngoingOffboarding": "offboarding:initiate",
    "VerifyOngoingAccessRevocation": "offboarding:verify_revocation",
    "CompleteOngoingOffboarding": "offboarding:complete",
}

PHASE5C_EVENTS = {
    "RecordOIAConversionDecision": "conversion.decision_recorded",
    "AcceptOIAConversion": "conversion.accepted",
    "ProposeOngoingAgreement": "ongoing_agreement.proposed",
    "RecordOngoingAgreementApproval": "ongoing_agreement.approval_recorded",
    "ActivateOngoingAgreement": "ongoing_agreement.activated",
    "TerminateOngoingAgreement": "ongoing_agreement.terminated",
    "RecordOngoingPaymentVerification": "ongoing_payment.verified",
    "InvalidateOngoingPaymentVerification": "ongoing_payment.invalidated",
    "ProposeOngoingAccessGrant": "ongoing_access.proposed",
    "RecordOngoingAccessApproval": "ongoing_access.approval_recorded",
    "ApproveOngoingAccessGrant": "ongoing_access.approved",
    "VerifyOngoingAccess": "ongoing_access.activated",
    "RevokeOngoingAccess": "ongoing_access.revoked",
    "CloseOngoingAccess": "ongoing_access.closed",
    "InitiateOngoingOffboarding": "offboarding.initiated",
    "VerifyOngoingAccessRevocation": "ongoing_access.revocation_verified",
    "CompleteOngoingOffboarding": "offboarding.completed",
}

ALLOWED_CALLER_TYPES = {
    "RecordOIAConversionDecision": frozenset({"HUMAN"}),
    "AcceptOIAConversion": frozenset({"HUMAN"}),
    "ProposeOngoingAgreement": frozenset({"HUMAN", "INTERNAL_SERVICE"}),
    "RecordOngoingAgreementApproval": frozenset({"HUMAN"}),
    "ActivateOngoingAgreement": frozenset({"INTERNAL_SERVICE"}),
    "TerminateOngoingAgreement": frozenset({"HUMAN"}),
    "RecordOngoingPaymentVerification": frozenset({"INTERNAL_SERVICE", "PROVIDER_ADAPTER"}),
    "InvalidateOngoingPaymentVerification": frozenset({"INTERNAL_SERVICE", "PROVIDER_ADAPTER"}),
    "ProposeOngoingAccessGrant": frozenset({"HUMAN", "INTERNAL_SERVICE"}),
    "RecordOngoingAccessApproval": frozenset({"HUMAN"}),
    "ApproveOngoingAccessGrant": frozenset({"INTERNAL_SERVICE"}),
    "VerifyOngoingAccess": frozenset({"INTERNAL_SERVICE", "PROVIDER_ADAPTER"}),
    "RevokeOngoingAccess": frozenset({"HUMAN", "SECURITY_AUTOMATION"}),
    "CloseOngoingAccess": frozenset({"INTERNAL_SERVICE"}),
    "InitiateOngoingOffboarding": frozenset({"HUMAN"}),
    "VerifyOngoingAccessRevocation": frozenset({"INTERNAL_SERVICE", "PROVIDER_ADAPTER"}),
    "CompleteOngoingOffboarding": frozenset({"HUMAN", "INTERNAL_SERVICE"}),
}

PROHIBITED_CHANGE_ACTIONS = frozenset({
    "CREATE", "MODIFY", "DELETE", "DEPLOY", "RESTART", "ROTATE", "GRANT",
    "REVOKE", "CHANGE_CONFIGURATION", "PRODUCTION_CHANGE",
})


def canonical_digest(value) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def reference(reference_type, reference_id, reference_version):
    return {
        "reference_type": reference_type,
        "reference_id": reference_id,
        "reference_version": reference_version,
    }


def _same_reference(value, kind, identity, version):
    return value == reference(kind, identity, version)


def _active_engagement(uow, tenant_id, engagement_id):
    engagement = uow.engagements.get(tenant_id, engagement_id)
    return engagement if engagement and engagement.get("engagement_state") in {
        "OPEN", "ONBOARDING", "ACTIVE"
    } else None


def _targets(values):
    return {value["resource_reference_id"] for value in values}


def _findings(values):
    return {
        (value["oia_finding_id"], value["finding_revision"], value["content_digest"])
        for value in values
    }


def agreement_valid(uow, agreement, conversion, trusted_now):
    if not agreement or not conversion:
        return False
    return all((
        agreement["tenant_id"] == conversion["tenant_id"],
        agreement["engagement_id"] == conversion["engagement_id"],
        conversion.get("state") == "ACCEPTED",
        _same_reference(
            agreement["conversion_decision_reference"], "OIA_CONVERSION_DECISION",
            conversion["oia_conversion_decision_id"], conversion["decision_version"],
        ),
        agreement.get("state") == "ACTIVE",
        agreement["effective_at"] <= trusted_now,
        not agreement.get("ends_at") or trusted_now < agreement["ends_at"],
    ))


def commercial_valid(uow, payment, agreement, conversion, trusted_now):
    return bool(
        payment and agreement_valid(uow, agreement, conversion, trusted_now)
        and payment["tenant_id"] == agreement["tenant_id"]
        and payment["engagement_id"] == agreement["engagement_id"]
        and _same_reference(
            payment["ongoing_agreement_reference"], "ONGOING_AGREEMENT_AUTHORITY",
            agreement["ongoing_agreement_authority_id"], agreement["agreement_version"],
        )
        and payment.get("status") == "VERIFIED"
        and payment["coverage_from"] <= trusted_now < payment["coverage_until"]
    )


def ongoing_access_usability(uow, tenant_id, grant_id, trusted_now, target_reference=None):
    grant = uow.ongoing_access_grants.get(tenant_id, grant_id)
    if not grant:
        return {"usable": False, "reasons": ["GRANT_NOT_ACTIVE"]}
    reasons = []
    engagement = _active_engagement(uow, tenant_id, grant["engagement_id"])
    if not engagement:
        reasons.append("ENGAGEMENT_INACTIVE")
    cref = grant["conversion_decision_reference"]
    conversion = uow.oia_conversion_decisions.get_version(
        tenant_id, cref["reference_id"], cref["reference_version"]
    )
    if not conversion or conversion.get("state") != "ACCEPTED":
        reasons.append("CONVERSION_NOT_ACCEPTED")
    aref = grant["ongoing_agreement_reference"]
    agreement = uow.ongoing_agreement_authorities.get_version(
        tenant_id, aref["reference_id"], aref["reference_version"]
    )
    if not agreement_valid(uow, agreement, conversion, trusted_now):
        reasons.append("AGREEMENT_INVALID")
    pref = grant["ongoing_payment_verification_reference"]
    payment = uow.ongoing_payment_verifications.get(tenant_id, pref["reference_id"])
    if (
        not payment
        or payment.get("record_version") != pref["reference_version"]
        or not commercial_valid(uow, payment, agreement, conversion, trusted_now)
    ):
        reasons.append("COMMERCIAL_INVALID")
    if grant.get("state") != "ACTIVE":
        reasons.append(
            "REVOKED" if grant.get("state") == "REVOKED"
            else "CLOSED" if grant.get("state") == "CLOSED"
            else "GRANT_NOT_ACTIVE"
        )
    if grant.get("active_from") and trusted_now < grant["active_from"]:
        reasons.append("BEFORE_ACTIVE_FROM")
    if trusted_now >= grant["expires_at"]:
        reasons.append("GRANT_EXPIRED")
    if agreement and grant["service_scope_digest"] != agreement["service_scope_digest"]:
        reasons.append("SCOPE_MISMATCH")
    agreement_targets = _targets(agreement["service_scope"]["target_system_references"]) if agreement else set()
    grant_targets = _targets(grant["target_resource_references"])
    if not grant_targets <= agreement_targets or (
        target_reference is not None
        and (target_reference not in grant_targets or target_reference not in agreement_targets)
    ):
        reasons.append("TARGET_MISMATCH")
    if uow.ongoing_offboardings.find_by_engagement(tenant_id, grant["engagement_id"]):
        reasons.append("OFFBOARDING_ACTIVE")
    return {"usable": not reasons, "reasons": list(dict.fromkeys(reasons))}


def ongoing_access_authorizes_action(*_args, **_kwargs):
    """Phase 5C access is a channel only and never authorizes a change action."""
    return False


class InMemoryOngoingAccessVerifier:
    def verify(self, grant, trusted_context, trusted_now):
        return {"verified": True}


class InMemoryOngoingRevocationVerifier:
    def verify(self, grant, offboarding, trusted_context, trusted_now):
        return {
            "verification_result": "ACCESS_REMOVAL_VERIFIED",
            "verification_reference": "local.revocation-verification",
        }


class Phase5CHandler:
    def __init__(self, uow, access_verifier=None, revocation_verifier=None):
        self.uow = uow
        self.access_verifier = access_verifier or InMemoryOngoingAccessVerifier()
        self.revocation_verifier = revocation_verifier or InMemoryOngoingRevocationVerifier()

    @staticmethod
    def require_caller(command_type, context):
        if context.caller_type not in ALLOWED_CALLER_TYPES[command_type]:
            raise ValueError("caller type is not authoritative for Phase 5C command")

    @staticmethod
    def require_human(context, role):
        if (
            context.caller_type != "HUMAN"
            or not context.human_principal_reference
            or not context.human_organization_reference
            or context.human_authority_role != role
        ):
            raise ValueError("trusted human authority is required")

    def _approval(self, *, approval_id, tenant_id, engagement_id, subject_type,
                  subject_id, subject_version, category, digest, role, context,
                  evidence_reference, command):
        self.require_human(context, role)
        if self.uow.human_approvals.find_active_phase5c_binding(
            tenant_id, subject_type, subject_id, subject_version, digest, role
        ):
            raise ValueError("duplicate active Phase 5C authority")
        record = {
            "approval_id": approval_id,
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "subject_version": subject_version,
            "approval_category": category,
            "authority_category": "CLIENT_AUTHORITY" if role == "CLIENT_DECISION_AUTHORITY" else "SEKINFRA_AUTHORITY",
            "actor_identity": context.human_principal_reference,
            "actor_organization": context.human_organization_reference,
            "actor_role": role,
            "decision": "APPROVE",
            "phase5c_authority": {"subject_id": subject_id, "authority_digest": digest},
            "conditions": [],
            "effective_at": command["now"],
            "evidence_reference": {key: evidence_reference[key] for key in ("reference_type", "reference_id")},
            "status": "ACTIVE",
            "correlation_id": command["correlation_id"],
            "idempotency_key": command["idempotency_key"],
            "created_at": command["now"],
        }
        self.uow.human_approvals.record_phase5c(record)
        return record

    def execute(self, command_type, prepared, context, now, command_id):
        self.require_caller(command_type, context)
        method = getattr(self, command_type)
        return method(prepared, context, now, command_id)

    def RecordOIAConversionDecision(self, p, context, now, command_id):
        payload = p.payload
        self.require_human(context, "CLIENT_DECISION_AUTHORITY")
        if not _active_engagement(self.uow, p.tenant_id, p.engagement_id):
            raise ValueError("active engagement is required")
        assessment = self.uow.oia_assessments.get(p.tenant_id, payload["oia_assessment_id"])
        delivery = self.uow.oia_findings_deliveries.get(p.tenant_id, payload["oia_findings_delivery_id"])
        if (
            not assessment or not delivery
            or assessment["engagement_id"] != p.engagement_id
            or delivery["oia_assessment_id"] != assessment["oia_assessment_id"]
            or assessment.get("state") not in {"FINDINGS_DELIVERED", "CLOSED"}
        ):
            raise ValueError("exact governed findings delivery is required")
        delivered = _findings(delivery["finding_revisions"])
        selected = _findings(payload["selected_finding_revisions"])
        if not selected <= delivered or (payload["decision"] == "PROCEED" and not selected):
            raise ValueError("selected Finding revision was not delivered")
        for finding_id, revision, digest in selected:
            finding = self.uow.oia_findings.get_revision(p.tenant_id, finding_id, revision)
            if not finding or finding.get("content_digest") != digest:
                raise ValueError("delivered Finding revision is not authoritative")
        if payload.get("supersedes_decision_reference"):
            previous = payload["supersedes_decision_reference"]
            prior = self.uow.oia_conversion_decisions.get_version(
                p.tenant_id, previous["reference_id"], previous["reference_version"]
            )
            if (
                not prior or prior.get("state") not in {"ACCEPTED", "DECLINED"}
                or prior["oia_conversion_decision_id"] != payload["oia_conversion_decision_id"]
                or payload["decision_version"] != prior["decision_version"] + 1
            ):
                raise ValueError("superseded conversion version is invalid")
        elif payload["decision_version"] != 1:
            raise ValueError("initial conversion version must be one")
        projection = {
            "tenant_id": p.tenant_id, "engagement_id": p.engagement_id,
            "oia_assessment_id": assessment["oia_assessment_id"],
            "oia_findings_delivery_id": delivery["oia_findings_delivery_id"],
            "delivery_sequence": delivery["delivery_sequence"],
            "delivery_manifest_digest": delivery["manifest_digest"],
            "decision": payload["decision"],
            "selected_finding_revisions": copy.deepcopy(payload["selected_finding_revisions"]),
        }
        digest = canonical_digest(projection)
        approval = self._approval(
            approval_id=command_id, tenant_id=p.tenant_id, engagement_id=p.engagement_id,
            subject_type="OIA_CONVERSION_DECISION", subject_id=payload["oia_conversion_decision_id"],
            subject_version=payload["decision_version"], category="CONVERSION", digest=digest,
            role="CLIENT_DECISION_AUTHORITY", context=context,
            evidence_reference=reference("OIA_FINDINGS_DELIVERY", delivery["oia_findings_delivery_id"], delivery["delivery_sequence"]),
            command={"now": now, "correlation_id": p.correlation_id, "idempotency_key": p.idempotency_key},
        )
        record = {
            "oia_conversion_decision_id": payload["oia_conversion_decision_id"],
            "decision_version": payload["decision_version"], **projection,
            "state": "PENDING_SEKINFRA" if payload["decision"] == "PROCEED" else "DECLINED",
            "conversion_authority_digest": digest,
            "client_approval_reference": reference("HUMAN_APPROVAL", approval["approval_id"], 1),
            "decided_at": now, "record_version": 1, "created_at": now, "updated_at": now,
        }
        if payload.get("supersedes_decision_reference"):
            record["supersedes_decision_reference"] = copy.deepcopy(payload["supersedes_decision_reference"])
        return self.uow.oia_conversion_decisions.create(record)

    def AcceptOIAConversion(self, p, context, now, command_id):
        payload = p.payload
        self.require_human(context, "SEKINFRA_ENGAGEMENT_AUTHORITY")
        current = self.uow.oia_conversion_decisions.get_version(
            p.tenant_id, payload["oia_conversion_decision_id"], payload["decision_version"]
        )
        if not current or current.get("state") != "PENDING_SEKINFRA" or current["record_version"] != p.expected_record_version:
            raise ValueError("conversion is not acceptable")
        client = self.uow.human_approvals.get(
            p.tenant_id, current["client_approval_reference"]["reference_id"]
        )
        if not self._approval_matches(client, current, "CLIENT_DECISION_AUTHORITY"):
            raise ValueError("active exact client conversion approval is required")
        approval = self._approval(
            approval_id=command_id, tenant_id=p.tenant_id, engagement_id=p.engagement_id,
            subject_type="OIA_CONVERSION_DECISION", subject_id=current["oia_conversion_decision_id"],
            subject_version=current["decision_version"], category="CONVERSION",
            digest=current["conversion_authority_digest"], role="SEKINFRA_ENGAGEMENT_AUTHORITY",
            context=context, evidence_reference=reference(
                "OIA_FINDINGS_DELIVERY", current["oia_findings_delivery_id"], current["delivery_sequence"]
            ), command={"now": now, "correlation_id": p.correlation_id, "idempotency_key": p.idempotency_key},
        )
        return self.uow.oia_conversion_decisions.accept(
            current, reference("HUMAN_APPROVAL", approval["approval_id"], 1), now
        )

    @staticmethod
    def _approval_matches(approval, subject, role):
        digest = subject.get("conversion_authority_digest") or subject.get("agreement_authority_digest") or subject.get("ongoing_access_authority_digest")
        identity = subject.get("oia_conversion_decision_id") or subject.get("ongoing_agreement_authority_id") or subject.get("ongoing_access_grant_id")
        version = subject.get("decision_version") or subject.get("agreement_version") or 1
        return bool(
            approval and approval.get("status") == "ACTIVE" and approval.get("decision") == "APPROVE"
            and approval.get("actor_role") == role and approval.get("subject_id") == identity
            and approval.get("subject_version") == version
            and approval.get("phase5c_authority", {}).get("authority_digest") == digest
        )

    def ProposeOngoingAgreement(self, p, context, now, command_id):
        payload = p.payload
        conversion = self.uow.oia_conversion_decisions.get_version(
            p.tenant_id, payload["oia_conversion_decision_id"], payload["decision_version"]
        )
        if not conversion or conversion.get("state") != "ACCEPTED" or conversion["engagement_id"] != p.engagement_id:
            raise ValueError("accepted exact conversion is required")
        selected = _findings(payload["service_scope"]["selected_finding_revisions"])
        if not selected or not selected <= _findings(conversion["selected_finding_revisions"]):
            raise ValueError("agreement scope is outside accepted delivered Findings")
        if payload.get("ends_at") and not payload["effective_at"] < payload["ends_at"]:
            raise ValueError("agreement term is invalid")
        if payload.get("supersedes_agreement_reference"):
            ref = payload["supersedes_agreement_reference"]
            previous = self.uow.ongoing_agreement_authorities.get_version(
                p.tenant_id, ref["reference_id"], ref["reference_version"]
            )
            if (
                not previous or previous["ongoing_agreement_authority_id"] != payload["ongoing_agreement_authority_id"]
                or previous.get("state") != "ACTIVE" or payload["agreement_version"] != previous["agreement_version"] + 1
            ):
                raise ValueError("agreement supersession binding is invalid")
        elif payload["agreement_version"] != 1:
            raise ValueError("initial agreement version must be one")
        scope = copy.deepcopy(payload["service_scope"])
        scope_digest = canonical_digest(scope)
        authority_digest = canonical_digest({
            "conversion": reference("OIA_CONVERSION_DECISION", conversion["oia_conversion_decision_id"], conversion["decision_version"]),
            "agreement_reference": payload["agreement_reference"], "service_scope_digest": scope_digest,
            "effective_at": payload["effective_at"], "ends_at": payload.get("ends_at"),
        })
        record = {
            "ongoing_agreement_authority_id": payload["ongoing_agreement_authority_id"],
            "agreement_version": payload["agreement_version"], "tenant_id": p.tenant_id,
            "engagement_id": p.engagement_id,
            "conversion_decision_reference": reference("OIA_CONVERSION_DECISION", conversion["oia_conversion_decision_id"], conversion["decision_version"]),
            "findings_delivery_reference": reference("OIA_FINDINGS_DELIVERY", conversion["oia_findings_delivery_id"], conversion["delivery_sequence"]),
            "agreement_reference": payload["agreement_reference"], "service_scope": scope,
            "service_scope_digest": scope_digest, "agreement_authority_digest": authority_digest,
            "state": "DRAFT", "effective_at": payload["effective_at"], "record_version": 1,
            "created_at": now, "updated_at": now,
        }
        if payload.get("ends_at"): record["ends_at"] = payload["ends_at"]
        if payload.get("supersedes_agreement_reference"):
            record["supersedes_agreement_reference"] = copy.deepcopy(payload["supersedes_agreement_reference"])
        return self.uow.ongoing_agreement_authorities.create(record)

    def RecordOngoingAgreementApproval(self, p, context, now, command_id):
        payload = p.payload
        current = self.uow.ongoing_agreement_authorities.get_version(
            p.tenant_id, payload["ongoing_agreement_authority_id"], payload["agreement_version"]
        )
        if not current or current.get("state") != "DRAFT" or current["record_version"] != p.expected_record_version:
            raise ValueError("draft exact agreement is required")
        approval = self._approval(
            approval_id=command_id, tenant_id=p.tenant_id, engagement_id=p.engagement_id,
            subject_type="ONGOING_AGREEMENT_AUTHORITY", subject_id=current["ongoing_agreement_authority_id"],
            subject_version=current["agreement_version"], category="ONGOING_AGREEMENT",
            digest=current["agreement_authority_digest"], role=payload["authority_role"], context=context,
            evidence_reference=copy.deepcopy(current["findings_delivery_reference"]),
            command={"now": now, "correlation_id": p.correlation_id, "idempotency_key": p.idempotency_key},
        )
        return {"record": current, "approval": approval}

    def ActivateOngoingAgreement(self, p, context, now, command_id):
        payload = p.payload
        current = self.uow.ongoing_agreement_authorities.get_version(
            p.tenant_id, payload["ongoing_agreement_authority_id"], payload["agreement_version"]
        )
        if (
            not current or current.get("state") != "DRAFT" or current["record_version"] != p.expected_record_version
            or now < current["effective_at"] or (current.get("ends_at") and now >= current["ends_at"])
        ):
            raise ValueError("agreement is not activatable")
        conversion_ref = current["conversion_decision_reference"]
        conversion = self.uow.oia_conversion_decisions.get_version(
            p.tenant_id, conversion_ref["reference_id"], conversion_ref["reference_version"]
        )
        if not conversion or conversion.get("state") != "ACCEPTED":
            raise ValueError("accepted conversion is required")
        approvals = []
        for role in ("CLIENT_DECISION_AUTHORITY", "SEKINFRA_ENGAGEMENT_AUTHORITY"):
            approval = self.uow.human_approvals.find_active_phase5c_binding(
                p.tenant_id, "ONGOING_AGREEMENT_AUTHORITY", current["ongoing_agreement_authority_id"],
                current["agreement_version"], current["agreement_authority_digest"], role,
            )
            if not self._approval_matches(approval, current, role):
                raise ValueError("dual exact agreement approvals are required")
            approvals.append(approval)
        return self.uow.ongoing_agreement_authorities.activate(
            current, reference("HUMAN_APPROVAL", approvals[0]["approval_id"], 1),
            reference("HUMAN_APPROVAL", approvals[1]["approval_id"], 1), now,
        )

    def TerminateOngoingAgreement(self, p, context, now, command_id):
        payload = p.payload
        role = context.human_authority_role
        if payload["termination_reason"] == "CLIENT_TERMINATION":
            self.require_human(context, "CLIENT_DECISION_AUTHORITY")
        elif payload["termination_reason"] in {"SEKINFRA_TERMINATION", "AUTHORITY_REVOKED"}:
            self.require_human(context, "SEKINFRA_ENGAGEMENT_AUTHORITY")
        elif role not in {"CLIENT_DECISION_AUTHORITY", "SEKINFRA_ENGAGEMENT_AUTHORITY"}:
            raise ValueError("bounded human termination authority is required")
        current = self.uow.ongoing_agreement_authorities.get_version(
            p.tenant_id, payload["ongoing_agreement_authority_id"], payload["agreement_version"]
        )
        if not current or current.get("state") != "ACTIVE" or current["record_version"] != p.expected_record_version:
            raise ValueError("active exact agreement is required")
        state = {
            "TERM_ENDED": "ENDED", "ENGAGEMENT_COMPLETED": "ENDED",
            "CLIENT_TERMINATION": "TERMINATED", "SEKINFRA_TERMINATION": "TERMINATED",
            "AUTHORITY_REVOKED": "REVOKED",
        }[payload["termination_reason"]]
        return self.uow.ongoing_agreement_authorities.terminate(
            current, state, payload["termination_reason"], now
        )

    def RecordOngoingPaymentVerification(self, p, context, now, command_id):
        payload = p.payload
        agreement = self.uow.ongoing_agreement_authorities.get_version(
            p.tenant_id, payload["ongoing_agreement_authority_id"], payload["agreement_version"]
        )
        if not agreement or agreement.get("state") != "ACTIVE" or agreement["engagement_id"] != p.engagement_id:
            raise ValueError("active exact Agreement #2 is required")
        if not payload["coverage_from"] < payload["coverage_until"] or now >= payload["coverage_until"]:
            raise ValueError("bounded current commercial coverage is required")
        record = {
            "ongoing_payment_verification_id": payload["ongoing_payment_verification_id"],
            "tenant_id": p.tenant_id, "engagement_id": p.engagement_id,
            "ongoing_agreement_reference": reference("ONGOING_AGREEMENT_AUTHORITY", agreement["ongoing_agreement_authority_id"], agreement["agreement_version"]),
            "verification_basis": payload["verification_basis"], "coverage_from": payload["coverage_from"],
            "coverage_until": payload["coverage_until"], "verification_reference": payload["verification_reference"],
            "status": "VERIFIED", "verified_at": now, "verified_by": context.principal_id,
            "record_version": 1,
        }
        for name in ("amount_minor", "currency"):
            if name in payload: record[name] = payload[name]
        return self.uow.ongoing_payment_verifications.create(record)

    def InvalidateOngoingPaymentVerification(self, p, context, now, command_id):
        current = self.uow.ongoing_payment_verifications.get(p.tenant_id, p.payload["ongoing_payment_verification_id"])
        if not current or current.get("status") != "VERIFIED" or current["record_version"] != p.expected_record_version:
            raise ValueError("verified exact commercial record is required")
        return self.uow.ongoing_payment_verifications.invalidate(
            current, p.payload["invalidation_reason"], now
        )

    def ProposeOngoingAccessGrant(self, p, context, now, command_id):
        payload = p.payload
        if self.uow.assessment_access_grants.get(p.tenant_id, payload["ongoing_access_grant_id"]):
            raise ValueError("AssessmentAccessGrant identity cannot be reused")
        agreement = self.uow.ongoing_agreement_authorities.get_version(
            p.tenant_id, payload["ongoing_agreement_authority_id"], payload["agreement_version"]
        )
        if not agreement:
            raise ValueError("agreement is required")
        cref = agreement["conversion_decision_reference"]
        conversion = self.uow.oia_conversion_decisions.get_version(
            p.tenant_id, cref["reference_id"], cref["reference_version"]
        )
        payment = self.uow.ongoing_payment_verifications.get(
            p.tenant_id, payload["ongoing_payment_verification_id"]
        )
        if not commercial_valid(self.uow, payment, agreement, conversion, now):
            raise ValueError("current bounded commercial authority is required")
        if not _same_reference(payment["ongoing_agreement_reference"], "ONGOING_AGREEMENT_AUTHORITY", agreement["ongoing_agreement_authority_id"], agreement["agreement_version"]):
            raise ValueError("commercial binding mismatch")
        agreement_targets = _targets(agreement["service_scope"]["target_system_references"])
        if not _targets(payload["target_resource_references"]) <= agreement_targets:
            raise ValueError("grant target is outside Agreement #2")
        if not (payload["effective_at"] <= payload["review_at"] < payload["expires_at"]):
            raise ValueError("grant time bounds are invalid")
        authority_projection = {
            "conversion": cref,
            "agreement": reference("ONGOING_AGREEMENT_AUTHORITY", agreement["ongoing_agreement_authority_id"], agreement["agreement_version"]),
            "payment": reference("ONGOING_PAYMENT_VERIFICATION", payment["ongoing_payment_verification_id"], payment["record_version"]),
            "service_scope_digest": agreement["service_scope_digest"],
            "targets": copy.deepcopy(payload["target_resource_references"]),
            "access_channel_reference": payload["access_channel_reference"],
            "effective_at": payload["effective_at"], "review_at": payload["review_at"], "expires_at": payload["expires_at"],
        }
        record = {
            "ongoing_access_grant_id": payload["ongoing_access_grant_id"], "tenant_id": p.tenant_id,
            "engagement_id": p.engagement_id, "conversion_decision_reference": copy.deepcopy(cref),
            "ongoing_agreement_reference": authority_projection["agreement"],
            "ongoing_payment_verification_reference": authority_projection["payment"],
            "service_scope_digest": agreement["service_scope_digest"],
            "ongoing_access_authority_digest": canonical_digest(authority_projection),
            "target_resource_references": copy.deepcopy(payload["target_resource_references"]),
            "access_channel_reference": payload["access_channel_reference"],
            "access_purpose": "ONGOING_SERVICE_CHANNEL", "state": "PROPOSED",
            "proposed_at": now, "effective_at": payload["effective_at"],
            "review_at": payload["review_at"], "expires_at": payload["expires_at"], "record_version": 1,
        }
        return self.uow.ongoing_access_grants.create(record)

    def RecordOngoingAccessApproval(self, p, context, now, command_id):
        grant = self.uow.ongoing_access_grants.get(p.tenant_id, p.payload["ongoing_access_grant_id"])
        if not grant or grant.get("state") != "PROPOSED" or grant["record_version"] != p.expected_record_version:
            raise ValueError("proposed exact ongoing grant is required")
        approval = self._approval(
            approval_id=command_id, tenant_id=p.tenant_id, engagement_id=p.engagement_id,
            subject_type="ONGOING_ACCESS_GRANT", subject_id=grant["ongoing_access_grant_id"],
            subject_version=1, category="ONGOING_ACCESS", digest=grant["ongoing_access_authority_digest"],
            role=p.payload["authority_role"], context=context,
            evidence_reference=copy.deepcopy(grant["ongoing_agreement_reference"]),
            command={"now": now, "correlation_id": p.correlation_id, "idempotency_key": p.idempotency_key},
        )
        return {"record": grant, "approval": approval}

    def _grant_chain(self, grant, now):
        cref = grant["conversion_decision_reference"]
        conversion = self.uow.oia_conversion_decisions.get_version(
            grant["tenant_id"], cref["reference_id"], cref["reference_version"]
        )
        aref = grant["ongoing_agreement_reference"]
        agreement = self.uow.ongoing_agreement_authorities.get_version(
            grant["tenant_id"], aref["reference_id"], aref["reference_version"]
        )
        pref = grant["ongoing_payment_verification_reference"]
        payment = self.uow.ongoing_payment_verifications.get(grant["tenant_id"], pref["reference_id"])
        if (
            not _active_engagement(self.uow, grant["tenant_id"], grant["engagement_id"])
            or not commercial_valid(self.uow, payment, agreement, conversion, now)
            or payment["record_version"] != pref["reference_version"]
            or agreement["service_scope_digest"] != grant["service_scope_digest"]
            or not _targets(grant["target_resource_references"]) <= _targets(agreement["service_scope"]["target_system_references"])
            or self.uow.ongoing_offboardings.find_by_engagement(grant["tenant_id"], grant["engagement_id"])
            or not (grant["effective_at"] <= now < grant["expires_at"])
        ):
            raise ValueError("full ongoing authority chain is not currently valid")
        return conversion, agreement, payment

    def ApproveOngoingAccessGrant(self, p, context, now, command_id):
        grant = self.uow.ongoing_access_grants.get(p.tenant_id, p.payload["ongoing_access_grant_id"])
        if not grant or grant.get("state") != "PROPOSED" or grant["record_version"] != p.expected_record_version:
            raise ValueError("proposed exact ongoing grant is required")
        self._grant_chain(grant, now)
        approvals = []
        for role in ("CLIENT_DECISION_AUTHORITY", "SEKINFRA_ENGAGEMENT_AUTHORITY"):
            approval = self.uow.human_approvals.find_active_phase5c_binding(
                p.tenant_id, "ONGOING_ACCESS_GRANT", grant["ongoing_access_grant_id"], 1,
                grant["ongoing_access_authority_digest"], role,
            )
            if not self._approval_matches(approval, grant, role):
                raise ValueError("dual exact ongoing access approvals are required")
            approvals.append(approval)
        return self.uow.ongoing_access_grants.approve(
            grant, reference("HUMAN_APPROVAL", approvals[0]["approval_id"], 1),
            reference("HUMAN_APPROVAL", approvals[1]["approval_id"], 1), now,
        )

    def VerifyOngoingAccess(self, p, context, now, command_id):
        grant = self.uow.ongoing_access_grants.get(p.tenant_id, p.payload["ongoing_access_grant_id"])
        if not grant or grant.get("state") != "APPROVED" or grant["record_version"] != p.expected_record_version:
            raise ValueError("approved exact ongoing grant is required")
        self._grant_chain(grant, now)
        if not self.access_verifier.verify(copy.deepcopy(grant), context, now).get("verified"):
            raise ValueError("trusted technical verification failed")
        return self.uow.ongoing_access_grants.activate(grant, now)

    def RevokeOngoingAccess(self, p, context, now, command_id):
        if context.caller_type == "HUMAN" and context.human_authority_role not in {
            "CLIENT_DECISION_AUTHORITY", "SEKINFRA_ENGAGEMENT_AUTHORITY"
        }:
            raise ValueError("bounded human revocation authority is required")
        if context.caller_type == "SECURITY_AUTOMATION" and p.payload["revocation_reason"] != "EMERGENCY_SECURITY_REVOCATION":
            raise ValueError("security automation is emergency-only")
        grant = self.uow.ongoing_access_grants.get(p.tenant_id, p.payload["ongoing_access_grant_id"])
        if not grant or grant.get("state") not in {"APPROVED", "ACTIVE"} or grant["record_version"] != p.expected_record_version:
            raise ValueError("ongoing grant is not revocable")
        return self.uow.ongoing_access_grants.revoke(grant, p.payload["revocation_reason"], now)

    def CloseOngoingAccess(self, p, context, now, command_id):
        payload = p.payload
        grant = self.uow.ongoing_access_grants.get(p.tenant_id, payload["ongoing_access_grant_id"])
        if not grant or grant.get("state") not in {"APPROVED", "ACTIVE"} or grant["record_version"] != p.expected_record_version:
            raise ValueError("ongoing grant is not closable")
        source = payload["closure_source_reference"]
        valid = False
        if source["reference_type"] == "ONGOING_AGREEMENT_AUTHORITY":
            agreement = self.uow.ongoing_agreement_authorities.get_version(p.tenant_id, source["reference_id"], source["reference_version"])
            valid = bool(
                payload["closure_reason"] == "AGREEMENT_ENDED"
                and agreement and agreement.get("state") in {"ENDED", "TERMINATED", "REVOKED", "SUPERSEDED"}
            )
        elif source["reference_type"] == "ONGOING_PAYMENT_VERIFICATION":
            payment = self.uow.ongoing_payment_verifications.get(p.tenant_id, source["reference_id"])
            valid = bool(
                payload["closure_reason"] == "COMMERCIAL_AUTHORITY_INVALID"
                and payment and payment["record_version"] == source["reference_version"]
                and payment.get("status") == "INVALIDATED"
            )
        elif source["reference_type"] == "ONGOING_OFFBOARDING":
            offboarding = self.uow.ongoing_offboardings.get(p.tenant_id, source["reference_id"])
            valid = bool(
                payload["closure_reason"] in {"OFFBOARDING_COMPLETED", "ENGAGEMENT_COMPLETED"}
                and offboarding and offboarding["record_version"] == source["reference_version"]
                and (
                    payload["closure_reason"] != "OFFBOARDING_COMPLETED"
                    or offboarding.get("state") == "COMPLETED"
                )
                and (
                    payload["closure_reason"] != "ENGAGEMENT_COMPLETED"
                    or offboarding.get("reason") == "ENGAGEMENT_COMPLETED"
                )
            )
        if not valid:
            raise ValueError("authoritative closure source is invalid")
        return self.uow.ongoing_access_grants.close(grant, payload["closure_reason"], now)

    def InitiateOngoingOffboarding(self, p, context, now, command_id):
        payload = p.payload
        if payload["reason"] in {"CONVERSION_DECLINED", "CLIENT_TERMINATION"}:
            self.require_human(context, "CLIENT_DECISION_AUTHORITY")
        elif payload["reason"] == "SEKINFRA_TERMINATION":
            self.require_human(context, "SEKINFRA_ENGAGEMENT_AUTHORITY")
        elif context.human_authority_role not in {"CLIENT_DECISION_AUTHORITY", "SEKINFRA_ENGAGEMENT_AUTHORITY"}:
            raise ValueError("bounded offboarding authority is required")
        conversion = self.uow.oia_conversion_decisions.get_version(
            p.tenant_id, payload["oia_conversion_decision_id"], payload["decision_version"]
        )
        if not conversion or conversion["engagement_id"] != p.engagement_id:
            raise ValueError("exact conversion is required")
        if payload["reason"] == "CONVERSION_DECLINED" and conversion.get("state") != "DECLINED":
            raise ValueError("conversion is not declined")
        agreement = None
        if payload.get("ongoing_agreement_authority_id"):
            agreement = self.uow.ongoing_agreement_authorities.get_version(
                p.tenant_id, payload["ongoing_agreement_authority_id"], payload["agreement_version"]
            )
            if not agreement or agreement["engagement_id"] != p.engagement_id:
                raise ValueError("exact agreement is required")
        grants = []
        for grant_id in payload["ongoing_access_grant_ids"]:
            grant = self.uow.ongoing_access_grants.get(p.tenant_id, grant_id)
            if not grant or grant["engagement_id"] != p.engagement_id:
                raise ValueError("exact tenant ongoing grant is required")
            grants.append(grant)
        access_required = bool(grants)
        record = {
            "ongoing_offboarding_id": payload["ongoing_offboarding_id"], "tenant_id": p.tenant_id,
            "engagement_id": p.engagement_id,
            "conversion_decision_reference": reference("OIA_CONVERSION_DECISION", conversion["oia_conversion_decision_id"], conversion["decision_version"]),
            "reason": payload["reason"],
            "state": "ACCESS_REVOCATION_PENDING" if access_required else "INITIATED",
            "access_revocation_required": access_required,
            "ongoing_access_grant_references": [reference("ONGOING_ACCESS_GRANT", grant["ongoing_access_grant_id"], grant["record_version"]) for grant in grants],
            "revocation_verification_references": [], "initiated_at": now,
            "initiated_by": context.human_principal_reference, "record_version": 1,
        }
        if agreement:
            record["ongoing_agreement_reference"] = reference(
                "ONGOING_AGREEMENT_AUTHORITY", agreement["ongoing_agreement_authority_id"], agreement["agreement_version"]
            )
        return self.uow.ongoing_offboardings.create(record)

    def VerifyOngoingAccessRevocation(self, p, context, now, command_id):
        payload = p.payload
        grant = self.uow.ongoing_access_grants.get(p.tenant_id, payload["ongoing_access_grant_id"])
        if (
            not grant or grant.get("state") not in {"EXPIRED", "REVOKED", "CLOSED"}
            or grant["record_version"] != p.expected_record_version
        ):
            raise ValueError("terminal exact ongoing grant is required")
        offboarding = None
        if payload.get("ongoing_offboarding_id"):
            offboarding = self.uow.ongoing_offboardings.get(p.tenant_id, payload["ongoing_offboarding_id"])
            if (
                not offboarding or offboarding.get("state") not in {"INITIATED", "ACCESS_REVOCATION_PENDING"}
                or grant["ongoing_access_grant_id"] not in {
                    item["reference_id"] for item in offboarding["ongoing_access_grant_references"]
                }
            ):
                raise ValueError("offboarding revocation request is required")
        result = self.revocation_verifier.verify(copy.deepcopy(grant), copy.deepcopy(offboarding), context, now)
        if result.get("verification_result") not in {"ACCESS_REMOVAL_VERIFIED", "ACCESS_ALREADY_ABSENT"}:
            raise ValueError("trusted external revocation verification failed")
        record = {
            "ongoing_access_revocation_verification_id": payload["ongoing_access_revocation_verification_id"],
            "tenant_id": p.tenant_id, "engagement_id": p.engagement_id,
            "ongoing_access_grant_reference": reference("ONGOING_ACCESS_GRANT", grant["ongoing_access_grant_id"], grant["record_version"]),
            "verification_result": result["verification_result"],
            "verification_reference": result.get("verification_reference", "trusted.revocation-verification"),
            "verified_at": now, "verified_by": context.principal_id, "record_version": 1,
        }
        if offboarding:
            record["offboarding_reference"] = reference(
                "ONGOING_OFFBOARDING", offboarding["ongoing_offboarding_id"], offboarding["record_version"]
            )
        return self.uow.ongoing_access_revocation_verifications.create(record)

    def CompleteOngoingOffboarding(self, p, context, now, command_id):
        offboarding = self.uow.ongoing_offboardings.get(p.tenant_id, p.payload["ongoing_offboarding_id"])
        if (
            not offboarding or offboarding.get("state") not in {"INITIATED", "ACCESS_REVOCATION_PENDING"}
            or offboarding["record_version"] != p.expected_record_version
        ):
            raise ValueError("active exact offboarding is required")
        if context.caller_type == "HUMAN" and context.human_authority_role not in {
            "CLIENT_DECISION_AUTHORITY", "SEKINFRA_ENGAGEMENT_AUTHORITY"
        }:
            raise ValueError("bounded completion authority is required")
        verifications = []
        for grant_ref in offboarding["ongoing_access_grant_references"]:
            matches = self.uow.ongoing_access_revocation_verifications.list_by_grant(
                p.tenant_id, grant_ref["reference_id"], offboarding["ongoing_offboarding_id"]
            )
            if not matches:
                raise ValueError("every requested external revocation must be verified")
            verifications.append(matches[-1])
        return self.uow.ongoing_offboardings.complete(
            offboarding,
            [reference("ONGOING_ACCESS_REVOCATION_VERIFICATION", value["ongoing_access_revocation_verification_id"], 1) for value in verifications],
            now, context.human_principal_reference or context.principal_id,
        )


class Phase5CReadService:
    """Tenant-bounded, derived and explicitly non-authoritative Phase 5C reads."""
    def __init__(self, uow):
        self.uow = uow

    def conversion_status(self, tenant_id, decision_id, decision_version, generated_at):
        record = self.uow.oia_conversion_decisions.get_version(tenant_id, decision_id, decision_version)
        if not record: return None
        return {key: record[key] for key in (
            "tenant_id", "engagement_id", "oia_conversion_decision_id", "decision_version",
            "oia_assessment_id", "oia_findings_delivery_id", "decision", "state",
        )} | {"generated_at": generated_at}

    def agreement_authority(self, tenant_id, agreement_id, version, generated_at):
        record = self.uow.ongoing_agreement_authorities.get_version(tenant_id, agreement_id, version)
        if not record: return None
        result = {key: record[key] for key in (
            "tenant_id", "engagement_id", "ongoing_agreement_authority_id", "agreement_version", "state"
        )}
        result["currently_authoritative"] = record["state"] == "ACTIVE" and record["effective_at"] <= generated_at and (not record.get("ends_at") or generated_at < record["ends_at"])
        for key in ("effective_at", "ends_at", "terminal_reason"):
            if key in record: result[key] = record[key]
        result["generated_at"] = generated_at
        return result

    def commercial_authority(self, tenant_id, payment_id, generated_at):
        payment = self.uow.ongoing_payment_verifications.get(tenant_id, payment_id)
        if not payment: return None
        aref = payment["ongoing_agreement_reference"]
        agreement = self.uow.ongoing_agreement_authorities.get_version(tenant_id, aref["reference_id"], aref["reference_version"])
        conversion = None
        if agreement:
            cref = agreement["conversion_decision_reference"]
            conversion = self.uow.oia_conversion_decisions.get_version(tenant_id, cref["reference_id"], cref["reference_version"])
        reasons = []
        if not agreement_valid(self.uow, agreement, conversion, generated_at): reasons.append("AGREEMENT_INVALID")
        if payment["status"] == "INVALIDATED": reasons.append("VERIFICATION_INVALIDATED")
        if generated_at < payment["coverage_from"]: reasons.append("COVERAGE_NOT_STARTED")
        if generated_at >= payment["coverage_until"]: reasons.append("COVERAGE_ENDED")
        if not agreement or not _same_reference(payment["ongoing_agreement_reference"], "ONGOING_AGREEMENT_AUTHORITY", agreement["ongoing_agreement_authority_id"], agreement["agreement_version"]): reasons.append("BINDING_MISMATCH")
        return {
            "tenant_id": tenant_id, "engagement_id": payment["engagement_id"],
            "ongoing_payment_verification_id": payment_id, "status": payment["status"],
            "coverage_from": payment["coverage_from"], "coverage_until": payment["coverage_until"],
            "commercially_valid": not reasons, "reasons": reasons, "generated_at": generated_at,
        }

    def access_status(self, tenant_id, grant_id, generated_at, target_reference=None):
        grant = self.uow.ongoing_access_grants.get(tenant_id, grant_id)
        if not grant: return None
        derived = ongoing_access_usability(self.uow, tenant_id, grant_id, generated_at, target_reference)
        return {
            "tenant_id": tenant_id, "engagement_id": grant["engagement_id"],
            "ongoing_access_grant_id": grant_id, "state": grant["state"],
            **derived, "implementation_authorized": False, "generated_at": generated_at,
        }

    def offboarding_status(self, tenant_id, offboarding_id, generated_at):
        record = self.uow.ongoing_offboardings.get(tenant_id, offboarding_id)
        if not record: return None
        required = {
            value["reference_id"] for value in record["ongoing_access_grant_references"]
        }
        verified = {
            value["ongoing_access_grant_reference"]["reference_id"]
            for value in self.uow.ongoing_access_revocation_verifications.list_by_offboarding(tenant_id, offboarding_id)
        }
        return {
            "tenant_id": tenant_id, "engagement_id": record["engagement_id"],
            "ongoing_offboarding_id": offboarding_id, "state": record["state"], "reason": record["reason"],
            "access_revocation_required": record["access_revocation_required"],
            "access_revocation_verified": not record["access_revocation_required"] or required <= verified,
            "generated_at": generated_at,
        }

    def eligibility(self, tenant_id, engagement_id, generated_at):
        reasons = []
        if not _active_engagement(self.uow, tenant_id, engagement_id): reasons.append("ENGAGEMENT_INACTIVE")
        conversion = self.uow.oia_conversion_decisions.find_current_by_engagement(tenant_id, engagement_id)
        if not conversion: reasons.append("CONVERSION_MISSING")
        elif conversion.get("state") != "ACCEPTED": reasons.append("CONVERSION_NOT_ACCEPTED")
        agreement = self.uow.ongoing_agreement_authorities.find_current_by_engagement(tenant_id, engagement_id)
        if not agreement: reasons.append("AGREEMENT_MISSING")
        elif not agreement_valid(self.uow, agreement, conversion, generated_at): reasons.append("AGREEMENT_INVALID")
        payment = self.uow.ongoing_payment_verifications.find_current_by_engagement(tenant_id, engagement_id)
        if not payment: reasons.append("PAYMENT_MISSING")
        elif not commercial_valid(self.uow, payment, agreement, conversion, generated_at): reasons.append("PAYMENT_INVALID")
        grant = self.uow.ongoing_access_grants.find_current_by_engagement(tenant_id, engagement_id)
        if not grant: reasons.append("ONGOING_ACCESS_MISSING")
        elif not ongoing_access_usability(self.uow, tenant_id, grant["ongoing_access_grant_id"], generated_at)["usable"]: reasons.append("ONGOING_ACCESS_UNUSABLE")
        if self.uow.ongoing_offboardings.find_by_engagement(tenant_id, engagement_id): reasons.append("OFFBOARDING_ACTIVE")
        return {
            "tenant_id": tenant_id, "engagement_id": engagement_id,
            "eligible_for_ongoing_work": not reasons, "reasons": list(dict.fromkeys(reasons)),
            "implementation_authorized": False, "generated_at": generated_at,
        }

    def progression(self, tenant_id, engagement_id, generated_at):
        conversion = self.uow.oia_conversion_decisions.find_current_by_engagement(tenant_id, engagement_id)
        agreement = self.uow.ongoing_agreement_authorities.find_current_by_engagement(tenant_id, engagement_id)
        payment = self.uow.ongoing_payment_verifications.find_current_by_engagement(tenant_id, engagement_id)
        grant = self.uow.ongoing_access_grants.find_current_by_engagement(tenant_id, engagement_id)
        return {
            "tenant_id": tenant_id, "engagement_id": engagement_id,
            "conversion_accepted": bool(conversion and conversion.get("state") == "ACCEPTED"),
            "ongoing_agreement_active": agreement_valid(self.uow, agreement, conversion, generated_at),
            "ongoing_commercial_valid": commercial_valid(self.uow, payment, agreement, conversion, generated_at),
            "ongoing_access_usable": bool(grant and ongoing_access_usability(self.uow, tenant_id, grant["ongoing_access_grant_id"], generated_at)["usable"]),
            "implementation_authorized": False, "deployment_authorized": False,
            "managed_operations_authorized": False, "generated_at": generated_at,
        }
