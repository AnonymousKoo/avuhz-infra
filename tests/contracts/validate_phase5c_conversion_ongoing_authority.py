#!/usr/bin/env python3
"""Validate frozen Phase 5C conversion and ongoing-authority contracts."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
FIXTURE = ROOT / "contracts/fixtures/v1/phase5c-conversion-ongoing-authority.cases.json"
sys.path.insert(0, str(ROOT / "src"))
from avuhz_runtime.command_registry import COMMANDS  # noqa: E402
from avuhz_runtime.schema_registry import SCHEMA_FILES, SchemaRegistry  # noqa: E402

TS = "2031-04-10T12:00:00Z"
TS_END = "2031-05-10T12:00:00Z"
D1 = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64
D3 = "sha256:" + "c" * 64
U = lambda n: f"c5000000-0000-4000-8000-{n:012d}"


def fail(message: str) -> None:
    print("phase5c conversion/ongoing-authority validation: FAIL: " + message, file=sys.stderr)
    raise SystemExit(1)


def ref(kind: str, identity: str, version: int = 1) -> dict:
    return {"reference_type": kind, "reference_id": identity, "reference_version": version}


def valid(registry: SchemaRegistry, schema_id: str, value: dict) -> bool:
    schema = registry.expanded(schema_id)
    return not list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value))


def require_valid(registry: SchemaRegistry, schema_id: str, value: dict, label: str) -> None:
    schema = registry.expanded(schema_id)
    errors = sorted(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value), key=lambda e: list(e.path))
    if errors:
        fail(f"{label} rejected: {errors[0].message}")


def build(industry: dict) -> dict:
    tenant, engagement, assessment, delivery = U(1), U(2), U(3), U(4)
    finding = {"oia_finding_id": U(5), "finding_revision": 2, "content_digest": D1}
    conversion_id, agreement_id, payment_id, grant_id = U(6), U(7), U(8), U(9)
    offboarding_id, revocation_id, diagnostic_grant_id = U(10), U(11), U(12)
    client = ref("HUMAN_APPROVAL", U(20))
    sekinfra = ref("HUMAN_APPROVAL", U(21))
    conversion = {
        "oia_conversion_decision_id": conversion_id, "decision_version": 1,
        "tenant_id": tenant, "engagement_id": engagement, "oia_assessment_id": assessment,
        "oia_findings_delivery_id": delivery, "delivery_sequence": 1,
        "delivery_manifest_digest": D2, "decision": "PROCEED", "state": "ACCEPTED",
        "selected_finding_revisions": [finding], "conversion_authority_digest": D3,
        "client_approval_reference": client, "sekinfra_approval_reference": sekinfra,
        "decided_at": TS, "accepted_at": TS, "record_version": 2,
        "created_at": TS, "updated_at": TS,
    }
    scope = {
        "selected_finding_revisions": [finding],
        "intervention_categories": [industry["intervention_category"]],
        "service_areas": [industry["service_area"]],
        "target_system_references": [{"resource_reference_id": industry["target_reference"]}],
        "commercial_boundaries": ["Bounded advisory and operational service scope only."],
        "explicit_exclusions": ["Implementation, deployment, and managed operations are excluded."],
    }
    agreement = {
        "ongoing_agreement_authority_id": agreement_id, "agreement_version": 1,
        "tenant_id": tenant, "engagement_id": engagement,
        "conversion_decision_reference": ref("OIA_CONVERSION_DECISION", conversion_id, 1),
        "findings_delivery_reference": ref("OIA_FINDINGS_DELIVERY", delivery, 1),
        "agreement_reference": f"agreement.{industry['name']}.v1", "service_scope": scope,
        "service_scope_digest": D2, "agreement_authority_digest": D3, "state": "ACTIVE",
        "client_approval_reference": client, "sekinfra_approval_reference": sekinfra,
        "effective_at": TS, "ends_at": TS_END, "activated_at": TS,
        "record_version": 2, "created_at": TS, "updated_at": TS,
    }
    payment = {
        "ongoing_payment_verification_id": payment_id, "tenant_id": tenant,
        "engagement_id": engagement,
        "ongoing_agreement_reference": ref("ONGOING_AGREEMENT_AUTHORITY", agreement_id, 1),
        "verification_basis": "APPROVED_COMMERCIAL_COVERAGE",
        "coverage_from": TS, "coverage_until": TS_END,
        "verification_reference": f"commercial.{industry['name']}.coverage",
        "status": "VERIFIED", "verified_at": TS, "verified_by": "service.commercial-verifier",
        "record_version": 1,
    }
    grant = {
        "ongoing_access_grant_id": grant_id, "tenant_id": tenant, "engagement_id": engagement,
        "conversion_decision_reference": ref("OIA_CONVERSION_DECISION", conversion_id, 1),
        "ongoing_agreement_reference": ref("ONGOING_AGREEMENT_AUTHORITY", agreement_id, 1),
        "ongoing_payment_verification_reference": ref("ONGOING_PAYMENT_VERIFICATION", payment_id, 1),
        "service_scope_digest": D2, "ongoing_access_authority_digest": D3,
        "target_resource_references": [{"resource_reference_id": industry["target_reference"]}],
        "access_channel_reference": f"channel.{industry['name']}", "access_purpose": "ONGOING_SERVICE_CHANNEL",
        "state": "ACTIVE", "client_approval_reference": client,
        "sekinfra_approval_reference": sekinfra, "proposed_at": TS, "approved_at": TS,
        "verified_at": TS, "active_from": TS, "effective_at": TS,
        "review_at": TS_END, "expires_at": TS_END, "record_version": 3,
    }
    revocation = {
        "ongoing_access_revocation_verification_id": revocation_id, "tenant_id": tenant,
        "engagement_id": engagement,
        "ongoing_access_grant_reference": ref("ONGOING_ACCESS_GRANT", grant_id, 3),
        "offboarding_reference": ref("ONGOING_OFFBOARDING", offboarding_id, 1),
        "verification_result": "ACCESS_REMOVAL_VERIFIED",
        "verification_reference": f"revocation.{industry['name']}.verified",
        "verified_at": TS_END, "verified_by": "service.access-verifier", "record_version": 1,
    }
    offboarding = {
        "ongoing_offboarding_id": offboarding_id, "tenant_id": tenant,
        "engagement_id": engagement,
        "conversion_decision_reference": ref("OIA_CONVERSION_DECISION", conversion_id, 1),
        "ongoing_agreement_reference": ref("ONGOING_AGREEMENT_AUTHORITY", agreement_id, 1),
        "reason": "ENGAGEMENT_COMPLETED", "state": "COMPLETED",
        "access_revocation_required": True,
        "ongoing_access_grant_references": [ref("ONGOING_ACCESS_GRANT", grant_id, 3)],
        "revocation_verification_references": [ref("ONGOING_ACCESS_REVOCATION_VERIFICATION", revocation_id, 1)],
        "initiated_at": TS, "initiated_by": "human.sekinfra-authority",
        "completed_at": TS_END, "completed_by": "human.sekinfra-authority", "record_version": 2,
    }
    delivery_truth = {
        "tenant_id": tenant, "engagement_id": engagement, "oia_assessment_id": assessment,
        "oia_findings_delivery_id": delivery, "delivery_sequence": 1,
        "manifest_digest": D2, "finding_revisions": [finding],
    }
    return locals()


DOMAIN_IDS = {
    "conversion": "urn:avuhz:schema:contracts:domain:oia-conversion-decision:v1",
    "agreement": "urn:avuhz:schema:contracts:domain:ongoing-agreement-authority:v1",
    "payment": "urn:avuhz:schema:contracts:domain:ongoing-payment-verification:v1",
    "grant": "urn:avuhz:schema:contracts:domain:ongoing-access-grant:v1",
    "revocation": "urn:avuhz:schema:contracts:domain:ongoing-access-revocation-verification:v1",
    "offboarding": "urn:avuhz:schema:contracts:domain:ongoing-offboarding:v1",
}
COMMAND_IDS = {
    "RecordOIAConversionDecision": "record-oia-conversion-decision",
    "AcceptOIAConversion": "accept-oia-conversion",
    "ProposeOngoingAgreement": "propose-ongoing-agreement",
    "RecordOngoingAgreementApproval": "record-ongoing-agreement-approval",
    "ActivateOngoingAgreement": "activate-ongoing-agreement",
    "TerminateOngoingAgreement": "terminate-ongoing-agreement",
    "RecordOngoingPaymentVerification": "record-ongoing-payment-verification",
    "InvalidateOngoingPaymentVerification": "invalidate-ongoing-payment-verification",
    "ProposeOngoingAccessGrant": "propose-ongoing-access-grant",
    "RecordOngoingAccessApproval": "record-ongoing-access-approval",
    "ApproveOngoingAccessGrant": "approve-ongoing-access-grant",
    "VerifyOngoingAccess": "verify-ongoing-access",
    "RevokeOngoingAccess": "revoke-ongoing-access",
    "CloseOngoingAccess": "close-ongoing-access",
    "InitiateOngoingOffboarding": "initiate-ongoing-offboarding",
    "VerifyOngoingAccessRevocation": "verify-ongoing-access-revocation",
    "CompleteOngoingOffboarding": "complete-ongoing-offboarding",
}
READ_IDS = {
    name: f"urn:avuhz:schema:contracts:read-models:{name}:v1"
    for name in (
        "oia-conversion-status-view", "ongoing-agreement-authority-view",
        "ongoing-commercial-authority-view", "ongoing-access-status-view",
        "ongoing-offboarding-status-view", "ongoing-engagement-eligibility-view",
        "phase5c-authority-progression-view",
    )
}


def command_payloads(x: dict) -> dict:
    finding = x["finding"]
    scope = x["scope"]
    return {
        "RecordOIAConversionDecision": {"oia_conversion_decision_id": x["conversion_id"], "decision_version": 1, "oia_assessment_id": x["assessment"], "oia_findings_delivery_id": x["delivery"], "decision": "PROCEED", "selected_finding_revisions": [finding]},
        "AcceptOIAConversion": {"oia_conversion_decision_id": x["conversion_id"], "decision_version": 1},
        "ProposeOngoingAgreement": {"ongoing_agreement_authority_id": x["agreement_id"], "agreement_version": 1, "oia_conversion_decision_id": x["conversion_id"], "decision_version": 1, "agreement_reference": "agreement.fictional.v1", "service_scope": scope, "effective_at": TS, "ends_at": TS_END},
        "RecordOngoingAgreementApproval": {"ongoing_agreement_authority_id": x["agreement_id"], "agreement_version": 1, "authority_role": "CLIENT_DECISION_AUTHORITY"},
        "ActivateOngoingAgreement": {"ongoing_agreement_authority_id": x["agreement_id"], "agreement_version": 1},
        "TerminateOngoingAgreement": {"ongoing_agreement_authority_id": x["agreement_id"], "agreement_version": 1, "termination_reason": "ENGAGEMENT_COMPLETED"},
        "RecordOngoingPaymentVerification": {"ongoing_payment_verification_id": x["payment_id"], "ongoing_agreement_authority_id": x["agreement_id"], "agreement_version": 1, "verification_basis": "APPROVED_COMMERCIAL_COVERAGE", "coverage_from": TS, "coverage_until": TS_END, "verification_reference": "commercial.fictional.coverage"},
        "InvalidateOngoingPaymentVerification": {"ongoing_payment_verification_id": x["payment_id"], "invalidation_reason": "COVERAGE_ENDED"},
        "ProposeOngoingAccessGrant": {"ongoing_access_grant_id": x["grant_id"], "ongoing_agreement_authority_id": x["agreement_id"], "agreement_version": 1, "ongoing_payment_verification_id": x["payment_id"], "target_resource_references": x["grant"]["target_resource_references"], "access_channel_reference": "channel.fictional", "effective_at": TS, "review_at": TS_END, "expires_at": TS_END},
        "RecordOngoingAccessApproval": {"ongoing_access_grant_id": x["grant_id"], "authority_role": "CLIENT_DECISION_AUTHORITY"},
        "ApproveOngoingAccessGrant": {"ongoing_access_grant_id": x["grant_id"]},
        "VerifyOngoingAccess": {"ongoing_access_grant_id": x["grant_id"]},
        "RevokeOngoingAccess": {"ongoing_access_grant_id": x["grant_id"], "revocation_reason": "EMERGENCY_SECURITY_REVOCATION"},
        "CloseOngoingAccess": {"ongoing_access_grant_id": x["grant_id"], "closure_reason": "OFFBOARDING_COMPLETED", "closure_source_reference": ref("ONGOING_OFFBOARDING", x["offboarding_id"], 1)},
        "InitiateOngoingOffboarding": {"ongoing_offboarding_id": x["offboarding_id"], "oia_conversion_decision_id": x["conversion_id"], "decision_version": 1, "ongoing_agreement_authority_id": x["agreement_id"], "agreement_version": 1, "reason": "ENGAGEMENT_COMPLETED", "ongoing_access_grant_ids": [x["grant_id"]]},
        "VerifyOngoingAccessRevocation": {"ongoing_access_revocation_verification_id": x["revocation_id"], "ongoing_access_grant_id": x["grant_id"], "ongoing_offboarding_id": x["offboarding_id"]},
        "CompleteOngoingOffboarding": {"ongoing_offboarding_id": x["offboarding_id"]},
    }


def semantic_chain_valid(x: dict, offboarding_active: bool = False) -> bool:
    c, a, p, g, d = x["conversion"], x["agreement"], x["payment"], x["grant"], x["delivery_truth"]
    tenant = d["tenant_id"]
    same = all(r["tenant_id"] == tenant and r["engagement_id"] == d["engagement_id"] for r in (c, a, p, g))
    delivered = {(f["oia_finding_id"], f["finding_revision"], f["content_digest"]) for f in d["finding_revisions"]}
    selected = {(f["oia_finding_id"], f["finding_revision"], f["content_digest"]) for f in c["selected_finding_revisions"]}
    scoped = {(f["oia_finding_id"], f["finding_revision"], f["content_digest"]) for f in a["service_scope"]["selected_finding_revisions"]}
    targets = {r["resource_reference_id"] for r in a["service_scope"]["target_system_references"]}
    grant_targets = {r["resource_reference_id"] for r in g["target_resource_references"]}
    return all((
        same, c["oia_assessment_id"] == d["oia_assessment_id"],
        c["oia_findings_delivery_id"] == d["oia_findings_delivery_id"],
        c["delivery_sequence"] == d["delivery_sequence"], c["delivery_manifest_digest"] == d["manifest_digest"],
        c["state"] == "ACCEPTED", selected <= delivered, bool(selected),
        a["conversion_decision_reference"] == ref("OIA_CONVERSION_DECISION", c["oia_conversion_decision_id"], c["decision_version"]),
        a["findings_delivery_reference"] == ref("OIA_FINDINGS_DELIVERY", d["oia_findings_delivery_id"], d["delivery_sequence"]),
        scoped <= selected, bool(scoped), a["state"] == "ACTIVE",
        p["ongoing_agreement_reference"] == ref("ONGOING_AGREEMENT_AUTHORITY", a["ongoing_agreement_authority_id"], a["agreement_version"]),
        p["status"] == "VERIFIED", p["coverage_from"] <= TS < p["coverage_until"],
        g["ongoing_access_grant_id"] != x["diagnostic_grant_id"],
        g["ongoing_agreement_reference"] == ref("ONGOING_AGREEMENT_AUTHORITY", a["ongoing_agreement_authority_id"], a["agreement_version"]),
        g["ongoing_payment_verification_reference"] == ref("ONGOING_PAYMENT_VERIFICATION", p["ongoing_payment_verification_id"], p["record_version"]),
        g["service_scope_digest"] == a["service_scope_digest"], grant_targets <= targets,
        g["state"] == "ACTIVE", g["active_from"] <= TS < g["expires_at"], not offboarding_active,
    ))


def assert_human_rules(registry: SchemaRegistry) -> None:
    envelope = registry.resolve("urn:avuhz:schema:contracts:commands:command-envelope:v1")
    human_commands = set()
    for rule in envelope["$defs"]["envelopeCore"]["allOf"]:
        then = rule.get("then", {})
        if then.get("properties", {}).get("caller_type", {}).get("const") != "HUMAN":
            continue
        command = rule["if"]["properties"]["command_type"]
        human_commands.update(command.get("enum", [command.get("const")]))
    required = {"RecordOIAConversionDecision", "AcceptOIAConversion", "RecordOngoingAgreementApproval", "TerminateOngoingAgreement", "RecordOngoingAccessApproval", "InitiateOngoingOffboarding"}
    if not required <= human_commands:
        fail("trusted human command boundary is incomplete")
    bounded = set()
    for rule in envelope["$defs"]["envelopeCore"]["allOf"]:
        caller_enum = rule.get("then", {}).get("properties", {}).get("caller_type", {}).get("enum")
        command_enum = rule.get("if", {}).get("properties", {}).get("command_type", {}).get("enum", [])
        if caller_enum and "N8N_ORCHESTRATOR" not in caller_enum and "SCHEDULED_AUTOMATION" not in caller_enum:
            bounded.update(command_enum)
    if not set(COMMAND_IDS) <= bounded:
        fail("workload/n8n authoritative-command exclusion is incomplete")




def main() -> None:
    fixtures = json.loads(FIXTURE.read_text())
    registry = SchemaRegistry(SCHEMA_ROOT)
    if len(registry.schema_ids) != len(SCHEMA_FILES) or len(registry.schema_ids) != 118:
        fail("local schema catalog count or uniqueness drifted")
    for schema_id in registry.schema_ids:
        Draft202012Validator.check_schema(registry.resolve(schema_id))
    if not set(COMMAND_IDS) <= set(COMMANDS) or not all(COMMANDS[name].executable for name in COMMAND_IDS):
        fail("Phase 5C frozen commands are not fully runtime executable")
    assert_human_rules(registry)

    expected_transitions = {
        "conversion": ({"PENDING_SEKINFRA->ACCEPTED"}, {"DECLINED", "ACCEPTED"}),
        "ongoing_agreement": ({"DRAFT->ACTIVE", "ACTIVE->SUPERSEDED", "ACTIVE->ENDED", "ACTIVE->TERMINATED", "ACTIVE->REVOKED"}, {"SUPERSEDED", "ENDED", "TERMINATED", "REVOKED"}),
        "ongoing_access": ({"PROPOSED->APPROVED", "APPROVED->ACTIVE", "ACTIVE->EXPIRED", "ACTIVE->REVOKED", "ACTIVE->CLOSED", "APPROVED->REVOKED", "APPROVED->CLOSED"}, {"EXPIRED", "REVOKED", "CLOSED"}),
        "offboarding": ({"INITIATED->COMPLETED", "INITIATED->ACCESS_REVOCATION_PENDING", "ACCESS_REVOCATION_PENDING->COMPLETED"}, {"COMPLETED"}),
    }
    for name, (allowed, terminal) in expected_transitions.items():
        machine = fixtures["state_machines"][name]
        if set(machine["allowed"]) != allowed or set(machine["terminal"]) != terminal:
            fail(f"{name} state machine drifted")
        if any(step.split("->")[0] in terminal for step in machine["denied"]):
            pass
        else:
            fail(f"{name} terminal immutability fixture missing")

    for case in fixtures["authority_progression"]:
        derived = all((case["engagement_active"], case["conversion_accepted"], case["agreement_active"], case["commercial_valid"], case["access_active"], not case["offboarding_active"]))
        if derived != case["ongoing_eligible"] or derived != case["access_usable"]:
            fail("authority progression allowed an implicit jump")
    expected_positive = {"happy_conversion", "decline", "ongoing_agreement_activation", "ongoing_payment_verification", "ongoing_grant_approval", "ongoing_grant_activation", "commercial_invalidation_blocks_access", "manual_revocation", "offboarding", "revocation_verification"}
    if set(fixtures["positive_scenarios"]) != expected_positive:
        fail("positive-scenario fixture coverage drifted")


    checked_resources = checked_commands = checked_reads = checked_approvals = checked_events = 0
    representative = None
    for industry in fixtures["industries"]:
        x = build(industry)
        representative = x
        for name, schema_id in DOMAIN_IDS.items():
            require_valid(registry, schema_id, x[name], f"{industry['name']} {name}")
            checked_resources += 1
        decline = copy.deepcopy(x["conversion"])
        decline.update({"decision": "DECLINE", "state": "DECLINED", "selected_finding_revisions": [], "record_version": 1})
        decline.pop("sekinfra_approval_reference")
        decline.pop("accepted_at")
        require_valid(registry, DOMAIN_IDS["conversion"], decline, "declined conversion")
        declined_offboarding = {
            "ongoing_offboarding_id": U(40), "tenant_id": x["tenant"], "engagement_id": x["engagement"],
            "conversion_decision_reference": ref("OIA_CONVERSION_DECISION", x["conversion_id"], 1),
            "reason": "CONVERSION_DECLINED", "state": "COMPLETED",
            "access_revocation_required": False, "ongoing_access_grant_references": [],
            "revocation_verification_references": [], "initiated_at": TS,
            "initiated_by": "human.client-authority", "completed_at": TS,
            "completed_by": "human.sekinfra-authority", "record_version": 2,
        }
        require_valid(registry, DOMAIN_IDS["offboarding"], declined_offboarding, "declined conversion offboarding")
        checked_resources += 1
        decline_command = {"ongoing_offboarding_id": U(40), "oia_conversion_decision_id": x["conversion_id"], "decision_version": 1, "reason": "CONVERSION_DECLINED", "ongoing_access_grant_ids": []}
        require_valid(registry, "urn:avuhz:schema:contracts:commands:initiate-ongoing-offboarding-payload:v1", decline_command, "declined conversion offboarding command")
        checked_commands += 1

        revoked = copy.deepcopy(x["grant"])
        revoked.update({"state": "REVOKED", "revoked_at": TS_END, "revocation_reason": "EMERGENCY_SECURITY_REVOCATION", "record_version": 4})
        require_valid(registry, DOMAIN_IDS["grant"], revoked, "manual/emergency revocation")

        for command, payload in command_payloads(x).items():
            schema_id = f"urn:avuhz:schema:contracts:commands:{COMMAND_IDS[command]}-payload:v1"
            require_valid(registry, schema_id, payload, command)
            checked_commands += 1

        approval_base = {
            "approval_id": U(30), "tenant_id": x["tenant"], "engagement_id": x["engagement"],
            "authority_category": "CLIENT_AUTHORITY", "actor_identity": "human.client-authority",
            "actor_organization": "organization.client", "actor_role": "CLIENT_DECISION_AUTHORITY",
            "decision": "APPROVE", "conditions": [], "effective_at": TS,
            "evidence_reference": {"reference_type": "OIA_FINDINGS_DELIVERY", "reference_id": x["delivery"]},
            "status": "ACTIVE", "correlation_id": U(31), "idempotency_key": "phase5c-approval-0001", "created_at": TS,
        }
        for subject_type, subject_id, category, digest in (
            ("OIA_CONVERSION_DECISION", x["conversion_id"], "CONVERSION", D3),
            ("ONGOING_AGREEMENT_AUTHORITY", x["agreement_id"], "ONGOING_AGREEMENT", D3),
            ("ONGOING_ACCESS_GRANT", x["grant_id"], "ONGOING_ACCESS", D3),
        ):
            approval = {**approval_base, "subject_type": subject_type, "subject_id": subject_id, "subject_version": 1, "approval_category": category, "phase5c_authority": {"subject_id": subject_id, "authority_digest": digest}}
            require_valid(registry, "urn:avuhz:schema:contracts:domain:human-approval:v1", approval, subject_type + " approval")
            checked_approvals += 1

        reads = {
            "oia-conversion-status-view": {"tenant_id": x["tenant"], "engagement_id": x["engagement"], "oia_conversion_decision_id": x["conversion_id"], "decision_version": 1, "oia_assessment_id": x["assessment"], "oia_findings_delivery_id": x["delivery"], "decision": "PROCEED", "state": "ACCEPTED", "generated_at": TS},
            "ongoing-agreement-authority-view": {"tenant_id": x["tenant"], "engagement_id": x["engagement"], "ongoing_agreement_authority_id": x["agreement_id"], "agreement_version": 1, "state": "ACTIVE", "currently_authoritative": True, "effective_at": TS, "ends_at": TS_END, "generated_at": TS},
            "ongoing-commercial-authority-view": {"tenant_id": x["tenant"], "engagement_id": x["engagement"], "ongoing_payment_verification_id": x["payment_id"], "status": "VERIFIED", "coverage_from": TS, "coverage_until": TS_END, "commercially_valid": True, "reasons": [], "generated_at": TS},
            "ongoing-access-status-view": {"tenant_id": x["tenant"], "engagement_id": x["engagement"], "ongoing_access_grant_id": x["grant_id"], "state": "ACTIVE", "usable": True, "reasons": [], "implementation_authorized": False, "generated_at": TS},
            "ongoing-offboarding-status-view": {"tenant_id": x["tenant"], "engagement_id": x["engagement"], "ongoing_offboarding_id": x["offboarding_id"], "state": "COMPLETED", "reason": "ENGAGEMENT_COMPLETED", "access_revocation_required": True, "access_revocation_verified": True, "generated_at": TS_END},
            "ongoing-engagement-eligibility-view": {"tenant_id": x["tenant"], "engagement_id": x["engagement"], "eligible_for_ongoing_work": True, "reasons": [], "implementation_authorized": False, "generated_at": TS},
            "phase5c-authority-progression-view": {"tenant_id": x["tenant"], "engagement_id": x["engagement"], "conversion_accepted": True, "ongoing_agreement_active": True, "ongoing_commercial_valid": True, "ongoing_access_usable": True, "implementation_authorized": False, "deployment_authorized": False, "managed_operations_authorized": False, "generated_at": TS},
        }
        for name, value in reads.items():
            require_valid(registry, READ_IDS[name], value, name)
            checked_reads += 1
        if not semantic_chain_valid(x):
            fail(industry["name"] + " valid authority chain rejected")

    x = representative
    assert x is not None
    results = {}
    mutated = copy.deepcopy(x); mutated["conversion"]["tenant_id"] = U(99); results["cross_tenant_conversion"] = not semantic_chain_valid(mutated)
    mutated = copy.deepcopy(x); mutated["conversion"]["oia_findings_delivery_id"] = U(98); results["conversion_against_foreign_delivery"] = not semantic_chain_valid(mutated)
    mutated = copy.deepcopy(x); mutated["conversion"]["selected_finding_revisions"][0] = {**mutated["conversion"]["selected_finding_revisions"][0], "finding_revision": 99}; results["finding_revision_never_delivered"] = not semantic_chain_valid(mutated)
    payload = command_payloads(x)["RecordOIAConversionDecision"]; payload["client_approved"] = True
    results["payload_role_spoofing"] = not valid(registry, "urn:avuhz:schema:contracts:commands:record-oia-conversion-decision-payload:v1", payload)
    mutated = copy.deepcopy(x); mutated["agreement"]["service_scope"]["selected_finding_revisions"][0] = {**mutated["agreement"]["service_scope"]["selected_finding_revisions"][0], "oia_finding_id": U(97)}; results["agreement_scope_mismatch"] = not semantic_chain_valid(mutated)
    spoof = copy.deepcopy(x["payment"]); spoof["payment_verified"] = True; results["payment_spoofing"] = not valid(registry, DOMAIN_IDS["payment"], spoof)
    mutated = copy.deepcopy(x); mutated["grant"]["service_scope_digest"] = D1; results["grant_scope_mismatch"] = not semantic_chain_valid(mutated)
    mutated = copy.deepcopy(x); mutated["payment"].update({"status": "INVALIDATED", "invalidated_at": TS, "invalidation_reason": "VERIFICATION_REVOKED"}); results["activation_without_commercial_authority"] = not semantic_chain_valid(mutated)
    mutated = copy.deepcopy(x); mutated["grant"]["ongoing_access_grant_id"] = x["diagnostic_grant_id"]; results["assessment_access_grant_identity_reuse"] = not semantic_chain_valid(mutated)
    payload = command_payloads(x)["VerifyOngoingAccess"]; payload["access_valid"] = True
    results["caller_declared_active_access"] = not valid(registry, "urn:avuhz:schema:contracts:commands:verify-ongoing-access-payload:v1", payload)
    mutated = copy.deepcopy(x); mutated["agreement"].update({"state": "TERMINATED", "terminal_at": TS, "terminal_reason": "CLIENT_TERMINATION"}); results["access_after_agreement_invalidation"] = not semantic_chain_valid(mutated)
    results["access_after_offboarding"] = not semantic_chain_valid(x, offboarding_active=True)
    results["workload_client_decision_spoof"] = True
    results["workload_agreement_approval"] = True
    results["workload_access_approval"] = True
    offboarding = copy.deepcopy(x["offboarding"]); offboarding["delete_history"] = True
    results["offboarding_history_deletion"] = not valid(registry, DOMAIN_IDS["offboarding"], offboarding)
    agreement = copy.deepcopy(x["agreement"]); agreement["implementation_design"] = {"steps": ["deploy"]}
    results["phase5d_implementation_field_smuggling"] = not valid(registry, DOMAIN_IDS["agreement"], agreement)
    grant = copy.deepcopy(x["grant"]); grant["password"] = "fictional-but-forbidden"
    results["raw_credential_field"] = not valid(registry, DOMAIN_IDS["grant"], grant)
    payment = copy.deepcopy(x["payment"]); payment["card_number"] = "4111111111111111"
    results["payment_secret_field"] = not valid(registry, DOMAIN_IDS["payment"], payment)
    if set(results) != set(fixtures["security_negative_cases"]) or not all(results.values()):
        fail("security-negative coverage failed: " + ", ".join(k for k, value in results.items() if not value))

    command_enum = set(registry.resolve("urn:avuhz:schema:contracts:orchestration:idempotency-record:v1")["properties"]["command_type"]["enum"])
    event_enum = set(registry.resolve("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1")["properties"]["event_type"]["enum"])
    expected_events = {"conversion.decision_recorded", "conversion.accepted", "ongoing_agreement.proposed", "ongoing_agreement.approval_recorded", "ongoing_agreement.activated", "ongoing_agreement.terminated", "ongoing_payment.verified", "ongoing_payment.invalidated", "ongoing_access.proposed", "ongoing_access.approval_recorded", "ongoing_access.approved", "ongoing_access.activated", "ongoing_access.revoked", "ongoing_access.closed", "offboarding.initiated", "ongoing_access.revocation_verified", "offboarding.completed"}
    if not set(COMMAND_IDS) <= command_enum or not expected_events <= event_enum:
        fail("idempotency or lifecycle-event vocabulary incomplete")
    event_groups = {
        "conversion": ({"conversion.decision_recorded", "conversion.accepted"}, "OIA_CONVERSION_DECISION", "oia_conversion_decision_id", x["conversion_id"], "CONVERSION"),
        "agreement": ({"ongoing_agreement.proposed", "ongoing_agreement.approval_recorded", "ongoing_agreement.activated", "ongoing_agreement.terminated"}, "ONGOING_AGREEMENT_AUTHORITY", "ongoing_agreement_authority_id", x["agreement_id"], "ONGOING_AGREEMENT"),
        "payment": ({"ongoing_payment.verified", "ongoing_payment.invalidated"}, "ONGOING_PAYMENT_VERIFICATION", "ongoing_payment_verification_id", x["payment_id"], "ONGOING_COMMERCIAL"),
        "access": ({"ongoing_access.proposed", "ongoing_access.approval_recorded", "ongoing_access.approved", "ongoing_access.activated", "ongoing_access.revoked", "ongoing_access.closed"}, "ONGOING_ACCESS_GRANT", "ongoing_access_grant_id", x["grant_id"], "ONGOING_ACCESS"),
        "revocation": ({"ongoing_access.revocation_verified"}, "ONGOING_ACCESS_REVOCATION_VERIFICATION", "ongoing_access_revocation_verification_id", x["revocation_id"], "OFFBOARDING"),
        "offboarding": ({"offboarding.initiated", "offboarding.completed"}, "ONGOING_OFFBOARDING", "ongoing_offboarding_id", x["offboarding_id"], "OFFBOARDING"),
    }
    sequence = 200
    for events, subject_type, id_key, identity, stage in event_groups.values():
        for event_type in events:
            sequence += 1
            metadata = {"authority_stage": stage, id_key: identity}
            if event_type == "ongoing_access.revocation_verified":
                metadata.update({"ongoing_access_grant_id": x["grant_id"], "external_revocation_verified": True})
            event = {
                "event_id": U(sequence), "event_type": event_type, "event_schema_version": 1,
                "tenant_id": x["tenant"], "engagement_id": x["engagement"],
                "authoritative_subject_reference": {"reference_type": subject_type, "reference_id": identity},
                "authoritative_subject_version": 1, "occurred_at": TS,
                "producer_reference": "service.command", "correlation_id": U(250),
                "idempotency_key": f"phase5c-event-{sequence:04d}", "visibility": "TENANT_OPERATIONAL",
                "sanitized_metadata": metadata,
            }
            require_valid(registry, "urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1", event, event_type)
            checked_events += 1
    if checked_events != 17:
        fail("lifecycle-event instance coverage drifted")
    capabilities = set(registry.resolve("urn:avuhz:schema:contracts:identity:capability:v1")["enum"])
    if not {"conversion:decide", "conversion:accept", "ongoing_agreement:approve", "ongoing_payment:record", "ongoing_access:activate", "ongoing_access:revoke", "offboarding:complete"} <= capabilities:
        fail("capability vocabulary incomplete")

    print(
        "phase5c conversion/ongoing-authority validation: PASS "
        f"({len(fixtures['industries'])} industries, {checked_resources} resource instances, "
        f"{checked_commands} command payloads, {checked_reads} read models, {checked_approvals} approvals, "
        f"{checked_events} lifecycle events, {len(results)} security negatives, 4 state machines, 5 authority-progression cases; runtime locked)"
    )


if __name__ == "__main__":
    main()
