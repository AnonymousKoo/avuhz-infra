#!/usr/bin/env python3
"""Validate frozen Phase 5D-A implementation-package architecture contracts."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
FIXTURE_PATH = ROOT / "contracts/fixtures/v1/phase5d-implementation-package.cases.json"
sys.path.insert(0, str(ROOT / "src"))
from avuhz_runtime.command_registry import COMMANDS  # noqa: E402
from avuhz_runtime.schema_registry import SCHEMA_FILES  # noqa: E402

COMMANDS_5D = [
    "DraftImplementationBrief",
    "ReviseImplementationBrief",
    "RecordImplementationBriefApproval",
    "ApproveImplementationBrief",
    "ProposeImplementationAuthorization",
    "ReviseImplementationAuthorization",
    "RecordImplementationAuthorizationApproval",
    "ActivateImplementationAuthorization",
    "RevokeImplementationAuthorization",
    "DraftCodexBuildPackage",
    "ReviseCodexBuildPackage",
    "RecordCodexBuildPackageApproval",
    "ReleaseCodexBuildPackage",
]
CAPABILITIES_5D = [
    "implementation_brief:draft",
    "implementation_brief:approve",
    "implementation_authorization:propose",
    "implementation_authorization:approve",
    "implementation_authorization:activate",
    "implementation_authorization:revoke",
    "codex_build_package:draft",
    "codex_build_package:approve",
    "codex_build_package:release",
]
EVENTS_5D = [
    "implementation_brief.drafted",
    "implementation_brief.revised",
    "implementation_brief.approval_recorded",
    "implementation_brief.approved",
    "implementation_authorization.proposed",
    "implementation_authorization.revised",
    "implementation_authorization.approval_recorded",
    "implementation_authorization.activated",
    "implementation_authorization.revoked",
    "codex_build_package.drafted",
    "codex_build_package.revised",
    "codex_build_package.approval_recorded",
    "codex_build_package.released",
]
SUBJECTS = {
    "ImplementationBrief": "IMPLEMENTATION_BRIEF",
    "ImplementationAuthorization": "IMPLEMENTATION_AUTHORIZATION",
    "CodexBuildPackage": "CODEX_BUILD_PACKAGE",
}
PROHIBITED = {
    "OUT_OF_SCOPE_SYSTEM_CHANGE",
    "PERMISSION_WIDENING",
    "DATA_DELETION",
    "CREDENTIAL_ROTATION",
    "PRODUCTION_DEPLOYMENT",
    "PRODUCTION_CHANGE",
    "BILLING_CHANGE",
    "OUT_OF_SCOPE_NETWORK_CHANGE",
    "OUT_OF_SCOPE_SECURITY_CONTROL_CHANGE",
}
DOMAIN_IDS = {
    "brief": "urn:avuhz:schema:contracts:domain:implementation-brief:v1",
    "authorization": "urn:avuhz:schema:contracts:domain:implementation-authorization:v1",
    "package": "urn:avuhz:schema:contracts:domain:codex-build-package:v1",
    "approval": "urn:avuhz:schema:contracts:domain:human-approval:v1",
}
PAYLOAD_IDS = {
    "DraftImplementationBrief": "urn:avuhz:schema:contracts:commands:draft-implementation-brief-payload:v1",
    "ReviseImplementationBrief": "urn:avuhz:schema:contracts:commands:revise-implementation-brief-payload:v1",
    "RecordImplementationBriefApproval": "urn:avuhz:schema:contracts:commands:record-implementation-brief-approval-payload:v1",
    "ApproveImplementationBrief": "urn:avuhz:schema:contracts:commands:approve-implementation-brief-payload:v1",
    "ProposeImplementationAuthorization": "urn:avuhz:schema:contracts:commands:propose-implementation-authorization-payload:v1",
    "ReviseImplementationAuthorization": "urn:avuhz:schema:contracts:commands:revise-implementation-authorization-payload:v1",
    "RecordImplementationAuthorizationApproval": "urn:avuhz:schema:contracts:commands:record-implementation-authorization-approval-payload:v1",
    "ActivateImplementationAuthorization": "urn:avuhz:schema:contracts:commands:activate-implementation-authorization-payload:v1",
    "RevokeImplementationAuthorization": "urn:avuhz:schema:contracts:commands:revoke-implementation-authorization-payload:v1",
    "DraftCodexBuildPackage": "urn:avuhz:schema:contracts:commands:draft-codex-build-package-payload:v1",
    "ReviseCodexBuildPackage": "urn:avuhz:schema:contracts:commands:revise-codex-build-package-payload:v1",
    "RecordCodexBuildPackageApproval": "urn:avuhz:schema:contracts:commands:record-codex-build-package-approval-payload:v1",
    "ReleaseCodexBuildPackage": "urn:avuhz:schema:contracts:commands:release-codex-build-package-payload:v1",
}


def fail(message: str) -> None:
    print("phase5d implementation-package validation: FAIL: " + message, file=sys.stderr)
    raise SystemExit(1)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def pointer(document: dict, fragment: str):
    target = document
    if not fragment:
        return target
    if not fragment.startswith("/"):
        raise KeyError(fragment)
    for part in fragment[1:].split("/"):
        target = target[part.replace("~1", "/").replace("~0", "~")]
    return target


def resolve(reference: str, document: dict, schemas: dict[str, dict]):
    if reference.startswith("#"):
        target_document, fragment = document, reference[1:]
    else:
        schema_id, separator, fragment = reference.partition("#")
        target_document = schemas[schema_id]
        fragment = fragment if separator else ""
    return target_document, pointer(target_document, fragment)


def expand(value, document: dict, schemas: dict[str, dict]):
    if isinstance(value, dict):
        if "$ref" in value:
            target_document, target = resolve(value["$ref"], document, schemas)
            expanded = expand(copy.deepcopy(target), target_document, schemas)
            siblings = {key: expand(child, document, schemas) for key, child in value.items() if key != "$ref"}
            return {**expanded, **siblings}
        return {key: expand(child, document, schemas) for key, child in value.items()}
    if isinstance(value, list):
        return [expand(child, document, schemas) for child in value]
    return value


def all_refs(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref":
                yield child
            yield from all_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from all_refs(child)


def validator(schema_id: str, schemas: dict[str, dict]) -> Draft202012Validator:
    schema = expand(schemas[schema_id], schemas[schema_id], schemas)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def require_valid(schema_id: str, value: dict, schemas: dict[str, dict], label: str) -> None:
    errors = sorted(validator(schema_id, schemas).iter_errors(value), key=lambda error: list(error.path))
    if errors:
        fail(f"{label} rejected: {errors[0].message}")


def require_invalid(schema_id: str, value: dict, schemas: dict[str, dict], label: str) -> None:
    if not list(validator(schema_id, schemas).iter_errors(value)):
        fail(f"{label} was accepted")


def command_applies(rule: dict, command: str) -> bool:
    command_rule = rule.get("if", {}).get("properties", {}).get("command_type", {})
    return command_rule.get("const") == command or command in command_rule.get("enum", [])


def assert_command_policy(schemas: dict[str, dict]) -> None:
    envelope = schemas["urn:avuhz:schema:contracts:commands:command-envelope:v1"]
    rules = envelope["$defs"]["envelopeCore"]["allOf"]
    expected_subject = {
        **{name: "IMPLEMENTATION_BRIEF" for name in COMMANDS_5D[:4]},
        **{name: "IMPLEMENTATION_AUTHORIZATION" for name in COMMANDS_5D[4:9]},
        **{name: "CODEX_BUILD_PACKAGE" for name in COMMANDS_5D[9:]},
    }
    human = {"RecordImplementationBriefApproval", "RecordImplementationAuthorizationApproval", "RevokeImplementationAuthorization", "RecordCodexBuildPackageApproval"}
    internal = {"ApproveImplementationBrief", "ActivateImplementationAuthorization", "ReleaseCodexBuildPackage"}
    creation = {"DraftImplementationBrief", "ProposeImplementationAuthorization", "DraftCodexBuildPackage"}
    expected_version = set(COMMANDS_5D) - creation
    all_callers = {"HUMAN", "CLIENT_USER", "SEKINFRA_USER", "INTERNAL_SERVICE", "N8N_ORCHESTRATOR", "PROVIDER_ADAPTER", "SCHEDULED_AUTOMATION", "SECURITY_AUTOMATION"}
    for command in COMMANDS_5D:
        allowed = set(all_callers)
        subjects = set()
        version_required = False
        engagement_required = False
        for rule in rules:
            if not command_applies(rule, command):
                continue
            then = rule.get("then", {})
            caller = then.get("properties", {}).get("caller_type", {})
            if "const" in caller:
                allowed &= {caller["const"]}
            if "enum" in caller:
                allowed &= set(caller["enum"])
            subject = then.get("properties", {}).get("subject_type", {})
            if "const" in subject:
                subjects.add(subject["const"])
            required = set(then.get("required", []))
            version_required |= "expected_record_version" in required
            engagement_required |= "engagement_id" in required
        wanted = {"HUMAN"} if command in human else {"INTERNAL_SERVICE"} if command in internal else {"HUMAN", "INTERNAL_SERVICE"}
        if allowed != wanted:
            fail(f"caller boundary drifted for {command}: {sorted(allowed)}")
        if subjects != {expected_subject[command]} or not engagement_required:
            fail(f"tenant/engagement subject binding drifted for {command}")
        if version_required != (command in expected_version):
            fail(f"expected-version rule drifted for {command}")
    if not set(COMMANDS_5D).issubset(envelope["$defs"]["commandType"]["enum"]):
        fail("Phase 5D command vocabulary drifted")
    if not set(SUBJECTS.values()).issubset(envelope["$defs"]["subjectType"]["enum"]):
        fail("Phase 5D subject vocabulary drifted")


def build_payloads(values: dict) -> dict[str, dict]:
    brief = values["implementation_brief"]
    authorization = values["implementation_authorization"]
    package = values["codex_build_package"]
    brief_omit = {"tenant_id", "engagement_id", "state", "client_approval_reference", "sekinfra_approval_reference", "trusted_attribution", "approved_at", "record_version", "created_at", "updated_at"}
    draft_brief = {key: copy.deepcopy(value) for key, value in brief.items() if key not in brief_omit}
    revise_brief = copy.deepcopy(draft_brief)
    revise_brief["implementation_brief_version"] = 2
    revise_brief["supersedes_implementation_brief_reference"] = {"reference_type": "IMPLEMENTATION_BRIEF", "reference_id": brief["implementation_brief_id"], "reference_version": 1}
    auth_keys = ["implementation_authorization_id", "authorization_version", "implementation_brief_reference", "implementation_brief_digest", "authorized_scope_digest", "target_references", "permitted_action_classes", "prohibited_action_classes", "effective_at", "expires_at", "implementation_authority_digest"]
    propose_auth = {key: copy.deepcopy(authorization[key]) for key in auth_keys}
    revise_auth = copy.deepcopy(propose_auth)
    revise_auth["authorization_version"] = 2
    revise_auth["supersedes_implementation_authorization_reference"] = {"reference_type": "IMPLEMENTATION_AUTHORIZATION", "reference_id": authorization["implementation_authorization_id"], "reference_version": 1}
    package_omit = {"tenant_id", "engagement_id", "state", "client_approval_reference", "sekinfra_approval_reference", "trusted_attribution", "released_at", "record_version", "created_at", "updated_at"}
    draft_package = {key: copy.deepcopy(value) for key, value in package.items() if key not in package_omit}
    revise_package = copy.deepcopy(draft_package)
    revise_package["package_version"] = 2
    revise_package["supersedes_codex_build_package_reference"] = {"reference_type": "CODEX_BUILD_PACKAGE", "reference_id": package["codex_build_package_id"], "reference_version": 1}
    return {
        "DraftImplementationBrief": draft_brief,
        "ReviseImplementationBrief": revise_brief,
        "RecordImplementationBriefApproval": {"subject_version": 1, "authority_role": "CLIENT_IMPLEMENTATION_AUTHORITY", "authority_digest": brief["implementation_brief_digest"]},
        "ApproveImplementationBrief": {"implementation_brief_id": brief["implementation_brief_id"], "implementation_brief_version": 1, "client_approval_reference": brief["client_approval_reference"], "sekinfra_approval_reference": brief["sekinfra_approval_reference"], "implementation_brief_digest": brief["implementation_brief_digest"]},
        "ProposeImplementationAuthorization": propose_auth,
        "ReviseImplementationAuthorization": revise_auth,
        "RecordImplementationAuthorizationApproval": {"subject_version": 1, "authority_role": "CLIENT_IMPLEMENTATION_AUTHORITY", "authority_digest": authorization["implementation_authority_digest"]},
        "ActivateImplementationAuthorization": {"implementation_authorization_id": authorization["implementation_authorization_id"], "authorization_version": 1, "client_approval_reference": authorization["client_approval_reference"], "sekinfra_approval_reference": authorization["sekinfra_approval_reference"], "implementation_authority_digest": authorization["implementation_authority_digest"]},
        "RevokeImplementationAuthorization": {"implementation_authorization_id": authorization["implementation_authorization_id"], "revocation_reason": "SECURITY_CONCERN"},
        "DraftCodexBuildPackage": draft_package,
        "ReviseCodexBuildPackage": revise_package,
        "RecordCodexBuildPackageApproval": {"subject_version": 1, "authority_role": "CLIENT_IMPLEMENTATION_AUTHORITY", "authority_digest": package["package_digest"]},
        "ReleaseCodexBuildPackage": {"codex_build_package_id": package["codex_build_package_id"], "package_version": 1, "client_approval_reference": package["client_approval_reference"], "sekinfra_approval_reference": package["sekinfra_approval_reference"], "package_digest": package["package_digest"]},
    }


def assert_approvals(schemas: dict[str, dict], values: dict) -> None:
    mapping = [
        ("IMPLEMENTATION_BRIEF", values["implementation_brief"]["implementation_brief_id"], "IMPLEMENTATION_BRIEF", values["implementation_brief"]["implementation_brief_digest"]),
        ("IMPLEMENTATION_AUTHORIZATION", values["implementation_authorization"]["implementation_authorization_id"], "IMPLEMENTATION_AUTHORIZATION", values["implementation_authorization"]["implementation_authority_digest"]),
        ("CODEX_BUILD_PACKAGE", values["codex_build_package"]["codex_build_package_id"], "CODEX_BUILD_PACKAGE", values["codex_build_package"]["package_digest"]),
    ]
    index = 30
    for subject_type, subject_id, category, digest in mapping:
        for authority, role in (("CLIENT_AUTHORITY", "CLIENT_IMPLEMENTATION_AUTHORITY"), ("SEKINFRA_AUTHORITY", "SEKINFRA_IMPLEMENTATION_AUTHORITY")):
            index += 1
            approval = {
                "approval_id": f"d5000000-0000-4000-8000-{index:012d}",
                "tenant_id": values["implementation_brief"]["tenant_id"],
                "engagement_id": values["implementation_brief"]["engagement_id"],
                "subject_type": subject_type,
                "subject_id": subject_id,
                "subject_version": 1,
                "approval_category": category,
                "authority_category": authority,
                "actor_identity": "human.phase5d",
                "actor_organization": "organization.fictional",
                "actor_role": role,
                "decision": "APPROVE",
                "phase5d_authority": {"subject_id": subject_id, "authority_digest": digest},
                "conditions": [],
                "effective_at": "2030-01-15T15:00:00Z",
                "evidence_reference": {"reference_type": "LIFECYCLE_EVENT", "reference_id": "d5000000-0000-4000-8000-000000000090"},
                "status": "ACTIVE",
                "correlation_id": "d5000000-0000-4000-8000-000000000091",
                "idempotency_key": f"phase5d-approval-{index:04d}",
                "created_at": "2030-01-15T15:00:00Z",
            }
            require_valid(DOMAIN_IDS["approval"], approval, schemas, f"{subject_type} {authority} approval")
            wrong_role = copy.deepcopy(approval)
            wrong_role["actor_role"] = "CLIENT_DECISION_AUTHORITY" if authority == "CLIENT_AUTHORITY" else "SEKINFRA_ENGAGEMENT_AUTHORITY"
            require_invalid(DOMAIN_IDS["approval"], wrong_role, schemas, f"{subject_type} legacy-role reuse")
    old = {
        "approval_id": "d5000000-0000-4000-8000-000000000092", "tenant_id": values["implementation_brief"]["tenant_id"], "engagement_id": values["implementation_brief"]["engagement_id"],
        "subject_type": "ONGOING_ACCESS_GRANT", "subject_id": values["implementation_brief"]["source_ongoing_access_reference"]["reference_id"], "subject_version": 4, "approval_category": "ONGOING_ACCESS",
        "authority_category": "CLIENT_AUTHORITY", "actor_identity": "human.client", "actor_organization": "organization.fictional", "actor_role": "CLIENT_DECISION_AUTHORITY", "decision": "APPROVE",
        "phase5c_authority": {"subject_id": values["implementation_brief"]["source_ongoing_access_reference"]["reference_id"], "authority_digest": "sha256:" + "2" * 64},
        "phase5d_authority": {"subject_id": values["implementation_brief"]["implementation_brief_id"], "authority_digest": values["implementation_brief"]["implementation_brief_digest"]},
        "conditions": [], "effective_at": "2030-01-15T15:00:00Z", "evidence_reference": {"reference_type": "LIFECYCLE_EVENT", "reference_id": "d5000000-0000-4000-8000-000000000090"},
        "status": "ACTIVE", "correlation_id": "d5000000-0000-4000-8000-000000000091", "idempotency_key": "phase5d-old-approval-reuse", "created_at": "2030-01-15T15:00:00Z",
    }
    require_invalid(DOMAIN_IDS["approval"], old, schemas, "Phase 5C approval with Phase 5D binding")


def assert_events(schemas: dict[str, dict], values: dict) -> None:
    event_schema = "urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"
    brief_id = values["implementation_brief"]["implementation_brief_id"]
    authorization_id = values["implementation_authorization"]["implementation_authorization_id"]
    package_id = values["codex_build_package"]["codex_build_package_id"]
    for index, event_type in enumerate(EVENTS_5D, 1):
        if event_type.startswith("implementation_brief."):
            subject, identity, stage, id_key = "IMPLEMENTATION_BRIEF", brief_id, "IMPLEMENTATION_BRIEF", "implementation_brief_id"
        elif event_type.startswith("implementation_authorization."):
            subject, identity, stage, id_key = "IMPLEMENTATION_AUTHORIZATION", authorization_id, "IMPLEMENTATION_AUTHORIZATION", "implementation_authorization_id"
        else:
            subject, identity, stage, id_key = "CODEX_BUILD_PACKAGE", package_id, "CODEX_BUILD_PACKAGE", "codex_build_package_id"
        metadata = {"authority_stage": stage, id_key: identity}
        if ".approval_recorded" in event_type:
            metadata["approval_id"] = f"d5000000-0000-4000-8000-{100 + index:012d}"
        if ".revised" in event_type:
            metadata["superseded_version"] = 1
        event = {
            "event_id": f"d5000000-0000-4000-8000-{200 + index:012d}", "event_type": event_type, "event_schema_version": 1,
            "tenant_id": values["implementation_brief"]["tenant_id"], "engagement_id": values["implementation_brief"]["engagement_id"],
            "authoritative_subject_reference": {"reference_type": subject, "reference_id": identity}, "authoritative_subject_version": 1,
            "occurred_at": "2030-01-15T17:00:00Z", "producer_reference": "service.phase5d", "command_id": f"d5000000-0000-4000-8000-{300 + index:012d}",
            "correlation_id": "d5000000-0000-4000-8000-000000000091", "idempotency_key": f"phase5d-event-{index:04d}",
            "visibility": "TENANT_OPERATIONAL", "sanitized_metadata": metadata,
        }
        require_valid(event_schema, event, schemas, event_type)
        if ".revised" in event_type:
            missing = copy.deepcopy(event)
            del missing["sanitized_metadata"]["superseded_version"]
            require_invalid(event_schema, missing, schemas, event_type + " without superseded version")


def assert_reads(schemas: dict[str, dict], values: dict) -> None:
    timestamp = "2030-01-15T17:00:00Z"
    brief = values["implementation_brief"]
    authorization = values["implementation_authorization"]
    package = values["codex_build_package"]
    cases = [
        ("urn:avuhz:schema:contracts:read-models:implementation-brief-readiness-view:v1", {
            "tenant_id": brief["tenant_id"], "engagement_id": brief["engagement_id"], "implementation_brief_reference": {"reference_type": "IMPLEMENTATION_BRIEF", "reference_id": brief["implementation_brief_id"], "reference_version": 1},
            "source_truth_exact": True, "conversion_accepted": True, "ongoing_agreement_active": True, "commercial_authority_valid": True, "ongoing_access_usable": True, "client_approval_active": True, "sekinfra_approval_active": True, "implementation_brief_ready": True, "reasons": [],
            "implementation_authorized": False, "deployment_authorized": False, "production_change_authorized": False, "generated_at": timestamp,
        }),
        ("urn:avuhz:schema:contracts:read-models:implementation-authorization-status-view:v1", {
            "tenant_id": brief["tenant_id"], "engagement_id": brief["engagement_id"], "implementation_authorization_reference": {"reference_type": "IMPLEMENTATION_AUTHORIZATION", "reference_id": authorization["implementation_authorization_id"], "reference_version": 1}, "state": "ACTIVE",
            "brief_ready": True, "commercial_authority_valid": True, "ongoing_access_usable": True, "within_validity_window": True, "scope_and_targets_match": True, "approvals_active": True, "implementation_authorization_ready": True, "implementation_authorization_usable": True, "reasons": [],
            "deployment_authorized": False, "production_change_authorized": False, "generated_at": timestamp,
        }),
        ("urn:avuhz:schema:contracts:read-models:codex-build-package-readiness-view:v1", {
            "tenant_id": brief["tenant_id"], "engagement_id": brief["engagement_id"], "codex_build_package_reference": {"reference_type": "CODEX_BUILD_PACKAGE", "reference_id": package["codex_build_package_id"], "reference_version": 1},
            "implementation_brief_reference": package["implementation_brief_reference"], "implementation_authorization_reference": package["implementation_authorization_reference"], "package_state": "RELEASED",
            "brief_ready": True, "implementation_authorization_usable": True, "digests_match": True, "approvals_active": True, "acceptance_criteria_complete": True, "prohibited_changes_complete": True, "codex_build_package_ready": True, "reasons": [],
            "package_grants_authority": False, "deployment_authorized": False, "production_change_authorized": False, "generated_at": timestamp,
        }),
        ("urn:avuhz:schema:contracts:read-models:phase5d-authority-progression-view:v1", {
            "tenant_id": brief["tenant_id"], "engagement_id": brief["engagement_id"], "findings_delivered": True, "conversion_accepted": True, "ongoing_commercial_valid": True, "ongoing_access_usable": True,
            "implementation_brief_ready": True, "implementation_authorization_ready": True, "implementation_authorization_usable": True, "codex_build_package_ready": True,
            "package_grants_authority": False, "deployment_authorized": False, "production_change_authorized": False, "managed_operations_authorized": False, "generated_at": timestamp,
        }),
    ]
    for schema_id, value in cases:
        require_valid(schema_id, value, schemas, schema_id)
        for field in ("package_grants_authority", "deployment_authorized", "production_change_authorized", "managed_operations_authorized"):
            if field not in value:
                continue
            invalid = copy.deepcopy(value)
            invalid[field] = True
            require_invalid(schema_id, invalid, schemas, schema_id + " caller authority claim")


def assert_security_negatives(schemas: dict[str, dict], fixture: dict, values: dict, payloads: dict[str, dict]) -> int:
    names = fixture["security_negative_names"]
    expected = {
        "latest_finding_reference", "finding_digest_omitted", "foreign_delivery_reference", "diagnostic_access_reuse",
        "ongoing_access_as_implementation_authority", "payload_role_claim", "workload_self_authorization", "package_as_authority",
        "deployment_authorized_true", "production_change_action", "permission_widening_omitted", "upstream_correction_silent_rewrite",
        "history_delete_field", "credential_field_injection", "raw_provider_payload_injection", "unsupported_acceptance_metric",
    }
    if set(names) != expected:
        fail("security-negative fixture vocabulary drifted")
    brief, authorization, package = values["implementation_brief"], values["implementation_authorization"], values["codex_build_package"]
    case = copy.deepcopy(brief); case["latest_finding_reference"] = "latest"; require_invalid(DOMAIN_IDS["brief"], case, schemas, "latest Finding")
    case = copy.deepcopy(brief); del case["source_finding_revisions"][0]["content_digest"]; require_invalid(DOMAIN_IDS["brief"], case, schemas, "Finding digest omission")
    case = copy.deepcopy(brief); case["source_findings_delivery_reference"]["reference_type"] = "OIA_FINDING"; require_invalid(DOMAIN_IDS["brief"], case, schemas, "foreign delivery")
    case = copy.deepcopy(brief); case["source_ongoing_access_reference"]["reference_type"] = "ASSESSMENT_ACCESS_GRANT"; require_invalid(DOMAIN_IDS["brief"], case, schemas, "diagnostic grant reuse")
    case = copy.deepcopy(authorization); case["source_ongoing_access_reference"]["reference_type"] = "IMPLEMENTATION_AUTHORIZATION"; require_invalid(DOMAIN_IDS["authorization"], case, schemas, "ongoing access as implementation authority")
    case = copy.deepcopy(payloads["ActivateImplementationAuthorization"]); case["authority_role"] = "SEKINFRA_IMPLEMENTATION_AUTHORITY"; require_invalid(PAYLOAD_IDS["ActivateImplementationAuthorization"], case, schemas, "payload role claim")
    # Exact caller policy proves workload, n8n, scheduled automation, provider, and security automation are outside the intersection.
    assert_command_policy(schemas)
    case = copy.deepcopy(package); case["implementation_authorization_reference"]["reference_type"] = "CODEX_BUILD_PACKAGE"; require_invalid(DOMAIN_IDS["package"], case, schemas, "package as authority")
    progression_id = "urn:avuhz:schema:contracts:read-models:phase5d-authority-progression-view:v1"
    progression = {"tenant_id": brief["tenant_id"], "engagement_id": brief["engagement_id"], "findings_delivered": True, "conversion_accepted": True, "ongoing_commercial_valid": True, "ongoing_access_usable": True, "implementation_brief_ready": True, "implementation_authorization_ready": True, "implementation_authorization_usable": True, "codex_build_package_ready": True, "package_grants_authority": False, "deployment_authorized": True, "production_change_authorized": False, "managed_operations_authorized": False, "generated_at": "2030-01-15T17:00:00Z"}
    require_invalid(progression_id, progression, schemas, "deployment authority claim")
    case = copy.deepcopy(authorization); case["permitted_action_classes"].append("PRODUCTION_CHANGE"); require_invalid(DOMAIN_IDS["authorization"], case, schemas, "production change action")
    case = copy.deepcopy(authorization); case["prohibited_action_classes"].remove("PERMISSION_WIDENING"); require_invalid(DOMAIN_IDS["authorization"], case, schemas, "omitted permission widening")
    case = copy.deepcopy(brief); case["implementation_brief_version"] = 2; require_invalid(DOMAIN_IDS["brief"], case, schemas, "silent upstream rewrite")
    case = copy.deepcopy(package); case["delete_history"] = True; require_invalid(DOMAIN_IDS["package"], case, schemas, "history deletion")
    case = copy.deepcopy(package); case["credentials"] = {"value": "fictional"}; require_invalid(DOMAIN_IDS["package"], case, schemas, "credential injection")
    case = copy.deepcopy(package); case["raw_provider_payload"] = {}; require_invalid(DOMAIN_IDS["package"], case, schemas, "raw provider payload")
    case = copy.deepcopy(brief); case["acceptance_criteria"][0]["success_metric"] = "unsupported"; require_invalid(DOMAIN_IDS["brief"], case, schemas, "unsupported metric")
    return len(names)


def main() -> None:
    schema_paths = sorted(SCHEMA_ROOT.rglob("*.schema.json"))
    schemas = {schema["$id"]: schema for path in schema_paths for schema in [load(path)]}
    if len(schema_paths) != 144 or len(schemas) != len(schema_paths):
        fail(f"schema catalog expected 144 unique IDs, found {len(schema_paths)} files/{len(schemas)} IDs")
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
        for reference in all_refs(schema):
            try:
                resolve(reference, schema, schemas)
            except (KeyError, TypeError):
                fail(f"unresolved local reference {reference} in {schema['$id']}")

    fixture = load(FIXTURE_PATH)
    values = fixture["positive"]
    for key in ("brief", "authorization", "package"):
        require_valid(DOMAIN_IDS[key], values[{"brief": "implementation_brief", "authorization": "implementation_authorization", "package": "codex_build_package"}[key]], schemas, key)

    brief, authorization, package = values["implementation_brief"], values["implementation_authorization"], values["codex_build_package"]
    if not (
        brief["tenant_id"] == authorization["tenant_id"] == package["tenant_id"]
        and brief["engagement_id"] == authorization["engagement_id"] == package["engagement_id"]
        and authorization["implementation_brief_reference"]["reference_id"] == brief["implementation_brief_id"]
        and authorization["implementation_brief_digest"] == brief["implementation_brief_digest"]
        and package["implementation_brief_reference"] == authorization["implementation_brief_reference"]
        and package["implementation_brief_digest"] == brief["implementation_brief_digest"]
        and package["implementation_authorization_reference"]["reference_id"] == authorization["implementation_authorization_id"]
        and package["implementation_authority_digest"] == authorization["implementation_authority_digest"]
    ):
        fail("exact tenant/engagement/source/digest chain is not reproducible")
    if set(brief["prohibited_changes"]) != PROHIBITED or set(authorization["prohibited_action_classes"]) != PROHIBITED or set(package["prohibited_changes"]) != PROHIBITED:
        fail("complete prohibited-change set drifted")

    payloads = build_payloads(values)
    for command, payload in payloads.items():
        require_valid(PAYLOAD_IDS[command], payload, schemas, command)
    for command in ("DraftImplementationBrief", "ProposeImplementationAuthorization", "DraftCodexBuildPackage"):
        bad = copy.deepcopy(payloads[command])
        version_key = "implementation_brief_version" if command == "DraftImplementationBrief" else "authorization_version" if command == "ProposeImplementationAuthorization" else "package_version"
        bad[version_key] = 2
        require_invalid(PAYLOAD_IDS[command], bad, schemas, command + " version widening")

    assert_command_policy(schemas)
    envelope = schemas["urn:avuhz:schema:contracts:commands:command-envelope:v1"]
    idempotency = schemas["urn:avuhz:schema:contracts:orchestration:idempotency-record:v1"]
    capability = schemas["urn:avuhz:schema:contracts:identity:capability:v1"]
    event = schemas["urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"]
    if not set(COMMANDS_5D).issubset(envelope["$defs"]["commandType"]["enum"]) or not set(COMMANDS_5D).issubset(idempotency["properties"]["command_type"]["enum"]):
        fail("command/idempotency vocabulary order drifted")
    if not set(CAPABILITIES_5D).issubset(capability["enum"]) or not set(EVENTS_5D).issubset(event["properties"]["event_type"]["enum"]):
        fail("capability/event vocabulary drifted")
    runtime_commands = COMMANDS_5D
    brief_commands = runtime_commands[:4]
    authorization_commands = runtime_commands[4:9]
    package_commands = runtime_commands[9:]
    if (
        set(COMMANDS).intersection(COMMANDS_5D) != set(runtime_commands)
        or not all(COMMANDS[command].executable for command in runtime_commands)
        or any(COMMANDS[command].subject_type != "IMPLEMENTATION_BRIEF" for command in brief_commands)
        or any(COMMANDS[command].subject_type != "IMPLEMENTATION_AUTHORIZATION" for command in authorization_commands)
        or any(COMMANDS[command].subject_type != "CODEX_BUILD_PACKAGE" for command in package_commands)
        or len(SCHEMA_FILES) != 129
    ):
        fail("Phase 5D-B3 CodexBuildPackage runtime boundary drifted")

    assert_approvals(schemas, values)
    assert_events(schemas, values)
    assert_reads(schemas, values)
    security_negative_count = assert_security_negatives(schemas, fixture, values, payloads)

    for industry in fixture["industry_examples"]:
        sample_brief = copy.deepcopy(brief)
        sample_package = copy.deepcopy(package)
        sample_brief["approved_business_problem"] = industry["problem"]
        sample_package["problem_statement"] = industry["problem"]
        sample_package["allowed_targets"][0]["target_reference_id"] = industry["target_reference"]
        require_valid(DOMAIN_IDS["brief"], sample_brief, schemas, industry["industry"] + " brief")
        require_valid(DOMAIN_IDS["package"], sample_package, schemas, industry["industry"] + " package")
    serialized_new_schemas = json.dumps([schemas[schema_id] for schema_id in schemas if "phase5d" in schema_id or any(token in schema_id for token in ("implementation-brief", "implementation-authorization", "codex-build-package"))]).lower()
    if any(vertical in serialized_new_schemas for vertical in ("roofing", "security_staffing", "medical_office")):
        fail("vertical-specific concept leaked into universal contracts")

    print(
        "phase5d implementation-package validation: PASS "
        f"(3 resources, {len(COMMANDS_5D)} commands, {len(CAPABILITIES_5D)} capabilities, "
        f"{len(EVENTS_5D)} events, 4 read models, 6 human approvals, "
        f"{security_negative_count} security negatives, 3 industries, {len(schemas)} unique schema IDs)"
    )


if __name__ == "__main__":
    main()
