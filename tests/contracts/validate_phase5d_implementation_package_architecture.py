#!/usr/bin/env python3
"""Focused provider-neutral ImplementationHandoff and Phase 5D package contracts."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
FIXTURE_PATH = ROOT / "contracts/fixtures/v1/phase5d-implementation-package.cases.json"
sys.path.insert(0, str(ROOT / "src"))
from avuhz_runtime.command_registry import COMMANDS
from avuhz_runtime.schema_registry import SCHEMA_FILES

HANDOFF_ID = "urn:avuhz:public-contract:implementation-handoff:v1"
DOMAIN_IDS = {
    "implementation_brief": "urn:avuhz:schema:contracts:domain:implementation-brief:v1",
    "implementation_authorization": "urn:avuhz:schema:contracts:domain:implementation-authorization:v1",
    "codex_build_package": "urn:avuhz:schema:contracts:domain:codex-build-package:v1",
    "approval": "urn:avuhz:schema:contracts:domain:human-approval:v1",
}
COMMANDS_5D = [
    "DraftImplementationBrief", "ReviseImplementationBrief",
    "RecordImplementationBriefApproval", "ApproveImplementationBrief",
    "ProposeImplementationAuthorization", "ReviseImplementationAuthorization",
    "RecordImplementationAuthorizationApproval", "ActivateImplementationAuthorization",
    "RevokeImplementationAuthorization", "DraftCodexBuildPackage",
    "ReviseCodexBuildPackage", "RecordCodexBuildPackageApproval",
    "ReleaseCodexBuildPackage",
]
CAPABILITIES_5D = {
    "implementation_brief:draft", "implementation_brief:approve",
    "implementation_authorization:propose", "implementation_authorization:approve",
    "implementation_authorization:activate", "implementation_authorization:revoke",
    "codex_build_package:draft", "codex_build_package:approve",
    "codex_build_package:release",
}
EVENTS_5D = {
    "implementation_brief.drafted", "implementation_brief.revised",
    "implementation_brief.approval_recorded", "implementation_brief.approved",
    "implementation_authorization.proposed", "implementation_authorization.revised",
    "implementation_authorization.approval_recorded", "implementation_authorization.activated",
    "implementation_authorization.revoked", "codex_build_package.drafted",
    "codex_build_package.revised", "codex_build_package.approval_recorded",
    "codex_build_package.released",
}
PROHIBITED = {
    "OUT_OF_SCOPE_SYSTEM_CHANGE", "PERMISSION_WIDENING", "DATA_DELETION",
    "CREDENTIAL_ROTATION", "PRODUCTION_DEPLOYMENT", "PRODUCTION_CHANGE",
    "BILLING_CHANGE", "OUT_OF_SCOPE_NETWORK_CHANGE",
    "OUT_OF_SCOPE_SECURITY_CONTROL_CHANGE",
}


def fail(message):
    print("phase5d implementation-package validation: FAIL: " + message, file=sys.stderr)
    raise SystemExit(1)


def pointer(document, fragment):
    target = document
    if not fragment:
        return target
    for part in fragment.lstrip("/").split("/"):
        target = target[part.replace("~1", "/").replace("~0", "~")]
    return target


def expand(value, document, schemas):
    if isinstance(value, dict):
        if "$ref" in value:
            reference = value["$ref"]
            if reference.startswith("#"):
                target_document, fragment = document, reference[1:]
            else:
                schema_id, separator, fragment = reference.partition("#")
                target_document = schemas[schema_id]
                fragment = fragment if separator else ""
            base = expand(copy.deepcopy(pointer(target_document, fragment)), target_document, schemas)
            return {**base, **{key: expand(child, document, schemas) for key, child in value.items() if key != "$ref"}}
        return {key: expand(child, document, schemas) for key, child in value.items()}
    if isinstance(value, list):
        return [expand(child, document, schemas) for child in value]
    return value


def valid(schema_id, value, schemas, label):
    schema = expand(schemas[schema_id], schemas[schema_id], schemas)
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value))
    if errors:
        fail(f"{label} rejected: {errors[0].message}")


def invalid(schema_id, value, schemas, label):
    schema = expand(schemas[schema_id], schemas[schema_id], schemas)
    if Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(value):
        fail(label + " was accepted")


def payloads(values):
    brief = values["implementation_brief"]
    authorization = values["implementation_authorization"]
    package = values["codex_build_package"]
    brief_omit = {"tenant_id", "engagement_id", "state", "client_approval_reference", "provider_approval_reference", "trusted_attribution", "approved_at", "record_version", "created_at", "updated_at"}
    draft_brief = {key: copy.deepcopy(value) for key, value in brief.items() if key not in brief_omit}
    revise_brief = copy.deepcopy(draft_brief)
    revise_brief.update(implementation_brief_version=2, supersedes_implementation_brief_reference={"reference_type": "IMPLEMENTATION_BRIEF", "reference_id": brief["implementation_brief_id"], "reference_version": 1})
    auth_keys = ["implementation_authorization_id", "authorization_version", "implementation_brief_reference", "implementation_brief_digest", "authorized_scope_digest", "target_references", "permitted_action_classes", "prohibited_action_classes", "effective_at", "expires_at", "implementation_authority_digest"]
    propose_auth = {key: copy.deepcopy(authorization[key]) for key in auth_keys}
    revise_auth = copy.deepcopy(propose_auth)
    revise_auth.update(authorization_version=2, supersedes_implementation_authorization_reference={"reference_type": "IMPLEMENTATION_AUTHORIZATION", "reference_id": authorization["implementation_authorization_id"], "reference_version": 1})
    package_omit = {"tenant_id", "engagement_id", "state", "client_approval_reference", "provider_approval_reference", "trusted_attribution", "released_at", "record_version", "created_at", "updated_at"}
    draft_package = {key: copy.deepcopy(value) for key, value in package.items() if key not in package_omit}
    revise_package = copy.deepcopy(draft_package)
    revise_package.update(package_version=2, supersedes_codex_build_package_reference={"reference_type": "CODEX_BUILD_PACKAGE", "reference_id": package["codex_build_package_id"], "reference_version": 1})
    return {
        "DraftImplementationBrief": draft_brief,
        "ReviseImplementationBrief": revise_brief,
        "RecordImplementationBriefApproval": {"subject_version": 1, "authority_role": "CLIENT_IMPLEMENTATION_AUTHORITY", "authority_digest": brief["implementation_brief_digest"]},
        "ApproveImplementationBrief": {"implementation_brief_id": brief["implementation_brief_id"], "implementation_brief_version": 1, "client_approval_reference": brief["client_approval_reference"], "provider_approval_reference": brief["provider_approval_reference"], "implementation_brief_digest": brief["implementation_brief_digest"]},
        "ProposeImplementationAuthorization": propose_auth,
        "ReviseImplementationAuthorization": revise_auth,
        "RecordImplementationAuthorizationApproval": {"subject_version": 1, "authority_role": "CLIENT_IMPLEMENTATION_AUTHORITY", "authority_digest": authorization["implementation_authority_digest"]},
        "ActivateImplementationAuthorization": {"implementation_authorization_id": authorization["implementation_authorization_id"], "authorization_version": 1, "client_approval_reference": authorization["client_approval_reference"], "provider_approval_reference": authorization["provider_approval_reference"], "implementation_authority_digest": authorization["implementation_authority_digest"]},
        "RevokeImplementationAuthorization": {"implementation_authorization_id": authorization["implementation_authorization_id"], "revocation_reason": "SECURITY_CONCERN"},
        "DraftCodexBuildPackage": draft_package,
        "ReviseCodexBuildPackage": revise_package,
        "RecordCodexBuildPackageApproval": {"subject_version": 1, "authority_role": "CLIENT_IMPLEMENTATION_AUTHORITY", "authority_digest": package["package_digest"]},
        "ReleaseCodexBuildPackage": {"codex_build_package_id": package["codex_build_package_id"], "package_version": 1, "client_approval_reference": package["client_approval_reference"], "provider_approval_reference": package["provider_approval_reference"], "package_digest": package["package_digest"]},
    }


def main():
    schemas = {}
    for path in sorted(SCHEMA_ROOT.rglob("*.schema.json")):
        schema = json.loads(path.read_text())
        Draft202012Validator.check_schema(schema)
        if schema["$id"] in schemas:
            fail("duplicate schema ID " + schema["$id"])
        schemas[schema["$id"]] = schema
    for required in (HANDOFF_ID, *DOMAIN_IDS.values()):
        if required not in schemas:
            fail("missing required schema " + required)
    if "public/implementation-handoff.schema.json" not in SCHEMA_FILES:
        fail("public handoff is absent from the local schema catalog")

    values = json.loads(FIXTURE_PATH.read_text())["positive"]
    valid(HANDOFF_ID, values["implementation_handoff"], schemas, "ImplementationHandoff")
    for key in ("implementation_brief", "implementation_authorization", "codex_build_package"):
        valid(DOMAIN_IDS[key], values[key], schemas, key)

    handoff = values["implementation_handoff"]
    brief = values["implementation_brief"]
    authorization = values["implementation_authorization"]
    package = values["codex_build_package"]
    exact_handoff = {
        "reference_type": "IMPLEMENTATION_HANDOFF",
        "reference_id": handoff["implementation_handoff_id"],
        "reference_version": handoff["handoff_version"],
        "reference_digest": handoff["handoff_digest"],
    }
    if (brief["source_implementation_handoff_reference"] != exact_handoff
            or authorization["source_implementation_handoff_reference"] != exact_handoff
            or authorization["implementation_brief_digest"] != brief["implementation_brief_digest"]
            or package["implementation_brief_digest"] != brief["implementation_brief_digest"]
            or package["implementation_authority_digest"] != authorization["implementation_authority_digest"]):
        fail("exact handoff-to-execution source/digest chain is not reproducible")
    if not (set(brief["prohibited_changes"]) == set(authorization["prohibited_action_classes"]) == set(package["prohibited_changes"]) == PROHIBITED):
        fail("complete prohibited-change boundary drifted")

    command_payloads = payloads(values)
    for command, payload in command_payloads.items():
        schema_id = COMMANDS[command].payload_schema_id
        valid(schema_id, payload, schemas, command)
        if COMMANDS[command].required_capability not in CAPABILITIES_5D:
            fail("capability drifted for " + command)
    envelope = schemas["urn:avuhz:schema:contracts:commands:command-envelope:v1"]
    lifecycle = schemas["urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"]
    if not set(COMMANDS_5D) <= set(envelope["$defs"]["commandType"]["enum"]):
        fail("command vocabulary drifted")
    if not EVENTS_5D <= set(lifecycle["properties"]["event_type"]["enum"]):
        fail("event vocabulary drifted")

    # Contract negatives: private methodology, mutable latest, authority widening,
    # raw payloads, credentials, and caller-created deployment truth stay outside.
    case = copy.deepcopy(handoff); case["oia_assessment_id"] = "private"; invalid(HANDOFF_ID, case, schemas, "private domain field")
    case = copy.deepcopy(brief); case["latest_handoff_reference"] = "latest"; invalid(DOMAIN_IDS["implementation_brief"], case, schemas, "latest handoff shortcut")
    case = copy.deepcopy(brief); case["source_implementation_handoff_reference"]["reference_type"] = "OIA_FINDING"; invalid(DOMAIN_IDS["implementation_brief"], case, schemas, "private source type")
    case = copy.deepcopy(authorization); case["permitted_action_classes"].append("PRODUCTION_CHANGE"); invalid(DOMAIN_IDS["implementation_authorization"], case, schemas, "production authority widening")
    case = copy.deepcopy(authorization); case["prohibited_action_classes"].remove("PERMISSION_WIDENING"); invalid(DOMAIN_IDS["implementation_authorization"], case, schemas, "prohibited-change weakening")
    for field in ("credentials", "raw_provider_payload", "deployment_allowed"):
        case = copy.deepcopy(package); case[field] = {} if field != "deployment_allowed" else True
        invalid(DOMAIN_IDS["codex_build_package"], case, schemas, field)

    print(f"phase5d implementation-package validation: PASS (ImplementationHandoff + 3 execution resources, {len(COMMANDS_5D)} commands, {len(schemas)} unique schema IDs)")


if __name__ == "__main__":
    main()
