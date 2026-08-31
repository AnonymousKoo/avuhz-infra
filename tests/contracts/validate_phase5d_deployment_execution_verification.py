#!/usr/bin/env python3
"""Validate frozen Phase 5D-D5 deployment execution and verification contracts."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.command_registry import COMMANDS
from avuhz_runtime.schema_registry import SCHEMA_FILES

COMMANDS_D5 = {
    "StartDeploymentExecution",
    "CompleteDeploymentExecution",
    "RecordDeploymentVerification",
}
CAPABILITIES_D5 = {
    "deployment_execution:start",
    "deployment_execution:complete",
    "deployment_verification:record",
}
EVENTS_D5 = {
    "deployment_execution.started",
    "deployment_execution.completed",
    "deployment_verification.recorded",
}
SUBJECTS_D5 = {"DEPLOYMENT_EXECUTION", "DEPLOYMENT_VERIFICATION"}
DOMAIN_EXECUTION = "urn:avuhz:schema:contracts:domain:deployment-execution:v1"
DOMAIN_VERIFICATION = "urn:avuhz:schema:contracts:domain:deployment-verification:v1"
START_PAYLOAD = "urn:avuhz:schema:contracts:commands:start-deployment-execution-payload:v1"
COMPLETE_PAYLOAD = "urn:avuhz:schema:contracts:commands:complete-deployment-execution-payload:v1"
VERIFY_PAYLOAD = "urn:avuhz:schema:contracts:commands:record-deployment-verification-payload:v1"
EXECUTION_VIEW = "urn:avuhz:schema:contracts:read-models:deployment-execution-status-view:v1"
VERIFICATION_VIEW = "urn:avuhz:schema:contracts:read-models:deployment-verification-status-view:v1"


def fail(message):
    print("phase5d-d5 validation: FAIL: " + message, file=sys.stderr)
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
            schema_id, separator, fragment = reference.partition("#")
            target_document = document if not schema_id else schemas[schema_id]
            base = expand(copy.deepcopy(pointer(target_document, fragment if separator else "")), target_document, schemas)
            return {**base, **{key: expand(child, document, schemas) for key, child in value.items() if key != "$ref"}}
        return {key: expand(child, document, schemas) for key, child in value.items()}
    if isinstance(value, list):
        return [expand(child, document, schemas) for child in value]
    return value


def validator(schema_id, schemas):
    return Draft202012Validator(
        expand(schemas[schema_id], schemas[schema_id], schemas),
        format_checker=FormatChecker(),
    )


def valid(schema_id, value, schemas, label):
    errors = list(validator(schema_id, schemas).iter_errors(value))
    if errors:
        fail(label + ": " + "; ".join(error.message for error in errors[:4]))


def invalid(schema_id, value, schemas, label):
    if validator(schema_id, schemas).is_valid(value):
        fail(label + " was accepted")


def ref(kind, identity, version=1):
    return {"reference_type": kind, "reference_id": identity, "reference_version": version}


def digest(character):
    return "sha256:" + character * 64


def evidence(suffix, kind="DEPLOYMENT_OPERATION"):
    return {
        "evidence_reference_id": f"evidence.{suffix}",
        "evidence_class": kind,
        "evidence_digest": digest(suffix[-1]),
        "provenance_reference": f"provenance.{suffix}",
    }


def authority_binding(target):
    return {
        "deployment_authorization_reference": ref("DEPLOYMENT_AUTHORIZATION", "d5d00000-0000-4000-8000-000000000001"),
        "deployment_authority_digest": digest("1"),
        "implementation_authorization_reference": ref("IMPLEMENTATION_AUTHORIZATION", "d5d00000-0000-4000-8000-000000000002"),
        "implementation_authority_digest": digest("2"),
        "codex_build_package_reference": ref("CODEX_BUILD_PACKAGE", "d5d00000-0000-4000-8000-000000000003"),
        "package_digest": digest("3"),
        "build_execution_reference": ref("BUILD_EXECUTION_RESULT", "d5d00000-0000-4000-8000-000000000004"),
        "build_execution_digest": digest("4"),
        "qa_result_reference": ref("QA_RESULT", "d5d00000-0000-4000-8000-000000000005"),
        "qa_result_digest": digest("5"),
        "client_acceptance_reference": ref("CLIENT_ACCEPTANCE", "d5d00000-0000-4000-8000-000000000006"),
        "client_acceptance_digest": digest("6"),
        "artifact_reference": {
            "artifact_reference_id": "artifact.release.1",
            "artifact_class": "CONTAINER_IMAGE",
            "artifact_version": "1.0.0",
            "artifact_digest": digest("a"),
        },
        "target_environment": "PRODUCTION",
        "target_resources": [target],
    }


def target_outcome(target, outcome="APPLIED"):
    return {
        "target_resource": copy.deepcopy(target),
        "outcome": outcome,
        "evidence_references": [evidence("operation.1")],
        "detail": "Bounded fictional operation evidence.",
    }


def target_verification(target, result="MATCHED"):
    value = {
        "target_resource": copy.deepcopy(target),
        "result": result,
        "expected_artifact_digest": digest("a"),
        "evidence_references": [evidence("state.1", "TARGET_STATE")],
        "detail": "Bounded fictional observed state.",
        "verified_at": "2026-08-31T15:15:00Z",
    }
    if result != "BLOCKED":
        value["observed_artifact_digest"] = digest("a" if result == "MATCHED" else "b")
        value["observed_state_fingerprint"] = "fpv1:fictionalstate0001"
    return value


def execution_example(target, outcome="APPLIED"):
    return {
        "deployment_execution_id": "d5d00000-0000-4000-8000-000000000007",
        "execution_attempt": 1,
        "tenant_id": "d5d00000-0000-4000-8000-000000000008",
        "engagement_id": "d5d00000-0000-4000-8000-000000000009",
        "authority_binding": authority_binding(target),
        "execution_action": "DEPLOY_EXACT_ARTIFACT",
        "status": "SUCCEEDED",
        "execution_fingerprint": "fpv1:fictionaldeploy0001",
        "target_outcomes": [target_outcome(target, outcome)],
        "completion_summary": "Exact bounded deployment operation completed.",
        "rollback_disposition": "PENDING_VERIFICATION",
        "execution_digest": digest("7"),
        "attribution": {
            "principal_reference": "service.deployer",
            "caller_type": "INTERNAL_SERVICE",
            "recorded_by": "service.command",
        },
        "started_at": "2026-08-31T15:00:00Z",
        "completed_at": "2026-08-31T15:10:00Z",
        "record_version": 2,
        "created_at": "2026-08-31T15:00:00Z",
        "updated_at": "2026-08-31T15:10:00Z",
    }


def verification_example(target, result="MATCHED"):
    return {
        "deployment_verification_id": "d5d00000-0000-4000-8000-000000000010",
        "verification_attempt": 1,
        "tenant_id": "d5d00000-0000-4000-8000-000000000008",
        "engagement_id": "d5d00000-0000-4000-8000-000000000009",
        "deployment_execution_reference": ref("DEPLOYMENT_EXECUTION", "d5d00000-0000-4000-8000-000000000007"),
        "deployment_execution_digest": digest("7"),
        "execution_status": "SUCCEEDED",
        "authority_binding": authority_binding(target),
        "target_verifications": [target_verification(target, result)],
        "overall_status": "VERIFIED",
        "rollback_required": False,
        "verification_digest": digest("8"),
        "attribution": {
            "principal_reference": "service.verifier",
            "caller_type": "INTERNAL_SERVICE",
            "recorded_by": "service.command",
        },
        "recorded_at": "2026-08-31T15:15:00Z",
        "record_version": 1,
        "created_at": "2026-08-31T15:15:00Z",
        "updated_at": "2026-08-31T15:15:00Z",
    }


def derive_execution(outcomes):
    values = [item["outcome"] for item in outcomes]
    if all(value in {"APPLIED", "UNCHANGED"} for value in values):
        return "SUCCEEDED", "PENDING_VERIFICATION"
    if "APPLIED" in values:
        return "PARTIAL", "REQUIRED"
    if "FAILED" in values:
        return "FAILED", "NOT_REQUIRED"
    return "BLOCKED", "NOT_REQUIRED"


def derive_verification(results):
    values = [item["result"] for item in results]
    if all(value == "MATCHED" for value in values):
        return "VERIFIED", False
    if "MISMATCHED" in values:
        return "FAILED", True
    if "MATCHED" in values:
        return "PARTIAL", True
    return "BLOCKED", True


def exact_target_set(items, field, authorized_targets):
    observed = [json.dumps(item[field], sort_keys=True) for item in items]
    authorized = [json.dumps(item, sort_keys=True) for item in authorized_targets]
    return len(observed) == len(set(observed)) == len(authorized) and set(observed) == set(authorized)


def execution_truth_consistent(record):
    return (
        exact_target_set(record["target_outcomes"], "target_resource", record["authority_binding"]["target_resources"])
        and derive_execution(record["target_outcomes"]) == (record["status"], record["rollback_disposition"])
    )


def verification_truth_consistent(record):
    return (
        exact_target_set(record["target_verifications"], "target_resource", record["authority_binding"]["target_resources"])
        and derive_verification(record["target_verifications"]) == (record["overall_status"], record["rollback_required"])
        and all(
            item.get("observed_artifact_digest") == record["authority_binding"]["artifact_reference"]["artifact_digest"]
            for item in record["target_verifications"] if item["result"] == "MATCHED"
        )
    )


def exact_authority(deployment_authorization, binding, action, now, tenant_id=None, engagement_id=None):
    return bool(
        (tenant_id is None or deployment_authorization["tenant_id"] == tenant_id)
        and (engagement_id is None or deployment_authorization["engagement_id"] == engagement_id)
        and deployment_authorization["state"] == "ACTIVE"
        and deployment_authorization["effective_at"] <= now < deployment_authorization["expires_at"]
        and binding["deployment_authorization_reference"]
        == ref("DEPLOYMENT_AUTHORIZATION", deployment_authorization["deployment_authorization_id"], deployment_authorization["authorization_version"])
        and binding["deployment_authority_digest"] == deployment_authorization["deployment_authority_digest"]
        and all(binding[field] == deployment_authorization[field] for field in (
            "implementation_authorization_reference", "implementation_authority_digest",
            "codex_build_package_reference", "package_digest", "build_execution_reference",
            "build_execution_digest", "qa_result_reference", "qa_result_digest",
            "client_acceptance_reference", "client_acceptance_digest", "artifact_reference",
            "target_environment", "target_resources",
        ))
        and action in deployment_authorization["permitted_deployment_actions"]
    )


def main():
    schemas = {}
    schema_paths = sorted(SCHEMA_ROOT.rglob("*.schema.json"))
    for path in schema_paths:
        schema = json.loads(path.read_text())
        Draft202012Validator.check_schema(schema)
        if schema["$id"] in schemas:
            fail("duplicate schema ID")
        schemas[schema["$id"]] = schema
    for schema in schemas.values():
        for reference in refs(schema):
            if reference.startswith(("http:", "https:")):
                fail("remote schema reference")
            schema_id = reference.partition("#")[0]
            if schema_id and schema_id not in schemas:
                fail("unresolved schema reference " + reference)

    required = {DOMAIN_EXECUTION, DOMAIN_VERIFICATION, START_PAYLOAD, COMPLETE_PAYLOAD, VERIFY_PAYLOAD, EXECUTION_VIEW, VERIFICATION_VIEW}
    if not required <= schemas.keys():
        fail("D5 schema surface incomplete")

    fixture = json.loads((ROOT / "contracts/fixtures/v1/phase5d-deployment-execution-verification.cases.json").read_text())
    if not fixture.get("fictional_only") or len(fixture.get("industries", [])) != 3 or len(fixture.get("required_negatives", [])) < 15:
        fail("D5 deterministic fixture coverage incomplete")

    for industry in fixture["industries"]:
        target = {"target_reference_id": industry["target_reference_id"], "target_class": industry["target_class"]}
        execution = execution_example(target)
        verification = verification_example(target)
        valid(DOMAIN_EXECUTION, execution, schemas, industry["name"] + " execution")
        valid(DOMAIN_VERIFICATION, verification, schemas, industry["name"] + " verification")

    target = {"target_reference_id": "service.application", "target_class": "SERVICE"}
    execution = execution_example(target)
    verification = verification_example(target)
    binding = authority_binding(target)
    start = {
        "execution_attempt": 1,
        "authority_binding": binding,
        "execution_action": "DEPLOY_EXACT_ARTIFACT",
        "execution_fingerprint": "fpv1:fictionaldeploy0001",
    }
    complete = {
        "execution_attempt": 1,
        "target_outcomes": [target_outcome(target)],
        "completion_summary": "Exact bounded deployment operation completed.",
    }
    record_verification = {
        "verification_attempt": 1,
        "deployment_execution_reference": verification["deployment_execution_reference"],
        "deployment_execution_digest": verification["deployment_execution_digest"],
        "authority_binding": binding,
        "target_verifications": verification["target_verifications"],
    }
    valid(START_PAYLOAD, start, schemas, "start payload")
    valid(COMPLETE_PAYLOAD, complete, schemas, "complete payload")
    valid(VERIFY_PAYLOAD, record_verification, schemas, "verification payload")
    rollback_start = copy.deepcopy(start)
    rollback_start["execution_action"] = "ROLLBACK_EXACT_ARTIFACT"
    rollback_start["rollback_of_deployment_execution_reference"] = ref("DEPLOYMENT_EXECUTION", execution["deployment_execution_id"])
    valid(START_PAYLOAD, rollback_start, schemas, "exact rollback payload")

    execution_view = {
        "deployment_execution_reference": verification["deployment_execution_reference"],
        "deployment_authorization_reference": binding["deployment_authorization_reference"],
        "status": "SUCCEEDED",
        "operation_completed": True,
        "deployment_verified": False,
        "rollback_disposition": "PENDING_VERIFICATION",
        "tenant_id": execution["tenant_id"],
        "engagement_id": execution["engagement_id"],
        "generated_at": "2026-08-31T15:16:00Z",
    }
    verification_view = {
        "deployment_verification_reference": ref("DEPLOYMENT_VERIFICATION", verification["deployment_verification_id"]),
        "deployment_execution_reference": verification["deployment_execution_reference"],
        "deployment_authorization_reference": binding["deployment_authorization_reference"],
        "overall_status": "VERIFIED",
        "target_state_matches_authority": True,
        "deployment_verified": True,
        "rollback_required": False,
        "tenant_id": execution["tenant_id"],
        "engagement_id": execution["engagement_id"],
        "generated_at": "2026-08-31T15:16:00Z",
    }
    valid(EXECUTION_VIEW, execution_view, schemas, "execution status view")
    valid(VERIFICATION_VIEW, verification_view, schemas, "verification status view")
    bad_view = copy.deepcopy(execution_view)
    bad_view["deployment_verified"] = True
    invalid(EXECUTION_VIEW, bad_view, schemas, "execution view treated as verification")
    bad_view = copy.deepcopy(verification_view)
    bad_view["deployment_verified"] = False
    invalid(VERIFICATION_VIEW, bad_view, schemas, "verified view with false deployment truth")

    # Closed schema security and anti-shortcut negatives.
    for schema_id, value, field in (
        (DOMAIN_EXECUTION, execution, "deployment_succeeded"),
        (DOMAIN_EXECUTION, execution, "raw_provider_payload"),
        (DOMAIN_VERIFICATION, verification, "verification_passed"),
        (DOMAIN_VERIFICATION, verification, "credentials"),
        (START_PAYLOAD, start, "approved"),
        (COMPLETE_PAYLOAD, complete, "success"),
        (VERIFY_PAYLOAD, record_verification, "verified"),
    ):
        bad = copy.deepcopy(value)
        bad[field] = True
        invalid(schema_id, bad, schemas, "forbidden " + field)

    bad = copy.deepcopy(execution)
    del bad["authority_binding"]["client_acceptance_digest"]
    invalid(DOMAIN_EXECUTION, bad, schemas, "missing upstream digest")
    bad = copy.deepcopy(verification)
    bad["deployment_execution_reference"]["reference_type"] = "BUILD_EXECUTION_RESULT"
    invalid(DOMAIN_VERIFICATION, bad, schemas, "wrong execution reference type")
    bad = copy.deepcopy(verification)
    bad["overall_status"] = "FAILED"
    invalid(DOMAIN_VERIFICATION, bad, schemas, "rollback false for failed verification")
    bad = copy.deepcopy(start)
    bad["execution_action"] = "ROLLBACK_EXACT_ARTIFACT"
    invalid(START_PAYLOAD, bad, schemas, "rollback without correction binding")

    if not execution_truth_consistent(execution):
        fail("execution truth not derived from exact outcomes")
    if not verification_truth_consistent(verification):
        fail("verification truth not derived from exact observed state")
    inconsistent = copy.deepcopy(execution)
    inconsistent["status"] = "FAILED"
    inconsistent["rollback_disposition"] = "NOT_REQUIRED"
    if execution_truth_consistent(inconsistent):
        fail("caller-selected execution failure/success was accepted")
    duplicate = copy.deepcopy(execution)
    duplicate["target_outcomes"].append(copy.deepcopy(duplicate["target_outcomes"][0]))
    duplicate["target_outcomes"][1]["detail"] = "Duplicate target with changed detail."
    if execution_truth_consistent(duplicate):
        fail("duplicate execution target accepted")
    mismatched = copy.deepcopy(verification)
    mismatched["target_verifications"] = [target_verification(target, "MISMATCHED")]
    if verification_truth_consistent(mismatched):
        fail("mismatched target accepted as verified")
    if derive_verification(mismatched["target_verifications"]) != ("FAILED", True):
        fail("verification mismatch did not require rollback")
    duplicate = copy.deepcopy(verification)
    duplicate["target_verifications"].append(copy.deepcopy(duplicate["target_verifications"][0]))
    duplicate["target_verifications"][1]["detail"] = "Duplicate target with changed detail."
    if verification_truth_consistent(duplicate):
        fail("duplicate verification target accepted")

    deployment_authorization = {
        "deployment_authorization_id": binding["deployment_authorization_reference"]["reference_id"],
        "authorization_version": 1,
        "deployment_authority_digest": binding["deployment_authority_digest"],
        "tenant_id": execution["tenant_id"],
        "engagement_id": execution["engagement_id"],
        "state": "ACTIVE",
        "effective_at": "2026-08-31T14:00:00Z",
        "expires_at": "2026-08-31T16:00:00Z",
        "permitted_deployment_actions": ["DEPLOY_EXACT_ARTIFACT", "ROLLBACK_EXACT_ARTIFACT"],
        **{field: copy.deepcopy(binding[field]) for field in (
            "implementation_authorization_reference", "implementation_authority_digest",
            "codex_build_package_reference", "package_digest", "build_execution_reference",
            "build_execution_digest", "qa_result_reference", "qa_result_digest",
            "client_acceptance_reference", "client_acceptance_digest", "artifact_reference",
            "target_environment", "target_resources",
        )},
    }
    if not exact_authority(deployment_authorization, binding, "DEPLOY_EXACT_ARTIFACT", "2026-08-31T15:00:00Z", execution["tenant_id"], execution["engagement_id"]):
        fail("exact active authority rejected")
    if exact_authority(deployment_authorization, binding, "DEPLOY_EXACT_ARTIFACT", "2026-08-31T15:00:00Z", "d5d00000-0000-4000-8000-000000000099", execution["engagement_id"]):
        fail("cross-tenant authority accepted")
    for label, mutation in (
        ("revoked authority", lambda auth, bound: auth.__setitem__("state", "REVOKED")),
        ("expired authority", lambda auth, bound: auth.__setitem__("expires_at", "2026-08-31T14:59:59Z")),
        ("wrong authority digest", lambda auth, bound: bound.__setitem__("deployment_authority_digest", digest("9"))),
        ("wrong upstream digest", lambda auth, bound: bound.__setitem__("qa_result_digest", digest("9"))),
        ("wrong artifact", lambda auth, bound: bound["artifact_reference"].__setitem__("artifact_digest", digest("9"))),
        ("wrong target", lambda auth, bound: bound.__setitem__("target_resources", [{"target_reference_id": "service.other", "target_class": "SERVICE"}])),
    ):
        auth = copy.deepcopy(deployment_authorization)
        bound = copy.deepcopy(binding)
        mutation(auth, bound)
        if exact_authority(auth, bound, "DEPLOY_EXACT_ARTIFACT", "2026-08-31T15:00:00Z"):
            fail(label + " accepted")
    if exact_authority(deployment_authorization, binding, "DELETE_DATA", "2026-08-31T15:00:00Z"):
        fail("unauthorized deployment action accepted")

    envelope = schemas["urn:avuhz:schema:contracts:commands:command-envelope:v1"]
    idempotency = schemas["urn:avuhz:schema:contracts:orchestration:idempotency-record:v1"]
    capability = schemas["urn:avuhz:schema:contracts:identity:capability:v1"]
    lifecycle = schemas["urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"]
    references = schemas["urn:avuhz:schema:contracts:common:references:v1"]
    if not COMMANDS_D5 <= set(envelope["$defs"]["commandType"]["enum"]):
        fail("command vocabulary incomplete")
    if not COMMANDS_D5 <= set(idempotency["properties"]["command_type"]["enum"]):
        fail("idempotency vocabulary incomplete")
    if not SUBJECTS_D5 <= set(envelope["$defs"]["subjectType"]["enum"]):
        fail("subject vocabulary incomplete")
    if not SUBJECTS_D5 <= set(references["$defs"]["internalReferenceType"]["enum"]):
        fail("reference vocabulary incomplete")
    if not CAPABILITIES_D5 <= set(capability["enum"]):
        fail("capability vocabulary incomplete")
    if not EVENTS_D5 <= set(lifecycle["properties"]["event_type"]["enum"]):
        fail("event vocabulary incomplete")
    completion_branches = [
        branch for branch in envelope["$defs"]["envelopeCore"]["allOf"]
        if branch.get("if", {}).get("properties", {}).get("command_type", {}).get("const") == "CompleteDeploymentExecution"
    ]
    if len(completion_branches) != 1 or "expected_record_version" not in completion_branches[0]["then"].get("required", []):
        fail("completion expected-version contract missing")

    retry = copy.deepcopy(start)
    retry["execution_attempt"] = 2
    invalid(START_PAYLOAD, retry, schemas, "retry without exact supersedes reference")
    retest = copy.deepcopy(record_verification)
    retest["verification_attempt"] = 2
    invalid(VERIFY_PAYLOAD, retest, schemas, "retest without exact supersedes reference")

    # D5a activation boundary: execution is active; verification remains contract-only.
    active_commands = {"StartDeploymentExecution", "CompleteDeploymentExecution"}
    if not active_commands <= set(COMMANDS) or "RecordDeploymentVerification" in COMMANDS:
        fail("D5a execution-only command boundary drifted")
    active_schema_files = {
        "domain/deployment-execution.schema.json",
        "domain/phase5d-deployment-execution-common.schema.json",
        "commands/start-deployment-execution.payload.schema.json",
        "commands/complete-deployment-execution.payload.schema.json",
        "read-models/deployment-execution-status-view.schema.json",
    }
    inactive_verification_files = {
        "domain/deployment-verification.schema.json",
        "commands/record-deployment-verification.payload.schema.json",
        "read-models/deployment-verification-status-view.schema.json",
    }
    if not active_schema_files <= set(SCHEMA_FILES) or inactive_verification_files & set(SCHEMA_FILES):
        fail("D5a execution/D5b verification runtime schema boundary drifted")
    migration_text = "\n".join(path.read_text().lower() for path in (ROOT / "supabase/migrations").glob("*.sql"))
    if "avuhz_deployment_executions" not in migration_text or "avuhz_deployment_verifications" in migration_text:
        fail("D5a execution-only persistence boundary drifted")
    if not (ROOT / "src/avuhz_runtime/phase5d_deployment_execution.py").exists():
        fail("D5a runtime module missing")
    if any((ROOT / "src/avuhz_runtime" / name).exists() for name in (
        "phase5d_deployment_verification.py", "postgres_phase5d_deployment_verification.py",
    )):
        fail("D5b verification runtime was implemented")

    architecture = (ROOT / "docs/phase5d-deployment-execution-verification-architecture.md").read_text()
    for phrase in (
        "DeploymentAuthorization ACTIVE != deployment started",
        "DeploymentExecution SUCCEEDED != deployed state verified",
        "Rollback requirement is fail-closed and derived",
        "runtime command and resource-schema registries",
        "No human payload, workload, or AI may invent operation success",
    ):
        if phrase not in architecture:
            fail("architecture rule missing: " + phrase)
    new_contract_text = architecture.lower() + "\n" + "\n".join(json.dumps(schemas[schema_id]).lower() for schema_id in required)
    if any(term in new_contract_text for term in ("sekinfra", "oiaassessment", "oiafinding")):
        fail("company/domain-specific concept in D5 boundary")

    print(
        "phase5d-d5 validation: PASS "
        "(2 resources, 3 commands, 3 capabilities, 3 events, 2 read models, "
        "3 industries, exact authority/rollback/security negatives, D5a execution-only runtime boundary)"
    )


def refs(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref":
                yield child
            yield from refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from refs(child)


if __name__ == "__main__":
    main()
