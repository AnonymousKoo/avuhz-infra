#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import approval_digest, initial_progress, plan_digest, progress_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v3-prewindow-key-retirement-v1"
V3 = "development-implementation-handoff-provider-adapter-positive-auth-v3"
PLAN_ID = "2f0af2ef-f17b-544e-9be0-22498b3c628a"
PLAN_DIGEST = "sha256:4b70a82966dad56ca9ff4c9c680356dbfa6bba48a71acc3780655a84da15ff2b"
RESOURCE_ID = "e2d11393-67b2-59f1-b97b-bd9d39ebe915"
RESOURCE_DIGEST = "sha256:145f0a22b3d231f434d40f9b45c53299c8a422b469e790580080ee3aaada0c86"
INCIDENT_DIGEST = "sha256:38bd6282b4da2453e100335b5666cb7edac65d8d91216b6e175315b7d99ac39a"
PREP_DIGEST = "sha256:7e3de3bac50715a112448f97c8b3f24ecadb5b01456f76aca8d670d7265b04ed"
PROGRESS_ID = "a6685fa8-651e-57d3-9c65-f766ba4a41fa"
PROGRESS_DIGEST = "sha256:54e65db1c2a3a84b3c19d233072df1488eba1ca320610f9f6054c9a2ab46a1ae"
CREATED_AT = "2026-10-04T20:31:26Z"
INCIDENT_OBSERVED_AT = "2026-10-04T20:29:41Z"
WINDOW_START = "2026-10-04T21:00:00Z"
WINDOW_END = "2026-10-05T01:00:00Z"
V3_WINDOW_START = "2026-10-04T20:30:00Z"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
KEY = "impl_handoff_provider_adapter_positive_auth_v3_ephemeral"
GH = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V3_EPHEMERAL"
V3_PLAN_ID = "8a31fb79-9e7e-53d8-b0b0-f14b611da37a"
V3_PLAN_DIGEST = "sha256:9d6ce4ff12450657dcda89650fe7b3207db6f179794cfb48eff8ebb81ad143d9"
V3_APPROVAL_ID = "f69cb520-1336-5281-ae51-13bdb242ee7d"
V3_APPROVAL_DIGEST = "sha256:e79e433af146c5260368087833e56ce98f16babc018ccd477515f0fc09a8b672"
APPROVAL_ID = "fd049de5-92fb-549c-b918-66cd1509d600"
APPROVAL_DIGEST = "sha256:229c3617af12c6ffad91b261364beb8ed46a71ae7936ebf080186c8471783a18"
APPROVAL_FILE_DIGEST = "sha256:dcaf061267208e9fec4f376b53b43cd0254613b217ba9b9285511fcfe019f392"
APPROVED_AT = "2026-10-04T20:43:25Z"
STEP1_RECORDED_AT = "2026-10-04T21:13:21Z"
STEP1_EVIDENCE_DIGEST = "sha256:23791e31d64420458293042c433cc4c52fe20040bddbc4de78e7f783ebd4f3a2"
STEP1_AUTHORIZATION_DIGEST = "sha256:db8b09adc9d217efd22315d09fd151bf230f3ddc708f1a38601277989a04b37f"
STEP1_RESULT_DIGEST = "sha256:5a4c1d7c0d5d56f89f9f63560b6b328e36483b7a3e4ff5825caf22c3d30bfbcd"
EXECUTION_PROGRESS_DIGEST = "sha256:5ac3af0f64d33027fd62b54a5c4c34d8a2255dc94f377080225b03034655c143"
STEP3_RECORDED_AT = "2026-10-04T21:35:17Z"
STEP3_EVIDENCE_DIGEST = "sha256:8fe9637d3b9c559063eca8e732a7b3a07b694d696a44315f3ac8eca24dd2c5bd"
STEP3_AUTHORIZATION_DIGEST = "sha256:c77d5d601bef711d7a8418ef992fc0053d52e279d9fa041c5e3497908d7a7ca7"
STEP3_RESULT_DIGEST = "sha256:78bbbe00772ae965b5dc9d3c0c8cbb62f7c18d0add36a7018c750849966a86e8"
STEP2_RECORDED_AT = "2026-10-04T21:25:51Z"
STEP2_EVIDENCE_DIGEST = "sha256:aca3e9d6fc8532cf1e0368bb2b9cfd8dc2bc42d99fc4b7836d90b6752957c495"
STEP2_AUTHORIZATION_DIGEST = "sha256:df63ff6ca2232bf9e916fdcc0e1bd5101aadcd5cec661df2de55a87df16a4854"
STEP2_RESULT_DIGEST = "sha256:31e72736f5991a9f375ddbba2ab08460a2be112a60bee0369dea2c39f31323c6"


def load(name: str) -> dict:
    value = json.loads((B / name).read_text())
    assert isinstance(value, dict)
    return value


def raw(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    incident = load(N + "-incident.evidence.json")
    resource = load(N + ".resource.json")
    prep = load(N + "-preparation.evidence.json")
    plan = load(N + ".plan.json")
    progress = load(N + ".progress.json")
    approval = load(N + ".approval.json")
    step1_success = load(N + "-step1-success.evidence.json")
    step2_success = load(N + "-step2-success.evidence.json")
    step3_success = load(N + "-step3-success.evidence.json")
    execution = load(N + ".execution-progress.json")
    v3_plan = load(V3 + ".plan.json")
    v3_approval = load(V3 + ".approval.json")

    validate_plan(plan, S)
    validate_progress(plan, progress, S)
    validate_approval(plan, approval, S, WINDOW_START)
    validate_progress(plan, execution, S)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 1
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["created_at"] == CREATED_AT
    assert plan["authorization_window"] == {"binding_state":"BOUND","starts_at":WINDOW_START,"expires_at":WINDOW_END}
    assert raw(B / (N + ".approval.json")) == APPROVAL_FILE_DIGEST
    assert approval["approval_id"] == APPROVAL_ID
    assert approval["plan_id"] == PLAN_ID and approval["plan_version"] == 1 and approval["plan_digest"] == PLAN_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo" and approval["decision"] == "APPROVE"
    assert approval["environment"] == "DEVELOPMENT" and approval["authority_scope"] == "EXACT_PLAN_ONLY"
    assert approval["effective_at"] == WINDOW_START and approval["expires_at"] == WINDOW_END
    assert approval["approved_at"] == APPROVED_AT and approval["status"] == "ACTIVE"
    assert approval["approval_digest"] == APPROVAL_DIGEST == approval_digest(approval)
    assert APPROVED_AT < WINDOW_START
    assert raw(B / (N + "-step1-success.evidence.json")) == STEP1_EVIDENCE_DIGEST
    assert execution["progress_digest"] == EXECUTION_PROGRESS_DIGEST == progress_digest(execution)
    assert execution["overall_state"] == "COMPLETED"
    assert execution["updated_at"] == STEP3_RECORDED_AT

    assert incident["evidence_digest"] == INCIDENT_DIGEST == canonical_digest({k:v for k,v in incident.items() if k != "evidence_digest"})
    assert incident["evidence_type"] == "auth.provider-adapter-positive-auth-v3.prewindow-key-creation.observed"
    assert incident["project_reference"] == PROJECT
    assert incident["target_key_name"] == KEY
    assert incident["plan_id"] == V3_PLAN_ID and incident["plan_digest"] == V3_PLAN_DIGEST
    assert incident["approval_id"] == V3_APPROVAL_ID and incident["approval_digest"] == V3_APPROVAL_DIGEST
    assert incident["owner_report"]["created"] is True
    assert incident["owner_report"]["exact_creation_timestamp_known"] is False
    assert incident["owner_report"]["report_observed_at"] == INCIDENT_OBSERVED_AT
    assert incident["owner_report"]["v3_authorization_effective_at"] == V3_WINDOW_START
    assert incident["owner_report"]["report_observed_before_effective_at"] is True
    assert INCIDENT_OBSERVED_AT < V3_WINDOW_START
    assert incident["authorization_assessment"] == {
        "v3_step1_recordable_as_authorized": False,
        "v3_execution_progress_created": False,
        "v3_execution_progress_may_be_retroactively_created": False,
        "fresh_forward_only_retirement_required": True,
        "v3_must_remain_blocked_until_retirement_complete": True,
    }
    assert incident["github_binding_state"]["creation_reported"] is False
    assert incident["github_binding_state"]["absence_requires_independent_names_only_verification"] is True
    assert all(value is False for value in incident["security_state"].values())

    assert resource["resource_id"] == RESOURCE_ID
    assert resource["resource_version"] == "provider-adapter-positive-auth-v3-prewindow-key-retirement.v1"
    assert resource["boundary"] == N
    assert resource["contract_digest"] == RESOURCE_DIGEST == canonical_digest({k:v for k,v in resource.items() if k != "contract_digest"})
    assert resource["project_reference"] == PROJECT
    assert DATA_PROJECT not in json.dumps(resource)
    assert resource["target_key_reference"] == KEY
    assert resource["github_secret_binding_name"] == GH
    assert resource["lineage"]["v3_plan_id"] == V3_PLAN_ID
    assert resource["lineage"]["v3_plan_digest"] == V3_PLAN_DIGEST
    assert resource["lineage"]["v3_approval_id"] == V3_APPROVAL_ID
    assert resource["lineage"]["v3_approval_digest"] == V3_APPROVAL_DIGEST
    assert resource["lineage"]["v3_execution_progress_absent"] is True
    assert resource["lineage"]["prewindow_key_creation_incident_digest"] == INCIDENT_DIGEST
    assert resource["authorized_counts"] == {
        "supabase_key_delete": 1,
        "supabase_key_absence_read": 1,
        "github_secret_absence_read": 1,
        "github_environment_secret_delete": 0,
        "credential_create": 0,
        "session_issue": 0,
        "token_issue": 0,
        "implementation_handoff_execute": 0,
    }
    assert all(value is False for value in resource["security_rules"].values())
    assert resource["failure_handling"]["v3_execution_must_remain_blocked"] is True
    assert resource["failure_handling"]["retry_v3_step1_authorized"] is False
    assert resource["failure_handling"]["github_binding_mutation_authorized"] is False

    assert prep["evidence_digest"] == PREP_DIGEST == canonical_digest({k:v for k,v in prep.items() if k != "evidence_digest"})
    assert prep["evidence_type"] == "auth.provider-adapter-positive-auth-v3.prewindow-key-retirement.prepared"
    assert prep["incident_evidence_digest"] == INCIDENT_DIGEST
    assert prep["resource_contract_digest"] == RESOURCE_DIGEST
    assert prep["provider_authority"] == "NONE"
    assert prep["external_provider_contact"] == "PROHIBITED"
    assert all(value is False for value in prep["security_state"].values())

    assert v3_plan["plan_id"] == V3_PLAN_ID and v3_plan["plan_digest"] == V3_PLAN_DIGEST
    assert v3_approval["approval_id"] == V3_APPROVAL_ID and v3_approval["approval_digest"] == V3_APPROVAL_DIGEST
    assert not (B / (V3 + ".execution-progress.json")).exists()

    steps = plan["steps"]
    assert len(steps) == 3
    assert plan["ordered_step_ids"] == [s["step_id"] for s in steps]
    assert [s["ordinal"] for s in steps] == [1,2,3]
    assert [s["execution_class"] for s in steps] == ["PROVIDER_MUTATION","PROVIDER_READ","PROVIDER_READ"]
    assert [s["operation"] for s in steps] == [
        "provider.auth-admin-credential.delete-dedicated-secret-key",
        "provider.auth-admin-credential.verify-dedicated-secret-key-absent",
        "provider.auth-secret-binding.verify-github-environment-reference-absent",
    ]
    assert all(s["resource"]["exact_digest"] == RESOURCE_DIGEST for s in steps)
    assert all(s["resource"]["exact_version"] == resource["resource_version"] for s in steps)
    assert steps[0]["dependency_step_ids"] == []
    assert steps[1]["dependency_step_ids"] == [steps[0]["step_id"]]
    assert steps[2]["dependency_step_ids"] == [steps[1]["step_id"]]
    assert KEY in steps[0]["resource"]["resource_reference"] and KEY in steps[1]["resource"]["resource_reference"]
    assert GH in steps[2]["resource"]["resource_reference"]
    first = {(x["evidence_type"],x["exact_digest"]) for x in steps[0]["required_evidence"]}
    assert (incident["evidence_type"], INCIDENT_DIGEST) in first
    assert (prep["evidence_type"], PREP_DIGEST) in first
    assert "github-secret.mutate" in plan["prohibited_actions"]
    assert "positive-auth-v3.progress.advance" in plan["prohibited_actions"]
    assert "positive-auth-v3.retry" in plan["prohibited_actions"]
    assert "credential.create" in plan["prohibited_actions"]

    assert progress == initial_progress(plan, S, PROGRESS_ID, CREATED_AT)
    assert progress["progress_digest"] == PROGRESS_DIGEST == progress_digest(progress)
    assert progress["overall_state"] == "NOT_STARTED"
    assert all((s["authorization_state"],s["execution_state"],s["verification_state"],s["authorization_consumed"]) == ("PENDING","NOT_STARTED","NOT_STARTED",False) for s in progress["step_states"])

    assert step1_success["evidence_type"] == "auth.provider-adapter-positive-auth.admin-credential.retired"
    assert step1_success["environment"] == "DEVELOPMENT" and step1_success["responsibility"] == "AUTH"
    assert step1_success["provider_reference"] == "supabase" and step1_success["project_reference"] == PROJECT
    assert step1_success["plan_id"] == PLAN_ID and step1_success["plan_digest"] == PLAN_DIGEST
    assert step1_success["approval_id"] == APPROVAL_ID and step1_success["approval_digest"] == APPROVAL_DIGEST
    assert step1_success["step_id"] == steps[0]["step_id"] and step1_success["attempt"] == 1
    assert step1_success["outcome"] == "SUCCEEDED_VERIFIED"
    assert step1_success["classification"] == "EXACT_PREWINDOW_V3_EPHEMERAL_AUTH_KEY_RETIRED"
    assert step1_success["authorization_observation_digest"] == STEP1_AUTHORIZATION_DIGEST
    assert canonical_digest(step1_success["authorization_observation"]) == STEP1_AUTHORIZATION_DIGEST
    assert step1_success["authorization_observation"]["authorization_window_active"] is True
    assert step1_success["authorization_observation"]["credential_material_observed"] is False
    assert step1_success["sanitized_result"] == {
        "key_name": KEY, "retired": True, "credential_material_observed": False, "other_key_changed": False,
    }
    assert step1_success["result_digest"] == STEP1_RESULT_DIGEST == canonical_digest(step1_success["sanitized_result"])
    assert step1_success["record_basis"] == "OWNER_CONFIRMED_SANITIZED_EXECUTION_OUTCOME"
    assert step1_success["recorded_at"] == STEP1_RECORDED_AT
    assert all(value is False for value in step1_success["security_state"].values())

    e1 = execution["step_states"][0]
    assert (e1["authorization_state"], e1["execution_state"], e1["verification_state"], e1["authorization_consumed"]) == ("CONSUMED","SUCCEEDED","PASS",True)
    assert e1["safe_error_code"] is None
    assert e1["observed_postcondition"] == steps[0]["expected_postcondition"]
    assert e1["evidence"] == [{
        "evidence_type": "auth.provider-adapter-positive-auth.admin-credential.retired",
        "evidence_reference": N + "-step1-success.evidence.json",
        "evidence_digest": STEP1_EVIDENCE_DIGEST,
        "recorded_at": STEP1_RECORDED_AT,
    }]
    assert len(e1["binding_assertions"]) == 2
    assert e1["binding_assertions"][0]["binding_id"] == "binding.development.provider-adapter-positive-auth-v3-prewindow-key-retirement-v1.step1-owner-session"
    assert e1["binding_assertions"][0]["evidence_digest"] == STEP1_AUTHORIZATION_DIGEST
    assert e1["binding_assertions"][0]["value_digest"] == STEP1_AUTHORIZATION_DIGEST
    assert e1["binding_assertions"][1]["binding_id"] == "binding.development.provider-adapter-positive-auth-v3-prewindow-key-retirement-v1.key-retired"
    assert e1["binding_assertions"][1]["evidence_digest"] == STEP1_EVIDENCE_DIGEST
    assert e1["binding_assertions"][1]["value_digest"] == STEP1_RESULT_DIGEST
    step2_path = B / (N + "-step2-success.evidence.json")
    assert raw(step2_path) == STEP2_EVIDENCE_DIGEST
    assert step2_success["evidence_type"] == "auth.provider-adapter-positive-auth.admin-credential.absence-verified"
    assert step2_success["environment"] == "DEVELOPMENT" and step2_success["responsibility"] == "AUTH"
    assert step2_success["provider_reference"] == "supabase" and step2_success["project_reference"] == PROJECT
    assert step2_success["plan_id"] == PLAN_ID and step2_success["plan_digest"] == PLAN_DIGEST
    assert step2_success["approval_id"] == APPROVAL_ID and step2_success["approval_digest"] == APPROVAL_DIGEST
    assert step2_success["step_id"] == steps[1]["step_id"] and step2_success["attempt"] == 1
    assert step2_success["outcome"] == "SUCCEEDED_VERIFIED"
    assert step2_success["classification"] == "EXACT_PREWINDOW_V3_EPHEMERAL_AUTH_KEY_ABSENCE_INDEPENDENTLY_CONFIRMED"
    assert step2_success["authorization_observation_digest"] == STEP2_AUTHORIZATION_DIGEST == canonical_digest(step2_success["authorization_observation"])
    assert step2_success["sanitized_result"] == {
        "key_name": KEY, "absent": True, "credential_material_observed": False,
        "other_key_inspected": False, "provider_mutation_performed": False,
    }
    assert step2_success["result_digest"] == STEP2_RESULT_DIGEST == canonical_digest(step2_success["sanitized_result"])
    assert step2_success["record_basis"] == "OWNER_CONFIRMED_SEPARATE_READ_ONLY_INSPECTION"
    assert step2_success["recorded_at"] == STEP2_RECORDED_AT
    assert all(value is False for value in step2_success["security_state"].values())

    e2 = execution["step_states"][1]
    assert (e2["authorization_state"], e2["execution_state"], e2["verification_state"], e2["authorization_consumed"]) == ("CONSUMED","SUCCEEDED","PASS",True)
    assert e2["safe_error_code"] is None
    assert e2["observed_postcondition"] == steps[1]["expected_postcondition"]
    assert e2["evidence"] == [{
        "evidence_type": "auth.provider-adapter-positive-auth.admin-credential.absence-verified",
        "evidence_reference": N + "-step2-success.evidence.json",
        "evidence_digest": STEP2_EVIDENCE_DIGEST,
        "recorded_at": STEP2_RECORDED_AT,
    }]
    assert len(e2["binding_assertions"]) == 3
    assert e2["binding_assertions"][0]["binding_id"] == "binding.development.provider-adapter-positive-auth-v3-prewindow-key-retirement-v1.key-retired"
    assert e2["binding_assertions"][0]["evidence_digest"] == STEP1_EVIDENCE_DIGEST
    assert e2["binding_assertions"][0]["value_digest"] == STEP1_RESULT_DIGEST
    assert e2["binding_assertions"][1]["binding_id"] == "binding.development.provider-adapter-positive-auth-v3-prewindow-key-retirement-v1.step2-owner-session"
    assert e2["binding_assertions"][1]["evidence_digest"] == STEP2_AUTHORIZATION_DIGEST
    assert e2["binding_assertions"][1]["value_digest"] == STEP2_AUTHORIZATION_DIGEST
    assert e2["binding_assertions"][2]["binding_id"] == "binding.development.provider-adapter-positive-auth-v3-prewindow-key-retirement-v1.key-absence"
    assert e2["binding_assertions"][2]["evidence_digest"] == STEP2_EVIDENCE_DIGEST
    assert e2["binding_assertions"][2]["value_digest"] == STEP2_RESULT_DIGEST
    step3_path = B / (N + "-step3-success.evidence.json")
    assert raw(step3_path) == STEP3_EVIDENCE_DIGEST
    assert step3_success["evidence_type"] == "auth.provider-adapter-positive-auth.github-binding.absence-verified"
    assert step3_success["environment"] == "DEVELOPMENT" and step3_success["responsibility"] == "AUTH"
    assert step3_success["provider_reference"] == "github"
    assert step3_success["repository"] == "AnonymousKoo/avuhz-infra" and step3_success["github_environment"] == "development"
    assert step3_success["plan_id"] == PLAN_ID and step3_success["plan_digest"] == PLAN_DIGEST
    assert step3_success["approval_id"] == APPROVAL_ID and step3_success["approval_digest"] == APPROVAL_DIGEST
    assert step3_success["step_id"] == steps[2]["step_id"] and step3_success["attempt"] == 1
    assert step3_success["outcome"] == "SUCCEEDED_VERIFIED"
    assert step3_success["classification"] == "EXACT_PREWINDOW_V3_GITHUB_BINDING_ABSENCE_INDEPENDENTLY_VERIFIED"
    assert step3_success["authorization_observation_digest"] == STEP3_AUTHORIZATION_DIGEST == canonical_digest(step3_success["authorization_observation"])
    assert step3_success["sanitized_result"] == {
        "repository": "AnonymousKoo/avuhz-infra",
        "environment": "development",
        "secret_name": GH,
        "exact_secret_reference_count": 0,
        "absent": True,
        "secret_value_requested": False,
        "secret_value_observed": False,
        "provider_mutation_performed": False,
    }
    assert step3_success["result_digest"] == STEP3_RESULT_DIGEST == canonical_digest(step3_success["sanitized_result"])
    assert step3_success["record_basis"] == "OWNER_AUTHORIZED_SANITIZED_NAMES_ONLY_READ_OUTCOME"
    assert step3_success["recorded_at"] == STEP3_RECORDED_AT
    assert all(value is False for value in step3_success["security_state"].values())

    e3 = execution["step_states"][2]
    assert (e3["authorization_state"],e3["execution_state"],e3["verification_state"],e3["authorization_consumed"]) == ("CONSUMED","SUCCEEDED","PASS",True)
    assert e3["safe_error_code"] is None
    assert e3["observed_postcondition"] == steps[2]["expected_postcondition"]
    assert e3["evidence"] == [{
        "evidence_type": "auth.provider-adapter-positive-auth.github-binding.absence-verified",
        "evidence_reference": N + "-step3-success.evidence.json",
        "evidence_digest": STEP3_EVIDENCE_DIGEST,
        "recorded_at": STEP3_RECORDED_AT,
    }]
    assert len(e3["binding_assertions"]) == 3
    assert e3["binding_assertions"][0]["binding_id"] == "binding.development.provider-adapter-positive-auth-v3-prewindow-key-retirement-v1.key-absence"
    assert e3["binding_assertions"][0]["evidence_digest"] == STEP2_EVIDENCE_DIGEST
    assert e3["binding_assertions"][0]["value_digest"] == STEP2_RESULT_DIGEST
    assert e3["binding_assertions"][1]["binding_id"] == "binding.development.provider-adapter-positive-auth-v3-prewindow-key-retirement-v1.step3-owner-session"
    assert e3["binding_assertions"][1]["evidence_digest"] == STEP3_AUTHORIZATION_DIGEST
    assert e3["binding_assertions"][1]["value_digest"] == STEP3_AUTHORIZATION_DIGEST
    assert e3["binding_assertions"][2]["binding_id"] == "binding.development.provider-adapter-positive-auth-v3-prewindow-key-retirement-v1.github-binding-absence"
    assert e3["binding_assertions"][2]["evidence_digest"] == STEP3_EVIDENCE_DIGEST
    assert e3["binding_assertions"][2]["value_digest"] == STEP3_RESULT_DIGEST

    rendered = "\n".join((B / (N + suffix)).read_text() for suffix in (
        "-incident.evidence.json", ".resource.json", "-preparation.evidence.json", ".plan.json", ".progress.json", ".approval.json",
        "-step1-success.evidence.json", "-step2-success.evidence.json", "-step3-success.evidence.json", ".execution-progress.json"
    ))
    for forbidden in ("Bearer eyJ", '"access_token":', '"refresh_token":', "service_role_key"):
        assert forbidden not in rendered
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", rendered) is None
    assert re.search(r"postgres(?:ql)?://[^\s/:]+:[^\s/@]+@", rendered, re.I) is None

    print(
        "DEVELOPMENT provider-adapter positive-auth v3 prewindow-key retirement v1: PASS "
        "(COMPLETED; Steps 1-3 CONSUMED/SUCCEEDED/PASS; exact prewindow v3 key retired; "
        "Supabase key and GitHub binding independently verified absent; original v3 execution remains non-retryable)"
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
