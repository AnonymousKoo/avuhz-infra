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

import validate_development_provider_adapter_positive_auth_continuation_v1 as continuation
from avuhz_engineering.authorization_plan import approval_digest, initial_progress, plan_digest, progress_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-corrective-cleanup-retirement-v1"

PLAN_ID = "dfce4d99-3e6c-5c63-b3cc-be1cdbe24d26"
PLAN_DIGEST = "sha256:a16bd85523ba1b7f5d32be5baea851c474b8ad885b6e75a003e2901c25639e43"
RESOURCE_ID = "01459d6c-c7c9-5215-8fff-73921a2edfc4"
RESOURCE_DIGEST = "sha256:34169dc4cd6c72420f32c3dfb00844f1b22cb9466f16a3b6276bbf964fa066b7"
PREP_DIGEST = "sha256:d54f8cdda1501d263c3c47798ca844977a29fe0e8783b6629a32ce5bfcf8c13b"
PROGRESS_ID = "1d4ba8ef-6d9a-5b11-9e3d-80bb6e32d79d"
PROGRESS_DIGEST = "sha256:8dce889a527959d91cf03cc05e4e5cba7965670f2cc0513cfe7d3c3e806c5a39"
CREATED_AT = "2026-10-04T16:18:30Z"
WINDOW_START = "2026-10-04T17:00:00Z"
WINDOW_END = "2026-10-04T21:00:00Z"
APPROVAL_ID = "1e60f413-f385-53a0-a03f-ccbceb2fcb55"
APPROVAL_DIGEST = "sha256:144d51d1786baf662e21b1bc6bde41abe7040e0b5070c984d3ed3ec5cd8c432c"
APPROVED_AT = "2026-10-04T16:49:30Z"
STEP1_RECORDED_AT = "2026-10-04T17:31:31Z"
STEP1_EVIDENCE_DIGEST = "sha256:5a4183d202fc94f948b25e9c60a59136e9b81687728bf02ecb116ceba25709d1"
STEP1_AUTHORIZATION_DIGEST = "sha256:5978bd396f8855dce3b3ee2d79a076098498ca57ce039da16c88c9958f1d8102"
STEP1_RESULT_DIGEST = "sha256:3e2e7abda1b4491314952227804dc17fc293978ecf7f0ab8a5be8158bb954473"
EXECUTION_PROGRESS_DIGEST = "sha256:e48fe89e45b47e31b5439ccefe2240ab0edc3e9f2e377d10c2f799e617bc08a4"
STEP2_RECORDED_AT = "2026-10-04T17:49:55Z"
STEP2_EVIDENCE_DIGEST = "sha256:3459f2907d318fe014e195baff9d057f455690bcab36a83c52c913550a6c6efc"
STEP2_AUTHORIZATION_DIGEST = "sha256:c4a806f7584a855b1484b03aeaec68e057ebbb170667fc6c28d8f56ff5238c0a"
STEP2_RESULT_DIGEST = "sha256:16504d80fa4d87b1bfed74a201c45cc6d0cf538e457b63504d8f1160efb33d21"
STEP3_RECORDED_AT = "2026-10-04T18:02:46Z"
STEP3_EVIDENCE_DIGEST = "sha256:e6145a74d3cc8a8de3dbc53ca6a547d13e76aa4643ad37c5213b75c4b52cdb48"
STEP3_AUTHORIZATION_DIGEST = "sha256:16582e6c75cfa36516494662f57f8e9470d188cf4a3eb843387a1f4e6fe7d8f1"
STEP3_RESULT_DIGEST = "sha256:54c30896031fcbefe3613ae9a72acb4305189c39e41ea46acc28578c54e21e18"
STEP4_RECORDED_AT = "2026-10-04T19:10:21Z"
STEP4_EVIDENCE_DIGEST = "sha256:338e9648389d857871c816d9e4ad5c814300c3a92de45671da77e2564274a60f"
STEP4_AUTHORIZATION_DIGEST = "sha256:df63ff6ca2232bf9e916fdcc0e1bd5101aadcd5cec661df2de55a87df16a4854"
STEP4_RESULT_DIGEST = "sha256:93835c878e90750738900167e02005df9577d9864b317fcf2422f20ada278199"
STEP5_RECORDED_AT = "2026-10-04T19:39:13Z"
STEP5_EVIDENCE_DIGEST = "sha256:318709e7c83d2e701552b4daaa9769120ccade381c3aeaf179132489f9ff3de4"
STEP5_AUTHORIZATION_DIGEST = "sha256:c77d5d601bef711d7a8418ef992fc0053d52e279d9fa041c5e3497908d7a7ca7"
STEP5_RESULT_DIGEST = "sha256:d4d35d0ec1efee069c7a80f2c0b0743133cba71ea3e30a1ee1e1359bb15e6149"

PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
KEY_NAME = "impl_handoff_provider_adapter_positive_auth_v1_ephemeral"
GH_SECRET = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V1_EPHEMERAL"
FAILURE_DIGEST = "sha256:a4678fb87107b7544b60e6349acda6c6232ef300e334d667836318c495f0b531"
STOPPED_DIGEST = "sha256:730f4c0a7b6393223c85cd5746472e1227bb9c77d174e8644075c4dc1722bd6b"
KEY_CREATED = "sha256:1afa5a5b2129364ca63f458e63211b1aa2201f004c1acc131f90aa1cd15c4a42"
GH_CREATED = "sha256:9cf39e54d31c6c861607df0750df4f80ae920040ebc15ae664c94d67ebc7a7dd"
GH_VERIFIED = "sha256:1949474314c7486e178e465e0e1436b6127c2da20260997daaf70bfb42a1d3d5"
CONT_PLAN_RAW = "sha256:dbfd225d78584e4b902d58e37155708d5398061ad0ce7b0acb8baf1cf96538b9"
CONT_APPROVAL_RAW = "sha256:9bcd2fc871e71ce8a8ee55307220088f8b490a70d109fde8a0e67799aa304424"
CONT_FAILURE_RAW = "sha256:27c324aa9f0c155fb5c75125cdc4ce24bb160e1bf06af1fd2d08bd75039180c9"
CONT_EXEC_RAW = "sha256:cd108d65ddd1ed95bc4307e1736d694460331318546b72418b6a36e7e5013ae7"

QUERY = """select
  (select count(*) from auth.sessions) as session_count,
  (select count(*) from auth.refresh_tokens) as refresh_token_count;"""


def load(name: str) -> dict:
    value = json.loads((B / name).read_text())
    assert isinstance(value, dict)
    return value


def raw(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    continuation.main()

    resource = load(N + ".resource.json")
    prep = load(N + "-preparation.evidence.json")
    plan = load(N + ".plan.json")
    progress = load(N + ".progress.json")
    approval = load(N + ".approval.json")
    success = load(N + "-step1-success.evidence.json")
    step2_success = load(N + "-step2-success.evidence.json")
    step3_success = load(N + "-step3-success.evidence.json")
    step4_success = load(N + "-step4-success.evidence.json")
    step5_success = load(N + "-step5-success.evidence.json")
    execution = load(N + ".execution-progress.json")

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
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }

    assert resource["resource_id"] == RESOURCE_ID
    assert resource["resource_version"] == "provider-adapter-positive-auth-corrective-cleanup-retirement.v1"
    assert resource["contract_digest"] == RESOURCE_DIGEST
    resource_without_digest = dict(resource)
    resource_without_digest.pop("contract_digest")
    assert canonical_digest(resource_without_digest) == RESOURCE_DIGEST
    assert resource["project_reference"] == PROJECT
    assert DATA_PROJECT not in json.dumps(resource)
    assert resource["fresh_provider_key_reference"] == KEY_NAME
    assert resource["github_secret_binding_name"] == GH_SECRET
    assert resource["session_state_verification"]["query"] == QUERY
    assert resource["session_state_verification"]["query_count"] == 1
    assert resource["session_state_verification"]["result_fields"] == ["session_count", "refresh_token_count"]
    assert resource["session_state_verification"]["expected_result"] == {"session_count": 0, "refresh_token_count": 0}
    assert resource["session_state_verification"]["aggregate_only"] is True
    assert resource["session_state_verification"]["raw_rows_authorized"] is False
    assert resource["session_state_verification"]["additional_sql_authorized"] is False
    assert resource["session_state_verification"]["retry_authorized"] is False
    assert resource["failure_handling"]["unknown_session_state_at_entry"] is True
    assert resource["failure_handling"]["zero_state_required_before_retirement"] is True
    assert resource["failure_handling"]["retirement_after_nonzero_or_ambiguous_state_authorized"] is False
    assert resource["failure_handling"]["retry_failed_positive_auth_authorized"] is False
    assert resource["authorized_counts"] == {
        "session_state_aggregate_read": 1,
        "supabase_key_delete": 1,
        "github_environment_secret_delete": 1,
        "supabase_key_absence_read": 1,
        "github_secret_absence_read": 1,
        "session_cleanup_mutation": 0,
        "positive_auth_retry": 0,
        "new_authentication": 0,
        "session_issue": 0,
        "token_issue": 0,
        "implementation_handoff_execute": 0,
    }
    assert all(value is False for value in resource["security_rules"].values())

    assert prep["evidence_type"] == "auth.provider-adapter-positive-auth.corrective-cleanup-retirement.prepared"
    assert prep["evidence_digest"] == PREP_DIGEST
    prep_without_digest = dict(prep)
    prep_without_digest.pop("evidence_digest")
    assert canonical_digest(prep_without_digest) == PREP_DIGEST
    assert prep["provider_authority"] == "NONE"
    assert prep["external_provider_contact"] == "PROHIBITED"
    assert prep["security_state"] == {
        "provider_contact_performed": False,
        "provider_mutation_performed": False,
        "credential_material_observed": False,
        "credential_material_digest_recorded": False,
        "secret_value_read": False,
        "raw_rows_observed": False,
        "pii_observed": False,
        "history_rewritten": False,
        "approval_created": False,
        "execution_progress_created": False,
        "result_evidence_created": False,
    }

    steps = plan["steps"]
    assert len(steps) == 5
    assert [s["ordinal"] for s in steps] == [1, 2, 3, 4, 5]
    assert [s["execution_class"] for s in steps] == [
        "PROVIDER_READ", "PROVIDER_MUTATION", "PROVIDER_MUTATION", "PROVIDER_READ", "PROVIDER_READ"
    ]
    assert [s["operation"] for s in steps] == [
        "provider.auth-session-state.inspect-read-only",
        "provider.auth-admin-credential.delete-dedicated-secret-key",
        "provider.auth-secret-binding.delete-github-environment-reference",
        "provider.auth-admin-credential.verify-dedicated-secret-key-absent",
        "provider.auth-secret-binding.verify-github-environment-reference-absent",
    ]
    assert all(s["resource"]["exact_digest"] == RESOURCE_DIGEST for s in steps)
    assert all(s["resource"]["exact_version"] == "provider-adapter-positive-auth-corrective-cleanup-retirement.v1" for s in steps)
    assert all(s["credential_policy"] == {
        "permitted": True, "allowed_classes": ["OWNER_INTERACTIVE_SESSION"], "values_stored": False
    } for s in steps)
    assert steps[0]["dependency_step_ids"] == []
    for idx in range(1, 5):
        assert steps[idx]["dependency_step_ids"] == [steps[idx - 1]["step_id"]]

    first_required = {(x["evidence_type"], x["exact_digest"]) for x in steps[0]["required_evidence"]}
    for item in (
        ("auth.provider-adapter-positive-auth.live-verified-logout-accepted", FAILURE_DIGEST),
        ("authorization-plan.execution-progress", STOPPED_DIGEST),
        ("auth.provider-adapter-positive-auth.admin-credential.created", KEY_CREATED),
        ("auth.provider-adapter-positive-auth.github-binding.created", GH_CREATED),
        ("auth.provider-adapter-positive-auth.github-binding.verified", GH_VERIFIED),
        ("auth.provider-adapter-positive-auth.corrective-cleanup-retirement.prepared", PREP_DIGEST),
    ):
        assert item in first_required

    assert "Both must equal 0 before any retirement mutation may proceed" in steps[0]["expected_postcondition"]
    assert "count.nonzero" in steps[0]["stop_conditions"]
    assert "result.unavailable" in steps[0]["stop_conditions"]
    assert "provider.mutation" in steps[0]["prohibited_actions"]
    assert "provider.retry" in steps[0]["prohibited_actions"]
    assert KEY_NAME in steps[1]["resource"]["resource_reference"]
    assert GH_SECRET in steps[2]["resource"]["resource_reference"]
    assert KEY_NAME in steps[3]["resource"]["resource_reference"]
    assert GH_SECRET in steps[4]["resource"]["resource_reference"]

    for forbidden in (
        "implementation-handoff.execute", "session.issue", "token.issue", "token.refresh",
        "logout.execute", "recovery-credential.generate", "positive-auth-continuation-v1.retry",
    ):
        assert forbidden in plan["prohibited_actions"]

    assert progress == initial_progress(plan, S, PROGRESS_ID, CREATED_AT)
    assert progress["progress_digest"] == PROGRESS_DIGEST == progress_digest(progress)
    assert progress["overall_state"] == "NOT_STARTED"
    assert all(
        (x["authorization_state"], x["execution_state"], x["verification_state"], x["authorization_consumed"])
        == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        for x in progress["step_states"]
    )
    assert approval == {
        "approval_id": APPROVAL_ID,
        "plan_id": PLAN_ID,
        "plan_version": 1,
        "plan_digest": PLAN_DIGEST,
        "owner_identity": "github:AnonymousKoo",
        "decision": "APPROVE",
        "environment": "DEVELOPMENT",
        "effective_at": WINDOW_START,
        "expires_at": WINDOW_END,
        "approved_at": APPROVED_AT,
        "status": "ACTIVE",
        "authority_scope": "EXACT_PLAN_ONLY",
        "approval_digest": APPROVAL_DIGEST,
    }
    assert approval_digest(approval) == APPROVAL_DIGEST
    assert APPROVED_AT < WINDOW_START

    success_path = B / (N + "-step1-success.evidence.json")
    assert raw(success_path) == STEP1_EVIDENCE_DIGEST
    assert success["evidence_type"] == "auth.provider-adapter-positive-auth.cleanup.verified"
    assert success["environment"] == "DEVELOPMENT"
    assert success["responsibility"] == "AUTH"
    assert success["provider_reference"] == "supabase"
    assert success["project_reference"] == PROJECT
    assert success["plan_id"] == PLAN_ID
    assert success["plan_version"] == 1
    assert success["plan_digest"] == PLAN_DIGEST
    assert success["approval_id"] == APPROVAL_ID
    assert success["approval_digest"] == APPROVAL_DIGEST
    assert success["step_id"] == steps[0]["step_id"]
    assert success["attempt"] == 1
    assert success["outcome"] == "SUCCEEDED_VERIFIED"
    assert success["classification"] == "ZERO_SESSION_REFRESH_STATE_VERIFIED"
    assert success["authorization_observation_digest"] == STEP1_AUTHORIZATION_DIGEST
    assert success["sanitized_result"] == {"session_count": 0, "refresh_token_count": 0}
    assert success["result_digest"] == STEP1_RESULT_DIGEST
    assert success["record_basis"] == "OWNER_CONFIRMED_SANITIZED_EXECUTION_OUTCOME"
    assert success["recorded_at"] == STEP1_RECORDED_AT
    assert success["execution_observation"] == {
        "execution_class": "PROVIDER_READ",
        "execution_timestamp_retained": False,
        "recorded_at_is_execution_timestamp": False,
        "approved_aggregate_select_attempts": 1,
        "additional_sql_executed": False,
        "provider_mutation_attempted": False,
        "retry_occurred": False,
    }
    assert success["verification_observation"] == {
        "one_row_only": True,
        "exact_two_fields_only": True,
        "all_counts_nonnegative_integers": True,
        "all_expected_counts_matched": True,
        "raw_rows_returned": False,
        "sensitive_values_returned": False,
    }
    assert not any(success["security_state"].values())

    assert execution["progress_digest"] == EXECUTION_PROGRESS_DIGEST
    assert execution["overall_state"] == "COMPLETED"
    assert execution["updated_at"] == STEP5_RECORDED_AT
    step1_state = execution["step_states"][0]
    assert (
        step1_state["authorization_state"],
        step1_state["execution_state"],
        step1_state["verification_state"],
        step1_state["authorization_consumed"],
    ) == ("CONSUMED", "SUCCEEDED", "PASS", True)
    assert step1_state["safe_error_code"] is None
    assert step1_state["evidence"] == [{
        "evidence_type": "auth.provider-adapter-positive-auth.cleanup.verified",
        "evidence_reference": N + "-step1-success.evidence.json",
        "evidence_digest": STEP1_EVIDENCE_DIGEST,
        "recorded_at": STEP1_RECORDED_AT,
    }]
    assert len(step1_state["binding_assertions"]) == 2
    assert step1_state["binding_assertions"][0]["evidence_digest"] == STEP1_AUTHORIZATION_DIGEST
    assert step1_state["binding_assertions"][1]["evidence_digest"] == STEP1_EVIDENCE_DIGEST
    assert step1_state["binding_assertions"][1]["value_digest"] == STEP1_RESULT_DIGEST
    step2_path = B / (N + "-step2-success.evidence.json")
    assert raw(step2_path) == STEP2_EVIDENCE_DIGEST
    assert step2_success["evidence_type"] == "auth.provider-adapter-positive-auth.admin-credential.retired"
    assert step2_success["environment"] == "DEVELOPMENT"
    assert step2_success["responsibility"] == "AUTH"
    assert step2_success["provider_reference"] == "supabase"
    assert step2_success["project_reference"] == PROJECT
    assert step2_success["plan_id"] == PLAN_ID
    assert step2_success["plan_digest"] == PLAN_DIGEST
    assert step2_success["approval_id"] == APPROVAL_ID
    assert step2_success["approval_digest"] == APPROVAL_DIGEST
    assert step2_success["step_id"] == steps[1]["step_id"]
    assert step2_success["attempt"] == 1
    assert step2_success["outcome"] == "SUCCEEDED_VERIFIED"
    assert step2_success["classification"] == "EXACT_EPHEMERAL_AUTH_KEY_RETIRED"
    assert step2_success["authorization_observation_digest"] == STEP2_AUTHORIZATION_DIGEST
    assert step2_success["sanitized_result"] == {
        "key_name": KEY_NAME,
        "retired": True,
        "credential_material_observed": False,
        "other_key_changed": False,
    }
    assert step2_success["result_digest"] == STEP2_RESULT_DIGEST
    assert step2_success["record_basis"] == "OWNER_CONFIRMED_SANITIZED_EXECUTION_OUTCOME"
    assert step2_success["recorded_at"] == STEP2_RECORDED_AT
    assert step2_success["execution_observation"] == {
        "execution_class": "PROVIDER_MUTATION",
        "execution_timestamp_retained": False,
        "recorded_at_is_execution_timestamp": False,
        "approved_delete_attempts": 1,
        "credential_value_read": False,
        "other_key_mutation_attempted": False,
        "retry_occurred": False,
    }
    assert not any(step2_success["security_state"].values())

    assert execution["progress_digest"] == EXECUTION_PROGRESS_DIGEST
    assert execution["overall_state"] == "COMPLETED"
    assert execution["updated_at"] == STEP5_RECORDED_AT
    step2_state = execution["step_states"][1]
    assert (
        step2_state["authorization_state"],
        step2_state["execution_state"],
        step2_state["verification_state"],
        step2_state["authorization_consumed"],
    ) == ("CONSUMED", "SUCCEEDED", "PASS", True)
    assert step2_state["safe_error_code"] is None
    assert step2_state["evidence"] == [{
        "evidence_type": "auth.provider-adapter-positive-auth.admin-credential.retired",
        "evidence_reference": N + "-step2-success.evidence.json",
        "evidence_digest": STEP2_EVIDENCE_DIGEST,
        "recorded_at": STEP2_RECORDED_AT,
    }]
    assert len(step2_state["binding_assertions"]) == 3
    assert step2_state["binding_assertions"][0]["evidence_digest"] == STEP1_EVIDENCE_DIGEST
    assert step2_state["binding_assertions"][1]["evidence_digest"] == STEP2_AUTHORIZATION_DIGEST
    assert step2_state["binding_assertions"][2]["evidence_digest"] == STEP2_EVIDENCE_DIGEST
    assert step2_state["binding_assertions"][2]["value_digest"] == STEP2_RESULT_DIGEST
    step3_path = B / (N + "-step3-success.evidence.json")
    assert raw(step3_path) == STEP3_EVIDENCE_DIGEST
    assert step3_success["evidence_type"] == "auth.provider-adapter-positive-auth.github-binding.retired"
    assert step3_success["environment"] == "DEVELOPMENT"
    assert step3_success["responsibility"] == "AUTH"
    assert step3_success["provider_reference"] == "github"
    assert step3_success["repository"] == "AnonymousKoo/avuhz-infra"
    assert step3_success["github_environment"] == "development"
    assert step3_success["plan_id"] == PLAN_ID
    assert step3_success["plan_digest"] == PLAN_DIGEST
    assert step3_success["approval_id"] == APPROVAL_ID
    assert step3_success["approval_digest"] == APPROVAL_DIGEST
    assert step3_success["step_id"] == steps[2]["step_id"]
    assert step3_success["attempt"] == 1
    assert step3_success["outcome"] == "SUCCEEDED_VERIFIED"
    assert step3_success["classification"] == "EXACT_GITHUB_ENVIRONMENT_SECRET_BINDING_RETIRED"
    assert step3_success["authorization_observation_digest"] == STEP3_AUTHORIZATION_DIGEST
    assert step3_success["sanitized_result"] == {
        "repository": "AnonymousKoo/avuhz-infra",
        "environment": "development",
        "secret_name": GH_SECRET,
        "retired": True,
        "secret_value_observed": False,
        "other_secret_changed": False,
    }
    assert step3_success["result_digest"] == STEP3_RESULT_DIGEST
    assert step3_success["record_basis"] == "OWNER_CONFIRMED_SANITIZED_EXECUTION_OUTCOME"
    assert step3_success["recorded_at"] == STEP3_RECORDED_AT
    assert step3_success["execution_observation"] == {
        "execution_class": "PROVIDER_MUTATION",
        "execution_timestamp_retained": False,
        "recorded_at_is_execution_timestamp": False,
        "approved_delete_attempts": 1,
        "secret_value_read": False,
        "other_secret_mutation_attempted": False,
        "retry_occurred": False,
    }
    assert not any(step3_success["security_state"].values())

    step3_state = execution["step_states"][2]
    assert (
        step3_state["authorization_state"],
        step3_state["execution_state"],
        step3_state["verification_state"],
        step3_state["authorization_consumed"],
    ) == ("CONSUMED", "SUCCEEDED", "PASS", True)
    assert step3_state["safe_error_code"] is None
    assert step3_state["evidence"] == [{
        "evidence_type": "auth.provider-adapter-positive-auth.github-binding.retired",
        "evidence_reference": N + "-step3-success.evidence.json",
        "evidence_digest": STEP3_EVIDENCE_DIGEST,
        "recorded_at": STEP3_RECORDED_AT,
    }]
    assert len(step3_state["binding_assertions"]) == 3
    assert step3_state["binding_assertions"][0]["evidence_digest"] == STEP2_EVIDENCE_DIGEST
    assert step3_state["binding_assertions"][1]["evidence_digest"] == STEP3_AUTHORIZATION_DIGEST
    assert step3_state["binding_assertions"][2]["evidence_digest"] == STEP3_EVIDENCE_DIGEST
    assert step3_state["binding_assertions"][2]["value_digest"] == STEP3_RESULT_DIGEST

    step4_path = B / (N + "-step4-success.evidence.json")
    assert raw(step4_path) == STEP4_EVIDENCE_DIGEST
    assert step4_success["evidence_type"] == "auth.provider-adapter-positive-auth.admin-credential.absence-verified"
    assert step4_success["environment"] == "DEVELOPMENT"
    assert step4_success["responsibility"] == "AUTH"
    assert step4_success["provider_reference"] == "supabase"
    assert step4_success["project_reference"] == PROJECT
    assert step4_success["plan_id"] == PLAN_ID
    assert step4_success["plan_digest"] == PLAN_DIGEST
    assert step4_success["approval_id"] == APPROVAL_ID
    assert step4_success["approval_digest"] == APPROVAL_DIGEST
    assert step4_success["step_id"] == steps[3]["step_id"]
    assert step4_success["attempt"] == 1
    assert step4_success["outcome"] == "SUCCEEDED_VERIFIED"
    assert step4_success["classification"] == "EXACT_EPHEMERAL_AUTH_KEY_ABSENCE_INDEPENDENTLY_CONFIRMED"
    assert step4_success["authorization_observation_digest"] == STEP4_AUTHORIZATION_DIGEST
    assert step4_success["authorization_observation"] == {
        "interaction_surface": "supabase.dashboard.project-settings.api-keys.names-only",
        "project_reference": PROJECT,
        "environment": "DEVELOPMENT",
        "responsibility": "AUTH",
        "approval_exact": True,
        "authorization_window_execution_owner_confirmed": True,
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "credential_material_observed": False,
        "provider_mutation_attempted": False,
    }
    assert step4_success["sanitized_result"] == {
        "key_name": KEY_NAME,
        "absent": True,
        "credential_material_observed": False,
        "other_key_inspected": False,
        "provider_mutation_performed": False,
    }
    assert step4_success["result_digest"] == STEP4_RESULT_DIGEST
    assert step4_success["record_basis"] == "OWNER_CONFIRMED_SEPARATE_READ_ONLY_INSPECTION"
    assert step4_success["recorded_at"] == STEP4_RECORDED_AT
    assert step4_success["execution_observation"] == {
        "execution_class": "PROVIDER_READ",
        "execution_timestamp_retained": False,
        "recorded_at_is_execution_timestamp": False,
        "approved_absence_read_attempts": 1,
        "credential_value_read": False,
        "other_key_inspected": False,
        "provider_mutation_attempted": False,
        "retry_occurred": False,
    }
    assert step4_success["security_state"] == {
        "credential_material_observed": False,
        "credential_material_retained": False,
        "credential_material_digest_recorded": False,
        "token_material_retained": False,
        "pii_retained": False,
        "other_provider_key_inspected": False,
        "provider_key_changed": False,
        "github_secret_changed": False,
        "data_touched": False,
        "render_touched": False,
        "n8n_touched": False,
        "staging_touched": False,
        "production_touched": False,
    }
    assert canonical_digest(step4_success["authorization_observation"]) == STEP4_AUTHORIZATION_DIGEST
    assert canonical_digest(step4_success["sanitized_result"]) == STEP4_RESULT_DIGEST

    step4_state = execution["step_states"][3]
    assert (
        step4_state["authorization_state"],
        step4_state["execution_state"],
        step4_state["verification_state"],
        step4_state["authorization_consumed"],
    ) == ("CONSUMED", "SUCCEEDED", "PASS", True)
    assert step4_state["safe_error_code"] is None
    assert step4_state["observed_postcondition"] == steps[3]["expected_postcondition"]
    assert step4_state["evidence"] == [{
        "evidence_type": "auth.provider-adapter-positive-auth.admin-credential.absence-verified",
        "evidence_reference": N + "-step4-success.evidence.json",
        "evidence_digest": STEP4_EVIDENCE_DIGEST,
        "recorded_at": STEP4_RECORDED_AT,
    }]
    assert len(step4_state["binding_assertions"]) == 3
    assert step4_state["binding_assertions"][0]["binding_id"] == "binding.development.provider-adapter-positive-auth-corrective-cleanup-retirement-v1.github-binding-retired"
    assert step4_state["binding_assertions"][0]["evidence_digest"] == STEP3_EVIDENCE_DIGEST
    assert step4_state["binding_assertions"][0]["value_digest"] == STEP3_RESULT_DIGEST
    assert step4_state["binding_assertions"][1]["binding_id"] == "binding.development.provider-adapter-positive-auth-corrective-cleanup-retirement-v1.step4-owner-session"
    assert step4_state["binding_assertions"][1]["evidence_digest"] == STEP4_AUTHORIZATION_DIGEST
    assert step4_state["binding_assertions"][1]["value_digest"] == STEP4_AUTHORIZATION_DIGEST
    assert step4_state["binding_assertions"][2]["binding_id"] == "binding.development.provider-adapter-positive-auth-corrective-cleanup-retirement-v1.fresh-key-absence"
    assert step4_state["binding_assertions"][2]["evidence_digest"] == STEP4_EVIDENCE_DIGEST
    assert step4_state["binding_assertions"][2]["value_digest"] == STEP4_RESULT_DIGEST
    step5_path = B / (N + "-step5-success.evidence.json")
    assert raw(step5_path) == STEP5_EVIDENCE_DIGEST
    assert step5_success["evidence_type"] == "auth.provider-adapter-positive-auth.github-binding.absence-verified"
    assert step5_success["environment"] == "DEVELOPMENT"
    assert step5_success["responsibility"] == "AUTH"
    assert step5_success["provider_reference"] == "github"
    assert step5_success["repository"] == "AnonymousKoo/avuhz-infra"
    assert step5_success["github_environment"] == "development"
    assert step5_success["plan_id"] == PLAN_ID
    assert step5_success["plan_digest"] == PLAN_DIGEST
    assert step5_success["approval_id"] == APPROVAL_ID
    assert step5_success["approval_digest"] == APPROVAL_DIGEST
    assert step5_success["step_id"] == steps[4]["step_id"]
    assert step5_success["attempt"] == 1
    assert step5_success["outcome"] == "SUCCEEDED_VERIFIED"
    assert step5_success["classification"] == "EXACT_GITHUB_ENVIRONMENT_SECRET_ABSENCE_INDEPENDENTLY_VERIFIED"
    assert step5_success["authorization_observation_digest"] == STEP5_AUTHORIZATION_DIGEST
    assert step5_success["authorization_observation"] == {
        "interaction_surface": "github.api.repository-environment-secrets.names-only",
        "repository": "AnonymousKoo/avuhz-infra",
        "environment": "development",
        "responsibility": "AUTH",
        "approval_exact": True,
        "authorization_window_execution_owner_confirmed": True,
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "secret_value_requested": False,
        "secret_value_observed": False,
        "provider_mutation_attempted": False,
    }
    assert step5_success["sanitized_result"] == {
        "repository": "AnonymousKoo/avuhz-infra",
        "environment": "development",
        "secret_name": GH_SECRET,
        "exact_secret_reference_count": 0,
        "absent": True,
        "secret_value_requested": False,
        "secret_value_observed": False,
        "provider_mutation_performed": False,
    }
    assert step5_success["result_digest"] == STEP5_RESULT_DIGEST
    assert step5_success["record_basis"] == "OWNER_AUTHORIZED_SANITIZED_NAMES_ONLY_READ_OUTCOME"
    assert step5_success["recorded_at"] == STEP5_RECORDED_AT
    assert step5_success["execution_observation"] == {
        "execution_class": "PROVIDER_READ",
        "execution_timestamp_retained": False,
        "recorded_at_is_execution_timestamp": False,
        "approved_absence_read_attempts": 1,
        "secret_value_requested": False,
        "secret_value_read": False,
        "provider_mutation_attempted": False,
        "retry_occurred": False,
    }
    assert step5_success["security_state"] == {
        "secret_value_observed": False,
        "credential_material_observed": False,
        "credential_material_retained": False,
        "credential_material_digest_recorded": False,
        "token_material_retained": False,
        "pii_retained": False,
        "provider_key_changed": False,
        "github_secret_changed": False,
        "data_touched": False,
        "render_touched": False,
        "n8n_touched": False,
        "staging_touched": False,
        "production_touched": False,
    }
    assert canonical_digest(step5_success["authorization_observation"]) == STEP5_AUTHORIZATION_DIGEST
    assert canonical_digest(step5_success["sanitized_result"]) == STEP5_RESULT_DIGEST

    step5_state = execution["step_states"][4]
    assert (
        step5_state["authorization_state"],
        step5_state["execution_state"],
        step5_state["verification_state"],
        step5_state["authorization_consumed"],
    ) == ("CONSUMED", "SUCCEEDED", "PASS", True)
    assert step5_state["safe_error_code"] is None
    assert step5_state["observed_postcondition"] == steps[4]["expected_postcondition"]
    assert step5_state["evidence"] == [{
        "evidence_type": "auth.provider-adapter-positive-auth.github-binding.absence-verified",
        "evidence_reference": N + "-step5-success.evidence.json",
        "evidence_digest": STEP5_EVIDENCE_DIGEST,
        "recorded_at": STEP5_RECORDED_AT,
    }]
    assert len(step5_state["binding_assertions"]) == 3
    assert step5_state["binding_assertions"][0]["binding_id"] == "binding.development.provider-adapter-positive-auth-corrective-cleanup-retirement-v1.fresh-key-absence"
    assert step5_state["binding_assertions"][0]["evidence_digest"] == STEP4_EVIDENCE_DIGEST
    assert step5_state["binding_assertions"][0]["value_digest"] == STEP4_RESULT_DIGEST
    assert step5_state["binding_assertions"][1]["binding_id"] == "binding.development.provider-adapter-positive-auth-corrective-cleanup-retirement-v1.step5-owner-session"
    assert step5_state["binding_assertions"][1]["evidence_digest"] == STEP5_AUTHORIZATION_DIGEST
    assert step5_state["binding_assertions"][1]["value_digest"] == STEP5_AUTHORIZATION_DIGEST
    assert step5_state["binding_assertions"][2]["binding_id"] == "binding.development.provider-adapter-positive-auth-corrective-cleanup-retirement-v1.github-binding-absence"
    assert step5_state["binding_assertions"][2]["evidence_digest"] == STEP5_EVIDENCE_DIGEST
    assert step5_state["binding_assertions"][2]["value_digest"] == STEP5_RESULT_DIGEST

    cont = "development-implementation-handoff-provider-adapter-positive-auth-continuation-v1"
    assert raw(B / (cont + ".plan.json")) == CONT_PLAN_RAW
    assert raw(B / (cont + ".approval.json")) == CONT_APPROVAL_RAW
    assert raw(B / (cont + "-step1-failure.evidence.json")) == CONT_FAILURE_RAW
    assert raw(B / (cont + ".execution-progress.json")) == CONT_EXEC_RAW
    stopped = load(cont + ".execution-progress.json")
    assert stopped["overall_state"] == "STOPPED"
    assert stopped["progress_digest"] == STOPPED_DIGEST
    assert (
        stopped["step_states"][0]["authorization_state"],
        stopped["step_states"][0]["execution_state"],
        stopped["step_states"][0]["verification_state"],
        stopped["step_states"][0]["authorization_consumed"],
    ) == ("CONSUMED", "FAILED", "FAIL", True)
    assert all(x["authorization_state"] == "BLOCKED" for x in stopped["step_states"][1:])

    rendered = "\n".join((B / (N + suffix)).read_text() for suffix in (
        ".resource.json", "-preparation.evidence.json", ".plan.json", ".progress.json", ".approval.json",
        "-step1-success.evidence.json", "-step2-success.evidence.json", "-step3-success.evidence.json",
        "-step4-success.evidence.json", "-step5-success.evidence.json", ".execution-progress.json"
    ))
    for forbidden in ("sb_secret_", "Bearer eyJ", "service_role_key", '"access_token":', '"refresh_token":'):
        assert forbidden not in rendered
    assert re.search(r"postgres(?:ql)?://[^\s/:]+:[^\s/@]+@", rendered, re.I) is None

    print(
        "DEVELOPMENT provider-adapter positive-auth corrective cleanup/retirement v1: PASS "
        "(COMPLETED; Steps 1-5 CONSUMED/SUCCEEDED/PASS; zero session/refresh state verified; "
        "ephemeral AUTH key and GitHub binding retired; Supabase key and GitHub binding absence "
        "independently verified; cleanup boundary complete)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
