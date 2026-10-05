#!/usr/bin/env python3
"""Offline guard for DEVELOPMENT positive-auth v4 Step-4 correction v1 preparation."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import initial_progress, plan_digest, progress_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v4-step4-correction-v1"
V4 = "development-implementation-handoff-provider-adapter-positive-auth-v4"
PLAN_ID = "0b4c99e5-10d7-5f20-a37d-de1409b74ccf"
PLAN_DIGEST = "sha256:e7de96447430bfb9452bea6c69d6c4994522b83febe26179223fb1df66edd35d"
PROGRESS_ID = "88f9a3a2-245b-5926-b4fb-82efa7e1ce15"
PROGRESS_DIGEST = "sha256:c0d3521e58a1c374c14af7263dbbd3b65493960bf2ae43623492392fa45547c5"
RESOURCE_DIGEST = "sha256:de25ac4ade79896876d02408546ff041579fec6e1e6e88e69ee64462744043b4"
PREP_DIGEST = "sha256:29fab2d780b57898d0e5e37b335871e9dcced4dc10d96343a5a6e093ea2fee71"
CREATED_AT = "2026-10-05T00:05:03Z"
WINDOW_START = "2026-10-05T01:00:00Z"
WINDOW_END = "2026-10-05T05:00:00Z"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
QUERY_DIGEST = "sha256:0d785af10877d43bd4d886a534438dc21a6dd4471ac80194630feef29af73f8e"
V4_PLAN_ID = "dd18445f-1bde-5523-9f5f-82231b39abde"
V4_PLAN_DIGEST = "sha256:77d92723177eae2dc690566496710c3a7520bf3d329926ddf1b5894929d7ed5a"
V4_APPROVAL_ID = "976971bf-f20c-5dc3-8895-d4e7cd2d1d16"
V4_APPROVAL_DIGEST = "sha256:31ede5908db0a9b29a21f27602ca3dd7708bdbaafcb9bb5ae25c829999eb81d6"
V4_STOPPED_PROGRESS = "sha256:89597fb31105b2398295ba8c0be4534c7de80e7813b673e108db83a57a301c9c"
V4_STEP3_EVIDENCE = "sha256:b32dba957f080e4f0df22d3dd572afd2e2172c0f63c157f1a8328ca11a9aea0d"
V4_SCOPE_DRIFT_EVIDENCE = "sha256:15548bdd48fa9df3f78b2a8b84888c3b191fcd510c07c50db0ce64fded5ae6d3"
V4_SCOPE_DRIFT_RESULT = "sha256:9cdd1a5df610cc4e193da53e03a74b108a0ebb0875cb16dc82bf6320516d846e"


def load(name: str) -> dict:
    value = json.loads((B / name).read_text())
    assert isinstance(value, dict)
    return value


def raw(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    resource = load(N + ".resource.json")
    prep = load(N + "-preparation.evidence.json")
    plan = load(N + ".plan.json")
    progress = load(N + ".progress.json")
    v4_plan = load(V4 + ".plan.json")
    v4_approval = load(V4 + ".approval.json")
    v4_execution = load(V4 + ".execution-progress.json")
    v4_scope = load(V4 + "-step04-scope-drift.evidence.json")

    validate_plan(plan, S)
    validate_progress(plan, progress, S)

    assert plan["plan_id"] == PLAN_ID and plan["plan_version"] == 1
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"
    assert DATA_PROJECT not in json.dumps(plan)
    assert plan["created_at"] == CREATED_AT
    assert plan["authorization_window"] == {"binding_state":"BOUND","starts_at":WINDOW_START,"expires_at":WINDOW_END}
    assert not (B / (N + ".approval.json")).exists()
    assert not (B / (N + ".execution-progress.json")).exists()
    assert not list(B.glob(N + "-step*-*.evidence.json"))

    assert resource["contract_digest"] == RESOURCE_DIGEST == canonical_digest({k:v for k,v in resource.items() if k != "contract_digest"})
    assert resource["project_reference"] == PROJECT
    assert resource["interaction_surface"] == "supabase.dashboard.sql-editor"
    assert resource["credential_class"] == "OWNER_INTERACTIVE_SESSION"
    assert resource["diagnostic_sql_sha256"] == QUERY_DIGEST
    assert "sha256:" + hashlib.sha256(resource["diagnostic_sql"].encode()).hexdigest() == QUERY_DIGEST
    assert resource["query_count"] == 1 and resource["aggregate_only"] is True
    assert resource["follow_up_sql_authorized"] is False and resource["retry_authorized"] is False
    assert resource["expected_result"] == {
        "auth_user_count":2, "target_identity_count":1, "target_password_null_count":1,
        "target_tenant_exact_count":1, "session_count":0, "refresh_token_count":0,
    }
    for key in (
        "provider_mutation_authorized","identity_change_authorized","password_state_change_authorized",
        "tenant_binding_authorized","allowlist_binding_authorized","token_issue_authorized",
        "session_issue_authorized","hook_change_authorized","data_operation_authorized",
        "render_operation_authorized","n8n_operation_authorized","staging_authorized",
        "production_authorized","raw_row_return_authorized","password_hash_value_read_authorized",
        "credential_material_persistence_authorized","credential_read_authorized","credential_lifecycle_authorized",
        "github_binding_read_or_change_authorized","step5_or_later_authorized",
        "v4_progress_advance_authorized","v4_step4_success_authorized",
    ):
        assert resource[key] is False
    assert resource["lineage"] == {
        "v4_plan_id":V4_PLAN_ID, "v4_plan_digest":V4_PLAN_DIGEST,
        "v4_approval_id":V4_APPROVAL_ID, "v4_approval_digest":V4_APPROVAL_DIGEST,
        "v4_stopped_execution_progress_digest":V4_STOPPED_PROGRESS,
        "v4_step3_verified_github_binding_evidence_digest":V4_STEP3_EVIDENCE,
        "v4_step4_scope_drift_evidence_digest":V4_SCOPE_DRIFT_EVIDENCE,
        "v4_step4_scope_drift_result_digest":V4_SCOPE_DRIFT_RESULT,
        "v4_step4_safe_error_code":"AUTHORITY_INVALID",
    }
    assert "never record it as v4 Step 4 success" in resource["result_use"]
    assert "Preserve the existing v4 ephemeral Supabase key and GitHub development binding" in resource["out_of_scope_state"]

    assert prep["evidence_digest"] == PREP_DIGEST == canonical_digest({k:v for k,v in prep.items() if k != "evidence_digest"})
    assert prep["evidence_type"] == "auth.provider-adapter-positive-auth-v4.step4-correction.prepared"
    assert prep["provider_authority"] == "NONE" and prep["external_provider_contact"] == "PROHIBITED"
    assert prep["selected_diagnostic"]["resource_digest"] == RESOURCE_DIGEST
    assert prep["selected_diagnostic"]["interaction_surface"] == "supabase.dashboard.sql-editor"
    assert prep["selected_diagnostic"]["credential_class"] == "OWNER_INTERACTIVE_SESSION"
    assert prep["selected_diagnostic"]["query_sha256"] == QUERY_DIGEST
    assert prep["selected_diagnostic"]["query_count"] == 1 and prep["selected_diagnostic"]["aggregate_only"] is True
    assert prep["selected_diagnostic"]["mutation_authorized"] is False
    assert prep["selected_diagnostic"]["retry_authorized"] is False
    assert prep["selected_diagnostic"]["follow_up_sql_authorized"] is False
    assert prep["selected_diagnostic"]["v4_progress_advance_authorized"] is False
    assert prep["selected_diagnostic"]["step5_or_later_authorized"] is False
    assert prep["correction_reason"]["historical_data_result_matched"] is True
    assert prep["correction_reason"]["historical_interaction_surface_matched"] is False
    assert prep["correction_reason"]["fresh_owner_interactive_read_required"] is True
    assert prep["correction_reason"]["v4_retry_authorized"] is False
    assert prep["correction_reason"]["step5_authorized"] is False
    assert all(value is False for value in prep["security_state"].values())

    assert v4_plan["plan_id"] == V4_PLAN_ID and v4_plan["plan_digest"] == V4_PLAN_DIGEST
    assert v4_approval["approval_id"] == V4_APPROVAL_ID and v4_approval["approval_digest"] == V4_APPROVAL_DIGEST
    assert v4_execution["overall_state"] == "STOPPED"
    assert v4_execution["progress_digest"] == V4_STOPPED_PROGRESS == progress_digest(v4_execution)
    assert all((s["authorization_state"],s["execution_state"],s["verification_state"],s["authorization_consumed"]) == ("CONSUMED","SUCCEEDED","PASS",True) for s in v4_execution["step_states"][:3])
    step4 = v4_execution["step_states"][3]
    assert (step4["authorization_state"],step4["execution_state"],step4["verification_state"],step4["authorization_consumed"]) == ("CONSUMED","FAILED","FAIL",True)
    assert step4["safe_error_code"] == "AUTHORITY_INVALID"
    assert step4["evidence"][0]["evidence_digest"] == V4_SCOPE_DRIFT_EVIDENCE
    assert all(s["authorization_state"] == "BLOCKED" and s["execution_state"] == "NOT_STARTED" and s["verification_state"] == "NOT_STARTED" and s["authorization_consumed"] is False for s in v4_execution["step_states"][4:])
    assert raw(B / (V4 + "-step03-success.evidence.json")) == V4_STEP3_EVIDENCE
    assert raw(B / (V4 + "-step04-scope-drift.evidence.json")) == V4_SCOPE_DRIFT_EVIDENCE
    assert v4_scope["result_digest"] == V4_SCOPE_DRIFT_RESULT
    assert v4_scope["outcome"] == "FAILED_SCOPE_DRIFT" and v4_scope["safe_error_code"] == "AUTHORITY_INVALID"
    assert v4_scope["authorized_contract"]["interaction_surface"] == "supabase.dashboard.sql-editor"
    assert v4_scope["actual_execution"]["interaction_surface"] == "supabase.mcp.execute_sql"
    assert v4_scope["sanitized_result"]["counts_match_expected"] is True
    assert v4_scope["sanitized_result"]["preflight_certified"] is False
    assert v4_scope["verification_observation"]["step5_may_continue"] is False

    assert len(plan["steps"]) == 1 and plan["ordered_step_ids"] == [plan["steps"][0]["step_id"]]
    step = plan["steps"][0]
    assert step["step_id"] == "development.implementation-handoff.provider-adapter-positive-auth-v4-step4-correction-v1.step.01.inspect-preflight-counts-read-only"
    assert step["resource"]["exact_digest"] == RESOURCE_DIGEST
    assert step["resource"]["exact_version"] == "positive-auth-v4-step4-correction.v1"
    assert step["resource"]["resource_reference"] == "supabase:pwlhruwutoitnieactol:auth:provider-adapter-positive-auth-v4-step4-correction-v1"
    assert step["execution_class"] == "PROVIDER_READ"
    assert step["credential_policy"] == {"permitted":True,"allowed_classes":["OWNER_INTERACTIVE_SESSION"],"values_stored":False}
    assert "supabase.mcp.execute_sql" in step["prohibited_actions"]
    assert "positive-auth-v4.progress.advance" in step["prohibited_actions"]
    assert "positive-auth-v4.step4.mark-success" in step["prohibited_actions"]
    assert "positive-auth.step5-or-later.execute" in step["prohibited_actions"]
    required = {(x["evidence_type"],x["exact_digest"]) for x in step["required_evidence"]}
    assert (prep["evidence_type"],PREP_DIGEST) in required
    assert ("auth.provider-adapter-positive-auth.preflight.verified",V4_SCOPE_DRIFT_EVIDENCE) in required
    assert ("auth.provider-adapter-positive-auth.github-binding.verified",V4_STEP3_EVIDENCE) in required
    assert ("authorization-plan.execution-progress",V4_STOPPED_PROGRESS) in required
    assert "one OWNER_INTERACTIVE_SESSION" in step["expected_postcondition"]
    assert "never mark v4 Step 4 success" in step["expected_postcondition"]
    assert "never execute Step 5" in step["expected_postcondition"]

    assert progress == initial_progress(plan, S, PROGRESS_ID, CREATED_AT)
    assert progress["progress_digest"] == PROGRESS_DIGEST == progress_digest(progress)
    assert progress["overall_state"] == "NOT_STARTED"

    rendered = "\n".join((B/(N+suffix)).read_text() for suffix in (
        ".resource.json","-preparation.evidence.json",".plan.json",".progress.json"
    ))
    for forbidden in ("Bearer eyJ", '"access_token":', '"refresh_token":', "service_role_key"):
        assert forbidden not in rendered
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", rendered) is None
    assert re.search(r"postgres(?:ql)?://[^\s/:]+:[^\s/@]+@", rendered, re.I) is None

    print("DEVELOPMENT provider-adapter positive-auth v4 Step-4 correction v1: PASS (READY_FOR_APPROVAL; pristine; exact one owner-interactive SQL Editor aggregate read; v4 remains STOPPED; Step 5 prohibited)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
