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
from avuhz_engineering.evidence_digest import evidence_digest
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v14"
RESOURCE = "sha256:e6e6699bb9ec756f4df726f0e2a1d74cb55d530f38b8d21ed20c72e1f9a62a41"
PREP = "sha256:03b916ad86f08c59849ea8e58c7eef2955581bb0f615778fb295c973af9bddfd"
PLAN = "sha256:8da4655cf8167a661935f88e340fe51d7da1821db807e9254ffca88b8b9ef47f"
PROGRESS = "sha256:f836b54d866c6a6ff9a01fcf0a51f80302e12982ef6071118cec19c1d4d65386"
EXECUTOR = "sha256:1d15c529df09f22af18d680b92c324769a102cc246841e9c691223d85a5f51ef"
WORKFLOW = "sha256:430d2d768fb513ad0c0af0b2e23cf3f50863b127f0f2688430f0378e13489215"
CREATED = "2026-10-08T06:40:37Z"
START = "2026-10-08T08:00:00Z"
END = "2026-10-08T12:00:00Z"
APPROVED = "2026-10-08T06:55:12Z"
APPROVAL = "sha256:9410d2e10b6fd7febe0d2c0d873608d54bdd1e9ca7c9da0e8aeec631847d36e0"
STEP1_EVIDENCE = "sha256:d4aff55bac16e73efc867b327ef88eab79fd3f0db6dcac04fd82233e34cf1b18"
STEP2_EVIDENCE = "sha256:62ee203e20be12f515e698cd69a10ced3422f46eb4b7f21e67ba157fc53adab1"
STEP3_EVIDENCE = "sha256:3590b89ce68436bb0109025b08869d7a4184a7207f65b52b67dca38e9d9395e0"
STEP4_EVIDENCE = "sha256:a81f43f32718325822785e6c246f90f9f161e93a3b377301ba83a607c7e3b8b2"
EXECUTION_PROGRESS = "sha256:4d3e44ca05339f980bbf5cced174f67f70d992b70456e9a94a64668ec643a096"
V13_EXPIRY = "sha256:b1589e9ec8d0435c0f6d8f2ab4f5904d2cf5716c217221217878b5dfa3df4f69"
V10_STOP = "sha256:38e26a596ebe6d3429c60f5f5cc8a49d13dc2da8868eb1f4bc75c42a11c74cd0"
V10_FAILURE = "sha256:d55ff4f7bcca05b03c5fc878f5fa2a09d95cd3b36b1716e181e4cd8bf3df2228"
V10_RET1_PROGRESS = "sha256:980bd163d03623f901d1f80e0fd25fbb70a8e06f1e3de1620af29cfb56c6e5a2"
V10_KEY_RETIRE = "sha256:35044d1166daa983e06781334c05d0002f877992cc9d9ca2ebe6a8bff597815e"
V10_KEY_ABSENCE = "sha256:cfaeca271afa9a51db7ff0390f45548a6e7b9e1864436c51e7d3acd1a89ae0e7"
V10_INCIDENT = "sha256:45c5a8f402d6d675ef25e1b4d77c1ad4c6a9f2a5090d1d11e36ed00bea873355"
V10_RET2_PROGRESS = "sha256:edc6600fb780bdff9b9b699d884d2fe739abcf1876f9af2cee27b246b1b5fd4a"
V10_GITHUB_ABSENCE = "sha256:1bef85f2ce88601d1a895ea9cb0ce5c9d2bb35a61ffcb05dbf15ecb9d15eacea"
V11_LATE = "sha256:81d4aa6893f1d378863ad15d33b88543de4ed1e8f5f99a252deb4ad0408e5380"
V12_LATE = "sha256:efd327d5f86b5c4db51601bf479620d2d5d733bcb9c921f2a3b33f0374b02b31"

def load(name: str) -> dict:
    return json.loads((B / name).read_text())

def raw(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

def main() -> int:
    r = load(N + ".resource.json")
    prep = load(N + "-preparation.evidence.json")
    p = load(N + ".plan.json")
    g = load(N + ".progress.json")
    a = load(N + ".approval.json")
    step1_evidence = load(N + "-step01-success.evidence.json")
    step2_evidence = load(N + "-step02-success.evidence.json")
    step3_evidence = load(N + "-step03-success.evidence.json")
    step4_evidence = load(N + "-step04-success.evidence.json")
    x = load(N + ".execution-progress.json")
    validate_plan(p, S)
    validate_progress(p, g, S)
    validate_approval(p, a, S, START)
    validate_progress(p, x, S)

    assert r["contract_digest"] == RESOURCE == canonical_digest({k:v for k,v in r.items() if k != "contract_digest"})
    assert prep["evidence_digest"] == PREP == evidence_digest(prep)
    assert p["plan_digest"] == PLAN == plan_digest(p)
    assert g["progress_digest"] == PROGRESS == progress_digest(g)
    assert g == initial_progress(p, S, g["progress_id"], CREATED)

    assert p["plan_id"] == "6ea08c43-5f97-4db2-b341-8f4e7c9a2d60"
    assert p["plan_version"] == 14
    assert p["definition_status"] == "READY_FOR_APPROVAL"
    assert p["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert p["authorization_window"] == {"binding_state":"BOUND","starts_at":START,"expires_at":END}
    assert p["target"]["project_reference"] == "pwlhruwutoitnieactol"
    assert p["target"]["responsibility"] == "AUTH"

    assert r["resource_version"] == "provider-adapter-positive-auth.v14"
    assert r["boundary"] == N
    assert r["fresh_provider_key_reference"] == "impl_handoff_provider_adapter_positive_auth_v14_ephemeral"
    assert r["github_secret_binding_name"] == "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V14_EPHEMERAL"
    assert r["step5_executor_digest"] == EXECUTOR == raw(ROOT / "scripts/development_provider_adapter_positive_auth_v14.py")
    assert r["step5_workflow_digest"] == WORKFLOW == raw(ROOT / ".github/workflows/development-provider-adapter-positive-auth-v14-step5.yml")
    assert r["execution_rules"]["owner_approval_deadline"] == START
    assert r["execution_rules"]["window_expiry"] == END
    assert r["retry_authorized"] is False
    assert r["implementation_handoff_execution_authorized"] is False
    assert r["data_operation_authorized"] is False
    assert r["render_mutation_authorized"] is False
    assert r["n8n_operation_authorized"] is False
    assert r["staging_authorized"] is False
    assert r["production_authorized"] is False

    assert prep["canonical_source_main"] == "b90bd7b2e3aede5c914574bed85672f32a5fe076"
    assert r["lineage"]["canonical_source_main"] == "b90bd7b2e3aede5c914574bed85672f32a5fe076"
    assert prep["resource_contract_digest"] == RESOURCE
    assert prep["authorization_window"] == {"starts_at":START,"expires_at":END}
    assert prep["predecessor_state"]["v10_overall_state"] == "STOPPED"
    assert prep["predecessor_state"]["v10_stopped_progress_digest"] == V10_STOP
    assert prep["predecessor_state"]["v10_plan_integrity_failure_evidence_digest"] == V10_FAILURE
    assert prep["predecessor_state"]["v10_retirement_v1_steps1_2_progress_digest"] == V10_RET1_PROGRESS
    assert prep["predecessor_state"]["v10_retirement_v2_overall_state"] == "COMPLETED"
    assert prep["predecessor_state"]["v10_retirement_v2_progress_digest"] == V10_RET2_PROGRESS
    assert prep["predecessor_state"]["v11_plan_id"] == "1f7c3e92-5a64-4b8d-a210-6e9c2d5f7b41"
    assert prep["predecessor_state"]["v11_plan_digest"] == "sha256:3fd1c42b6a5eb10958c13b9c99e64be806f7278e16415d6b931c2410de09f7fa"
    assert prep["predecessor_state"]["v11_late_rejection_evidence_digest"] == V11_LATE
    assert prep["predecessor_state"]["v11_approval_outcome"] == "REJECTED_LATE_APPROVAL_NONCANONICALIZABLE"
    assert prep["predecessor_state"]["v11_provider_authority_activated"] is False
    assert prep["predecessor_state"]["v12_plan_id"] == "4c8e6a21-3d75-4b9f-a120-6e2c5d7f8a41"
    assert prep["predecessor_state"]["v12_plan_digest"] == "sha256:b6fcb1f503f73023fb71a54a8452e4d5d2eafecafae8a02a58ff481e413ec11c"
    assert prep["predecessor_state"]["v12_late_rejection_evidence_digest"] == V12_LATE
    assert prep["predecessor_state"]["v12_approval_outcome"] == "REJECTED_LATE_APPROVAL_NONCANONICALIZABLE"
    assert prep["predecessor_state"]["v12_provider_authority_activated"] is False
    assert prep["predecessor_state"]["v13_plan_id"] == "5d9f7b32-4e86-4ca1-b230-7f3d6e8a9b52"
    assert prep["predecessor_state"]["v13_plan_digest"] == "sha256:284d6ed4ee9d3651e29afa83108642037f569db76bd1161fb7700a725f63b964"
    assert prep["predecessor_state"]["v13_approval_id"] == "7b4e2c91-6d35-4f8a-b120-9c5e3d7a6f42"
    assert prep["predecessor_state"]["v13_approval_digest"] == "sha256:8b8d6d842dcce50bfb013c2dde1c1a7296917f4f4e8dc43f2c3c07c8a74414ae"
    assert prep["predecessor_state"]["v13_progress_digest"] == "sha256:b0227e09710a65df4bc317a718b37183fd10d7de075db7b39c28aeb8537cc048"
    assert prep["predecessor_state"]["v13_expiry_evidence_digest"] == V13_EXPIRY
    assert prep["predecessor_state"]["v13_outcome"] == "EXPIRED_UNEXECUTED"
    assert prep["predecessor_state"]["v13_provider_authority_effects"] is False
    assert prep["whole_boundary_integrity"]["active_version"] == "v14"
    assert prep["whole_boundary_integrity"]["stale_active_v10_namespace_allowed"] is False
    assert prep["whole_boundary_integrity"]["stale_active_v11_namespace_allowed"] is False
    assert prep["whole_boundary_integrity"]["stale_active_v12_namespace_allowed"] is False
    assert prep["whole_boundary_integrity"]["stale_active_v13_namespace_allowed"] is False
    assert prep["whole_boundary_integrity"]["step4_resource_wording"] == "v14"
    assert prep["whole_boundary_integrity"]["step5_credential_wording"] == "v14"
    assert all(v is False for v in prep["security_state"].values())

    v10_stop = load("development-implementation-handoff-provider-adapter-positive-auth-v10.execution-progress.json")
    v10_failure = load("development-implementation-handoff-provider-adapter-positive-auth-v10-step05-plan-integrity-failure.evidence.json")
    v10_ret1 = load("development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v1.execution-progress.json")
    v10_key_retire = load("development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v1-step1-success.evidence.json")
    v10_key_absence = load("development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v1-step2-success.evidence.json")
    v10_incident = load("development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v1-post-window-github-outcome.evidence.json")
    v10_ret2 = load("development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v2.execution-progress.json")
    v10_github = load("development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v2-step1-success.evidence.json")
    v11_late = load("development-implementation-handoff-provider-adapter-positive-auth-v11-late-window-rejection.evidence.json")
    v12_late = load("development-implementation-handoff-provider-adapter-positive-auth-v12-late-window-rejection.evidence.json")
    v13_expiry = load("development-implementation-handoff-provider-adapter-positive-auth-v13-expiry.evidence.json")

    assert v10_stop["overall_state"] == "STOPPED"
    assert v10_stop["progress_digest"] == V10_STOP == r["required_v10_stopped_progress_digest"]
    assert evidence_digest(v10_failure) == V10_FAILURE == r["required_v10_plan_integrity_failure_evidence_digest"]
    assert v10_failure["safe_error_code"] == "PLAN_STATE_INVALID"
    assert v10_failure["sanitized_result"]["provider_mutation_performed"] is False
    assert v10_ret1["overall_state"] == "IN_PROGRESS"
    assert v10_ret1["progress_digest"] == V10_RET1_PROGRESS == r["required_v10_retirement_v1_progress_digest"]
    assert all(s["verification_state"] == "PASS" for s in v10_ret1["step_states"][:2])
    assert all(s["authorization_state"] == "PENDING" for s in v10_ret1["step_states"][2:])
    assert evidence_digest(v10_key_retire) == V10_KEY_RETIRE == r["required_v10_key_retirement_evidence_digest"]
    assert evidence_digest(v10_key_absence) == V10_KEY_ABSENCE == r["required_v10_key_absence_evidence_digest"]
    assert evidence_digest(v10_incident) == V10_INCIDENT == r["required_v10_post_window_github_outcome_evidence_digest"]
    assert v10_incident["authorization_assessment"]["retirement_v1_execution_progress_may_be_retroactively_advanced"] is False
    assert v10_incident["authorization_assessment"]["fresh_forward_only_v2_absence_reconciliation_required"] is True
    assert v10_ret2["overall_state"] == "COMPLETED"
    assert v10_ret2["progress_digest"] == V10_RET2_PROGRESS == r["required_v10_retirement_v2_progress_digest"]
    assert evidence_digest(v10_github) == V10_GITHUB_ABSENCE == r["required_v10_github_absence_evidence_digest"]
    assert evidence_digest(v11_late) == V11_LATE == r["required_v11_late_rejection_evidence_digest"]
    assert v11_late["outcome"] == "REJECTED_LATE_APPROVAL_NONCANONICALIZABLE"
    assert v11_late["approval_artifact_created"] is False
    assert v11_late["approval_canonicalized"] is False
    assert evidence_digest(v12_late) == V12_LATE == r["required_v12_late_rejection_evidence_digest"]
    assert v12_late["outcome"] == "REJECTED_LATE_APPROVAL_NONCANONICALIZABLE"
    assert v12_late["approval_artifact_created"] is False
    assert v12_late["approval_canonicalized"] is False
    assert evidence_digest(v13_expiry) == V13_EXPIRY == r["required_v13_expiry_evidence_digest"]
    assert v13_expiry["outcome"] == "EXPIRED_UNEXECUTED"
    assert v13_expiry["progress_state"]["overall_state"] == "NOT_STARTED"
    assert v13_expiry["progress_state"]["all_steps_pending"] is True
    assert v13_expiry["progress_state"]["all_steps_not_started"] is True
    assert v13_expiry["progress_state"]["authorization_consumed"] is False
    assert all(value is False for value in v13_expiry["effects"].values())

    assert len(p["steps"]) == 10
    assert [s["ordinal"] for s in p["steps"]] == list(range(1,11))
    assert all(s["resource"]["exact_version"] == "provider-adapter-positive-auth.v14" for s in p["steps"])
    assert all(s["resource"]["exact_digest"] == RESOURCE for s in p["steps"])
    assert "bound in the v14 resource" in p["steps"][3]["expected_postcondition"]
    assert "bound in the v9 resource" not in p["steps"][3]["expected_postcondition"]
    assert "bound in the v10 resource" not in p["steps"][3]["expected_postcondition"]
    assert "fresh v14 GitHub environment credential" in p["steps"][4]["expected_postcondition"]
    assert "fresh v9 GitHub environment credential" not in p["steps"][4]["expected_postcondition"]
    assert "fresh v10 GitHub environment credential" not in p["steps"][4]["expected_postcondition"]

    for idx in (0,3):
        required = {(e["evidence_type"], e["exact_digest"]) for e in p["steps"][idx]["required_evidence"]}
        assert ("auth.provider-adapter-positive-auth-v14.preparation.observed", PREP) in required
        assert ("authorization-plan.execution-progress", V10_STOP) in required
        assert ("auth.provider-adapter-positive-auth.live-verified-logout-accepted", V10_FAILURE) in required
        assert ("authorization-plan.execution-progress", V10_RET1_PROGRESS) in required
        assert ("auth.provider-adapter-positive-auth.admin-credential.retired", V10_KEY_RETIRE) in required
        assert ("auth.provider-adapter-positive-auth.admin-credential.absence-verified", V10_KEY_ABSENCE) in required
        assert ("auth.provider-adapter-positive-auth-v10.key-retirement-v1.post-window-github-outcome-observed", V10_INCIDENT) in required
        assert ("authorization-plan.execution-progress", V10_RET2_PROGRESS) in required
        assert ("auth.provider-adapter-positive-auth.github-binding.absence-verified", V10_GITHUB_ABSENCE) in required
        assert ("auth.provider-adapter-positive-auth-v11.late-approval-rejected", V11_LATE) in required
        assert ("auth.provider-adapter-positive-auth-v12.late-approval-rejected", V12_LATE) in required
        assert ("auth.provider-adapter-positive-auth-v13.expired-unexecuted", V13_EXPIRY) in required

    assert g["overall_state"] == "NOT_STARTED" and g["record_version"] == 1
    assert all((s["authorization_state"],s["execution_state"],s["verification_state"],s["authorization_consumed"]) == ("PENDING","NOT_STARTED","NOT_STARTED",False) for s in g["step_states"])
    assert a["approval_id"] == "8c5f3d72-7e46-4a9b-b231-0d6e4f8a5c73"
    assert a["plan_id"] == p["plan_id"]
    assert a["plan_version"] == 14
    assert a["plan_digest"] == p["plan_digest"]
    assert a["owner_identity"] == p["owner_identity"]
    assert a["decision"] == "APPROVE"
    assert a["environment"] == "DEVELOPMENT"
    assert a["approved_at"] == APPROVED
    assert APPROVED < START
    assert a["effective_at"] == START
    assert a["expires_at"] == END
    assert a["status"] == "ACTIVE"
    assert a["authority_scope"] == "EXACT_PLAN_ONLY"
    assert a["approval_digest"] == APPROVAL == approval_digest(a)

    assert evidence_digest(step1_evidence) == STEP1_EVIDENCE
    assert evidence_digest(step2_evidence) == STEP2_EVIDENCE
    assert evidence_digest(step3_evidence) == STEP3_EVIDENCE
    assert evidence_digest(step4_evidence) == STEP4_EVIDENCE
    assert step1_evidence["owner_confirmed_created"] is True
    assert step1_evidence["credential_material_retained"] is False
    assert step2_evidence["sanitized_result"]["binding_created"] is True
    assert step2_evidence["credential_material_retained"] is False
    assert step3_evidence["sanitized_result"]["binding_present"] is True
    assert step3_evidence["sanitized_result"]["value_read"] is False
    assert step3_evidence["credential_material_retained"] is False
    assert step4_evidence["sanitized_result"] == {"classification":"EXPECTED_PRECHECK_COUNTS_MATCHED","auth_user_count":2,"target_identity_count":1,"target_password_null_count":1,"target_tenant_exact_count":1,"session_count":0,"refresh_token_count":0}
    assert step4_evidence["execution_observation"]["approved_aggregate_select_attempts"] == 1
    assert step4_evidence["execution_observation"]["additional_sql_executed"] is False
    assert step4_evidence["execution_observation"]["retry_occurred"] is False
    assert step4_evidence["execution_observation"]["step5_attempted"] is False
    assert x["progress_digest"] == EXECUTION_PROGRESS == progress_digest(x)
    assert x["record_version"] == 5
    assert x["overall_state"] == "IN_PROGRESS"
    assert all(
        (
            state["authorization_state"],
            state["execution_state"],
            state["verification_state"],
            state["authorization_consumed"],
        ) == ("CONSUMED", "SUCCEEDED", "PASS", True)
        for state in x["step_states"][:4]
    )
    assert all(
        (
            state["authorization_state"],
            state["execution_state"],
            state["verification_state"],
            state["authorization_consumed"],
        ) == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        for state in x["step_states"][4:]
    )
    rendered = "\n".join((B / (N + suffix)).read_text() for suffix in (".resource.json","-preparation.evidence.json",".plan.json",".progress.json",".approval.json",".execution-progress.json","-step01-success.evidence.json","-step02-success.evidence.json","-step03-success.evidence.json","-step04-success.evidence.json"))
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", rendered) is None
    assert "gnuqaefotwgkwurjpyik" not in rendered
    assert "Bearer eyJ" not in rendered
    assert "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V10_EPHEMERAL" not in p.__str__()
    assert "impl_handoff_provider_adapter_positive_auth_v10_ephemeral" not in p.__str__()

    print("DEVELOPMENT provider-adapter positive-auth v14: PASS (APPROVED / STEPS 1-4 CONSUMED SUCCEEDED PASS; Step 5 pending; credential material absent)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
