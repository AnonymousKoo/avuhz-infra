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

from avuhz_engineering.authorization_plan import initial_progress, plan_digest, progress_digest, validate_plan, validate_progress
from avuhz_engineering.evidence_digest import evidence_digest
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v11"
RESOURCE = "sha256:3aeb90f4a39c5693c8b0f58d7b8a8be7cca6bb0eab56e0f609e3f1a77e8614bc"
PREP = "sha256:9190ed1334c62846bf78248e7017852adbbb8ffaf07116eb868ae68ee540563a"
PLAN = "sha256:3fd1c42b6a5eb10958c13b9c99e64be806f7278e16415d6b931c2410de09f7fa"
PROGRESS = "sha256:206736d9f59a2fcad79c2c56edbf7881b9764f6f18bbd612100c85f055f6750e"
EXECUTOR = "sha256:5fa56fd057250f92eb10e5eb25e869b4af2c58494875e20f685190ac50c3a73b"
WORKFLOW = "sha256:d1ed1d3eefa6bbe20b881a9993c73f12411b8787f008d72b721ec665e7677009"
CREATED = "2026-10-07T00:28:21Z"
START = "2026-10-07T00:45:00Z"
END = "2026-10-07T02:00:00Z"\nLATE_REJECTION = "sha256:81d4aa6893f1d378863ad15d33b88543de4ed1e8f5f99a252deb4ad0408e5380"\nLATE_OBSERVED = "2026-10-07T00:57:37Z"
V10_STOP = "sha256:38e26a596ebe6d3429c60f5f5cc8a49d13dc2da8868eb1f4bc75c42a11c74cd0"
V10_FAILURE = "sha256:d55ff4f7bcca05b03c5fc878f5fa2a09d95cd3b36b1716e181e4cd8bf3df2228"
V10_RET1_PROGRESS = "sha256:980bd163d03623f901d1f80e0fd25fbb70a8e06f1e3de1620af29cfb56c6e5a2"
V10_KEY_RETIRE = "sha256:35044d1166daa983e06781334c05d0002f877992cc9d9ca2ebe6a8bff597815e"
V10_KEY_ABSENCE = "sha256:cfaeca271afa9a51db7ff0390f45548a6e7b9e1864436c51e7d3acd1a89ae0e7"
V10_INCIDENT = "sha256:45c5a8f402d6d675ef25e1b4d77c1ad4c6a9f2a5090d1d11e36ed00bea873355"
V10_RET2_PROGRESS = "sha256:edc6600fb780bdff9b9b699d884d2fe739abcf1876f9af2cee27b246b1b5fd4a"
V10_GITHUB_ABSENCE = "sha256:1bef85f2ce88601d1a895ea9cb0ce5c9d2bb35a61ffcb05dbf15ecb9d15eacea"

def load(name: str) -> dict:
    return json.loads((B / name).read_text())

def raw(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

def main() -> int:
    r = load(N + ".resource.json")
    prep = load(N + "-preparation.evidence.json")
    p = load(N + ".plan.json")
    g = load(N + ".progress.json")\n    late = load(N + "-late-window-rejection.evidence.json")
    validate_plan(p, S)
    validate_progress(p, g, S)

    assert r["contract_digest"] == RESOURCE == canonical_digest({k:v for k,v in r.items() if k != "contract_digest"})
    assert prep["evidence_digest"] == PREP == evidence_digest(prep)
    assert p["plan_digest"] == PLAN == plan_digest(p)
    assert g["progress_digest"] == PROGRESS == progress_digest(g)
    assert g == initial_progress(p, S, g["progress_id"], CREATED)

    assert p["plan_id"] == "1f7c3e92-5a64-4b8d-a210-6e9c2d5f7b41"
    assert p["plan_version"] == 11
    assert p["definition_status"] == "READY_FOR_APPROVAL"
    assert p["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert p["authorization_window"] == {"binding_state":"BOUND","starts_at":START,"expires_at":END}
    assert p["target"]["project_reference"] == "pwlhruwutoitnieactol"
    assert p["target"]["responsibility"] == "AUTH"

    assert r["resource_version"] == "provider-adapter-positive-auth.v11"
    assert r["boundary"] == N
    assert r["fresh_provider_key_reference"] == "impl_handoff_provider_adapter_positive_auth_v11_ephemeral"
    assert r["github_secret_binding_name"] == "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V11_EPHEMERAL"
    assert r["step5_executor_digest"] == EXECUTOR == raw(ROOT / "scripts/development_provider_adapter_positive_auth_v11.py")
    assert r["step5_workflow_digest"] == WORKFLOW == raw(ROOT / ".github/workflows/development-provider-adapter-positive-auth-v11-step5.yml")
    assert r["execution_rules"]["owner_approval_deadline"] == START
    assert r["execution_rules"]["window_expiry"] == END
    assert r["retry_authorized"] is False
    assert r["implementation_handoff_execution_authorized"] is False
    assert r["data_operation_authorized"] is False
    assert r["render_mutation_authorized"] is False
    assert r["n8n_operation_authorized"] is False
    assert r["staging_authorized"] is False
    assert r["production_authorized"] is False

    assert prep["canonical_source_main"] == "6c7af0eef8bffdaa881dffe864ed961255435d62"
    assert prep["resource_contract_digest"] == RESOURCE
    assert prep["authorization_window"] == {"starts_at":START,"expires_at":END}
    assert prep["predecessor_state"]["v10_overall_state"] == "STOPPED"
    assert prep["predecessor_state"]["v10_stopped_progress_digest"] == V10_STOP
    assert prep["predecessor_state"]["v10_plan_integrity_failure_evidence_digest"] == V10_FAILURE
    assert prep["predecessor_state"]["v10_retirement_v1_steps1_2_progress_digest"] == V10_RET1_PROGRESS
    assert prep["predecessor_state"]["v10_retirement_v2_overall_state"] == "COMPLETED"
    assert prep["predecessor_state"]["v10_retirement_v2_progress_digest"] == V10_RET2_PROGRESS
    assert prep["whole_boundary_integrity"]["active_version"] == "v11"
    assert prep["whole_boundary_integrity"]["stale_active_v10_namespace_allowed"] is False
    assert prep["whole_boundary_integrity"]["step4_resource_wording"] == "v11"
    assert prep["whole_boundary_integrity"]["step5_credential_wording"] == "v11"
    assert all(v is False for v in prep["security_state"].values())

    v10_stop = load("development-implementation-handoff-provider-adapter-positive-auth-v10.execution-progress.json")
    v10_failure = load("development-implementation-handoff-provider-adapter-positive-auth-v10-step05-plan-integrity-failure.evidence.json")
    v10_ret1 = load("development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v1.execution-progress.json")
    v10_key_retire = load("development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v1-step1-success.evidence.json")
    v10_key_absence = load("development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v1-step2-success.evidence.json")
    v10_incident = load("development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v1-post-window-github-outcome.evidence.json")
    v10_ret2 = load("development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v2.execution-progress.json")
    v10_github = load("development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v2-step1-success.evidence.json")

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

    assert len(p["steps"]) == 10
    assert [s["ordinal"] for s in p["steps"]] == list(range(1,11))
    assert all(s["resource"]["exact_version"] == "provider-adapter-positive-auth.v11" for s in p["steps"])
    assert all(s["resource"]["exact_digest"] == RESOURCE for s in p["steps"])
    assert "bound in the v11 resource" in p["steps"][3]["expected_postcondition"]
    assert "bound in the v9 resource" not in p["steps"][3]["expected_postcondition"]
    assert "bound in the v10 resource" not in p["steps"][3]["expected_postcondition"]
    assert "fresh v11 GitHub environment credential" in p["steps"][4]["expected_postcondition"]
    assert "fresh v9 GitHub environment credential" not in p["steps"][4]["expected_postcondition"]
    assert "fresh v10 GitHub environment credential" not in p["steps"][4]["expected_postcondition"]

    for idx in (0,3):
        required = {(e["evidence_type"], e["exact_digest"]) for e in p["steps"][idx]["required_evidence"]}
        assert ("auth.provider-adapter-positive-auth-v11.preparation.observed", PREP) in required
        assert ("authorization-plan.execution-progress", V10_STOP) in required
        assert ("auth.provider-adapter-positive-auth.live-verified-logout-accepted", V10_FAILURE) in required
        assert ("authorization-plan.execution-progress", V10_RET1_PROGRESS) in required
        assert ("auth.provider-adapter-positive-auth.admin-credential.retired", V10_KEY_RETIRE) in required
        assert ("auth.provider-adapter-positive-auth.admin-credential.absence-verified", V10_KEY_ABSENCE) in required
        assert ("auth.provider-adapter-positive-auth-v10.key-retirement-v1.post-window-github-outcome-observed", V10_INCIDENT) in required
        assert ("authorization-plan.execution-progress", V10_RET2_PROGRESS) in required
        assert ("auth.provider-adapter-positive-auth.github-binding.absence-verified", V10_GITHUB_ABSENCE) in required

    assert late["evidence_digest"] == LATE_REJECTION == canonical_digest(
        {k: v for k, v in late.items() if k != "evidence_digest"}
    )
    assert late["candidate_plan_id"] == p["plan_id"]
    assert late["candidate_plan_version"] == 11
    assert late["candidate_plan_digest"] == PLAN
    assert late["approval_instruction_received"] is True
    assert late["approval_artifact_created"] is False
    assert late["approval_canonicalized"] is False
    assert late["candidate_effective_at"] == START
    assert late["candidate_expires_at"] == END
    assert late["approval_observed_at"] == LATE_OBSERVED
    assert LATE_OBSERVED > START
    assert late["outcome"] == "REJECTED_LATE_APPROVAL_NONCANONICALIZABLE"
    assert late["safe_error_code"] == "PLAN_AUTHORIZATION_EXPIRED"
    assert all(v is False for v in late["provider_effects"].values())
    assert late["continuation_rule"] == "CREATE_FRESH_FORWARD_ONLY_POSITIVE_AUTH_V12"

    assert g["overall_state"] == "NOT_STARTED" and g["record_version"] == 1
    assert all((s["authorization_state"],s["execution_state"],s["verification_state"],s["authorization_consumed"]) == ("PENDING","NOT_STARTED","NOT_STARTED",False) for s in g["step_states"])
    assert not (B / (N + ".approval.json")).exists()
    assert not (B / (N + ".execution-progress.json")).exists()

    rendered = "\n".join((B / (N + suffix)).read_text() for suffix in (".resource.json","-preparation.evidence.json",".plan.json",".progress.json","-late-window-rejection.evidence.json"))
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", rendered) is None
    assert "gnuqaefotwgkwurjpyik" not in rendered
    assert "Bearer eyJ" not in rendered
    assert "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V10_EPHEMERAL" not in p.__str__()
    assert "impl_handoff_provider_adapter_positive_auth_v10_ephemeral" not in p.__str__()

    print("DEVELOPMENT provider-adapter positive-auth v11: PASS (LATE APPROVAL REJECTED / UNAPPROVED / UNEXECUTED; forward-only v12 required; no provider authority)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
