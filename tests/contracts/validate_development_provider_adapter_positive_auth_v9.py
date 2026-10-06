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

from avuhz_engineering.authorization_plan import (
    approval_digest,
    initial_progress,
    plan_digest,
    progress_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v9"
V8 = "development-implementation-handoff-provider-adapter-positive-auth-v8"
V8_RETIRE = "development-implementation-handoff-provider-adapter-positive-auth-v8-key-retirement-v2"

PROJECT = "pwlhruwutoitnieactol"
KEY = "impl_handoff_provider_adapter_positive_auth_v9_ephemeral"
GH = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V9_EPHEMERAL"
CREATED = "2026-10-06T15:37:03Z"
START = "2026-10-06T17:00:00Z"
END = "2026-10-06T23:00:00Z"
APPROVED = "2026-10-06T15:55:00Z"
APPROVAL = "sha256:ee9fa899d8b842b73677609955061618ec873a2a2c926a88207dab34dec234c5"

RESOURCE = "sha256:798fa6cdd64f3c5cee74380eb255661cc9fe5de53dfbb96916309b3dfe78c3b3"
PREP = "sha256:1198068f3a86bc49b77823856eece87e9b50803d227a9fa02051d3f0900c2a68"
PLAN = "sha256:9ffc1f6d4c91614b79b281c9f21e3c87d7586517b5b20898d847e54038a026c4"
PROGRESS = "sha256:fde7b914b74d1b6cdeda3b162f19438da786f818e43a41b6b3e1ebb8641c602a"
STEP1_EVIDENCE = "sha256:e794f45457172d917f6dded302231edeb7369253d54d1a51aa7f503eb7c84f10"
STEP2_EVIDENCE = "sha256:9576eddf1b2a55598cdfd4052126d592b21be652ceba4b2488641d046f600e7a"
STEP3_EVIDENCE = "sha256:e6d2befae47955bbb66e042996eda5f2460a32515223e8d79b6438cbd608ae51"
EXECUTION_PROGRESS = "sha256:9facf2544a7ac38adaa30b8fe2f1d54002807c270fcd6ff4bc5cd6323962c7de"
EXECUTOR = "sha256:c92562443d2e9af274a150174b76bfdb7cae7989896590f2298addfafa9190d3"
WORKFLOW = "sha256:c657fcd7b82352bf62e1a646f5e890225f22370ad48992fd81c2838f34a7abe2"

V8_STOPPED = "sha256:45c6d902458eee68f2f2782aaac82598d8cef7a2c022124691d3db4f08222b8d"
V8_RETIREMENT = "sha256:dda26efb46d17998b71072edfec3ce3490478b595e92e31ce58ee645b211bade"
V8_KEY_ABSENCE = "sha256:4568bc1310f24c0e2db15dc9922b751bfff0565fd2c811e8477ca433aaa9046f"
V8_GH_ABSENCE = "sha256:4d4e4f695b60e90c5c6e230a10004bade558e22c69aa4c9fe3d477518d50015a"


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
    x = load(N + ".execution-progress.json")
    v8_x = load(V8 + ".execution-progress.json")
    v8_retire_x = load(V8_RETIRE + ".execution-progress.json")
    v8_key_absence = load(V8_RETIRE + "-step1-success.evidence.json")
    v8_gh_absence = load(V8_RETIRE + "-step2-success.evidence.json")

    validate_plan(p, S)
    validate_progress(p, g, S)
    validate_progress(p, x, S)
    validate_approval(p, a, S, START)

    assert r["contract_digest"] == RESOURCE == canonical_digest(
        {k: v for k, v in r.items() if k != "contract_digest"}
    )
    assert prep["evidence_digest"] == PREP == canonical_digest(
        {k: v for k, v in prep.items() if k != "evidence_digest"}
    )
    assert p["plan_digest"] == PLAN == plan_digest(p)
    assert g["progress_digest"] == PROGRESS == progress_digest(g)
    assert g == initial_progress(p, S, g["progress_id"], CREATED)

    assert p["plan_id"] == "9f4e3d72-6b1a-4f0c-a8d5-2e7c9b4a6130"
    assert p["plan_version"] == 9
    assert p["definition_status"] == "READY_FOR_APPROVAL"
    assert p["environment"] == "DEVELOPMENT"
    assert p["target"]["project_reference"] == PROJECT
    assert p["target"]["responsibility"] == "AUTH"
    assert p["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": START,
        "expires_at": END,
    }
    assert p["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"

    assert a["approval_id"] == "7c4a6f21-8c9e-46b1-9b4a-3f7d2e6c5a10"
    assert a["plan_id"] == p["plan_id"] and a["plan_version"] == 9
    assert a["plan_digest"] == PLAN and a["owner_identity"] == p["owner_identity"]
    assert a["decision"] == "APPROVE" and a["environment"] == "DEVELOPMENT"
    assert a["effective_at"] == START and a["expires_at"] == END
    assert a["approved_at"] == APPROVED and APPROVED < START
    assert a["status"] == "ACTIVE" and a["authority_scope"] == "EXACT_PLAN_ONLY"
    assert a["approval_digest"] == APPROVAL == approval_digest(a)

    assert r["project_reference"] == PROJECT and r["responsibility"] == "AUTH"
    assert r["fresh_provider_key_reference"] == KEY
    assert r["github_secret_binding_name"] == GH
    assert r["resource_version"] == "provider-adapter-positive-auth.v9"
    assert r["boundary"] == N
    assert r["step5_executor_digest"] == EXECUTOR == raw(
        ROOT / "scripts/development_provider_adapter_positive_auth_v9.py"
    )
    assert r["step5_workflow_digest"] == WORKFLOW == raw(
        ROOT / ".github/workflows/development-provider-adapter-positive-auth-v9-step5.yml"
    )
    assert r["execution_rules"]["owner_approval_deadline"] == START
    assert r["execution_rules"]["window_expiry"] == END
    assert r["retry_authorized"] is False
    assert r["implementation_handoff_execution_authorized"] is False
    assert r["data_operation_authorized"] is False
    assert r["render_mutation_authorized"] is False
    assert r["n8n_operation_authorized"] is False
    assert r["staging_authorized"] is False
    assert r["production_authorized"] is False

    assert v8_x["overall_state"] == "STOPPED"
    assert v8_x["progress_digest"] == V8_STOPPED == progress_digest(v8_x)
    assert v8_retire_x["overall_state"] == "COMPLETED"
    assert v8_retire_x["progress_digest"] == V8_RETIREMENT == progress_digest(v8_retire_x)
    assert canonical_digest(v8_key_absence) == V8_KEY_ABSENCE
    assert canonical_digest(v8_gh_absence) == V8_GH_ABSENCE
    assert all(
        (
            s["authorization_state"],
            s["execution_state"],
            s["verification_state"],
            s["authorization_consumed"],
        )
        == ("CONSUMED", "SUCCEEDED", "PASS", True)
        for s in v8_retire_x["step_states"]
    )

    assert r["required_v8_stopped_progress_digest"] == V8_STOPPED
    assert r["required_v8_retirement_progress_digest"] == V8_RETIREMENT
    assert r["required_v8_key_absence_evidence_digest"] == V8_KEY_ABSENCE
    assert r["required_v8_github_absence_evidence_digest"] == V8_GH_ABSENCE
    assert r["lineage"]["v8_stopped_progress_digest"] == V8_STOPPED
    assert r["lineage"]["v8_retirement_v2_completed_progress_digest"] == V8_RETIREMENT
    assert r["lineage"]["v8_key_absence_evidence_digest"] == V8_KEY_ABSENCE
    assert r["lineage"]["v8_github_absence_evidence_digest"] == V8_GH_ABSENCE
    assert r["lineage"]["canonical_source_main"] == "9239e3e357789003d3563f9f2bb682a54be91618"

    assert prep["canonical_source_main"] == "9239e3e357789003d3563f9f2bb682a54be91618"
    assert prep["resource_contract_digest"] == RESOURCE
    assert prep["authorization_window"] == {"starts_at": START, "expires_at": END}
    assert prep["predecessor_state"] == {
        "v8_overall_state": "STOPPED",
        "v8_stopped_progress_digest": V8_STOPPED,
        "v8_retirement_v2_overall_state": "COMPLETED",
        "v8_retirement_v2_progress_digest": V8_RETIREMENT,
        "v8_key_absence_evidence_digest": V8_KEY_ABSENCE,
        "v8_github_absence_evidence_digest": V8_GH_ABSENCE,
    }
    assert prep["whole_boundary_integrity"] == {
        "active_version": "v9",
        "stale_active_v8_namespace_allowed": False,
        "step4_resource_wording": "v9",
        "step5_credential_wording": "v9",
        "source_validator_required": True,
    }
    assert all(v is False for v in prep["security_state"].values())

    assert len(p["steps"]) == 10
    assert all("positive-auth-v9" in step["step_id"] for step in p["steps"])
    assert all(
        step["resource"]["exact_version"] == "provider-adapter-positive-auth.v9"
        and step["resource"]["exact_digest"] == RESOURCE
        for step in p["steps"]
    )
    for idx in (0, 6, 8):
        assert KEY in p["steps"][idx]["resource"]["resource_reference"]
        assert KEY in p["steps"][idx]["expected_postcondition"]
    assert "bound in the v9 resource" in p["steps"][3]["expected_postcondition"]
    assert "fresh v9 GitHub environment credential" in p["steps"][4]["expected_postcondition"]

    for idx in (0, 3):
        required = {
            (e["evidence_type"], e["exact_digest"])
            for e in p["steps"][idx]["required_evidence"]
            if e["binding_state"] == "BOUND"
        }
        assert ("authorization-plan.execution-progress", V8_STOPPED) in required
        assert ("authorization-plan.execution-progress", V8_RETIREMENT) in required
        assert (
            "auth.provider-adapter-positive-auth.admin-credential.absence-verified",
            V8_KEY_ABSENCE,
        ) in required
        assert (
            "auth.provider-adapter-positive-auth.github-binding.absence-verified",
            V8_GH_ABSENCE,
        ) in required

    active_plan = json.dumps(p, sort_keys=True)
    for stale in (
        "provider-adapter-positive-auth.v8",
        "POSITIVE_AUTH_V8_EPHEMERAL",
        "impl_handoff_provider_adapter_positive_auth_v8_ephemeral",
        "fresh v8 GitHub environment credential",
        "bound in the v8 resource",
        "fresh v7 GitHub environment credential",
        "bound in the v7 resource",
    ):
        assert stale not in active_plan, stale

    assert g["overall_state"] == "NOT_STARTED" and g["record_version"] == 1
    assert all(
        (
            s["authorization_state"],
            s["execution_state"],
            s["verification_state"],
            s["authorization_consumed"],
        )
        == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        for s in g["step_states"]
    )
    assert canonical_digest(step1_evidence) == STEP1_EVIDENCE
    assert step1_evidence["plan_id"] == p["plan_id"]
    assert step1_evidence["approval_id"] == a["approval_id"]
    assert step1_evidence["project_reference"] == PROJECT
    assert step1_evidence["credential_material_retained"] is False
    assert step1_evidence["credential_material_digest_recorded"] is False
    assert canonical_digest(step2_evidence) == STEP2_EVIDENCE
    assert step2_evidence["plan_id"] == p["plan_id"]
    assert step2_evidence["approval_id"] == a["approval_id"]
    assert step2_evidence["project_reference"] == PROJECT
    assert step2_evidence["repository"] == "AnonymousKoo/avuhz-infra"
    assert step2_evidence["environment_reference"] == "development"
    assert step2_evidence["credential_material_retained"] is False
    assert step2_evidence["credential_material_digest_recorded"] is False
    assert canonical_digest(step3_evidence) == STEP3_EVIDENCE
    assert step3_evidence["plan_id"] == p["plan_id"]
    assert step3_evidence["approval_id"] == a["approval_id"]
    assert step3_evidence["project_reference"] == PROJECT
    assert step3_evidence["repository"] == "AnonymousKoo/avuhz-infra"
    assert step3_evidence["environment_reference"] == "development"
    assert step3_evidence["sanitized_result"]["binding_present"] is True
    assert step3_evidence["credential_material_retained"] is False
    assert step3_evidence["credential_material_digest_recorded"] is False
    assert x["progress_digest"] == EXECUTION_PROGRESS == progress_digest(x)
    assert x["record_version"] == 4 and x["overall_state"] == "IN_PROGRESS"
    first, second, third = x["step_states"][:3]
    for state in (first, second, third):
        assert (
            state["authorization_state"],
            state["execution_state"],
            state["verification_state"],
            state["authorization_consumed"],
        ) == ("CONSUMED", "SUCCEEDED", "PASS", True)
    assert first["evidence"][0]["evidence_digest"] == STEP1_EVIDENCE
    assert second["evidence"][0]["evidence_digest"] == STEP2_EVIDENCE
    assert third["evidence"][0]["evidence_digest"] == STEP3_EVIDENCE
    assert all(
        (
            s["authorization_state"],
            s["execution_state"],
            s["verification_state"],
            s["authorization_consumed"],
        )
        == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        for s in x["step_states"][3:]
    )

    rendered = "\n".join(
        (B / (N + suffix)).read_text()
        for suffix in (
            ".resource.json",
            "-preparation.evidence.json",
            ".plan.json",
            ".progress.json",
            ".approval.json",
            "-step01-success.evidence.json",
            "-step02-success.evidence.json",
            "-step03-success.evidence.json",
            ".execution-progress.json",
        )
    )
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", rendered) is None
    assert "gnuqaefotwgkwurjpyik" not in rendered
    for forbidden in ("service_role", "Bearer eyJ"):
        assert forbidden not in rendered

    print(
        "DEVELOPMENT provider-adapter positive-auth v9: PASS "
        "(IN_PROGRESS; Steps 1-3 CONSUMED/SUCCEEDED/PASS; "
        "Step 4 pending; v8 cleanup bound; whole-plan stale active-version scan PASS)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
