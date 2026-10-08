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
N = "development-implementation-handoff-provider-adapter-positive-auth-v8"
V6 = "development-implementation-handoff-provider-adapter-positive-auth-v6"
V6_RETIRE = "development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v4"
V4_RECON = "development-implementation-handoff-provider-adapter-positive-auth-v4-github-binding-absence-reconciliation-v1"
V7 = "development-implementation-handoff-provider-adapter-positive-auth-v7"

PROJECT = "pwlhruwutoitnieactol"
KEY = "impl_handoff_provider_adapter_positive_auth_v8_ephemeral"
GH = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V8_EPHEMERAL"
CREATED = "2026-10-06T08:02:47Z"
START = "2026-10-06T12:00:00Z"
END = "2026-10-06T18:00:00Z"
APPROVED = "2026-10-06T08:26:51Z"
APPROVAL = "sha256:cbafe4d53befe00909c4cb0c086ce45b55f20dd7f299975e11a9a11ec2dbd770"

RESOURCE = "sha256:bbd92e25a085a41c3484730a1346970179f68f064245de0ee55ba8b8ab2c3a9b"
PREP = "sha256:d1c6cb704c67feb64875f5721e153a69f9d888424b5fe23a413d17af6fdcf1c9"
PLAN = "sha256:9ec8b204229a31c526870aa6b96776ede5ec474c592c72f814ce9ad5ed6eaba8"
PROGRESS = "sha256:ff8f112aa0bf270eea1ff02c06151307d943e50d3fdb894d9369a35aa27a7701"

EXECUTOR = "sha256:b94bafd10f7d77f79f618299d45ab8b4bfdec56c3238e2596635c86d5612e2a3"
WORKFLOW = "sha256:52e462c6414b5e4814037760dad27cea436a0229420a4b640f9cf1eec2df95f9"
V6_STOPPED = "sha256:c5d7bf0545ca10f453f4ac9775edccb1a2eb5e63efa7966225b95f5e5659df6f"
V6_FAILURE = "sha256:fdd233c078ee3e60bae0dd95128535526dc073759c54ee5cd21c8070cac15937"
V6_RETIREMENT = "sha256:b988dd98a2623e5831f007d65238940095725050a9cb8fc32e0dcba0cdb7ef0a"
V6_KEY_ABSENCE = "sha256:96e9371c01dcf15e061823c35df159d4627f79b06884af3c4edf6c48d08e2770"
V6_GH_ABSENCE = "sha256:a92e3926482aaed1ac19c241aef6d23b0079f47e1087c77bc65797dd11f99d76"
V4_RECON_PROGRESS = "sha256:57365c1791a9548568bb19515f70270e80b4ff1e4f3fa26f4560ebb6a3a572e9"
V4_RECON_EVIDENCE = "sha256:1c0b6abf5a3e49ffd9dec1b2573918f4e7046ae7dd0144e6d31645d09bcf2773"
V7_LATE = "sha256:5ea9bd9fade9a6b5674f190bc133a7aa70233e06c50193e7125f26303d8eca5b"
RECORDED = "2026-10-06T12:15:58Z"
STEP1 = "sha256:e2f4cc24eb5bbe974ee51d2086262af68314a29a136c5f630f949bbf6699c420"
STEP2_FAILURE = "sha256:eb2138a99751165302f01b9e063fdd883919c69c1df3f67db040c001879d9ae5"
STOPPED = "sha256:45c6d902458eee68f2f2782aaac82598d8cef7a2c022124691d3db4f08222b8d"
CORRECTION = "sha256:8ec18cfe0586881e072aa6157012c15fcc9be3cd80d359731e12f3f99e7d75a0"


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
    v6_x = load(V6 + ".execution-progress.json")
    v6_failure = load(V6 + "-step02-plan-integrity-failure.evidence.json")
    retire_x = load(V6_RETIRE + ".execution-progress.json")
    key_absence = load(V6_RETIRE + "-step2-success.evidence.json")
    gh_absence = load(V6_RETIRE + "-step3-success.evidence.json")
    recon_x = load(V4_RECON + ".execution-progress.json")
    recon_evidence = load(V4_RECON + "-step1-success.evidence.json")
    v7_late = load(V7 + "-late-window-rejection.evidence.json")
    e1 = load(N + "-step01-success.evidence.json")
    e2 = load(N + "-step02-plan-integrity-failure.evidence.json")
    x = load(N + ".execution-progress.json")
    correction = load(N + "-recording-step-id-correction-v1.evidence.json")

    validate_plan(p, S)
    validate_progress(p, g, S)
    validate_approval(p, a, S, START)
    validate_progress(p, x, S)

    assert r["contract_digest"] == RESOURCE == canonical_digest({k: v for k, v in r.items() if k != "contract_digest"})
    assert prep["evidence_digest"] == PREP == canonical_digest({k: v for k, v in prep.items() if k != "evidence_digest"})
    assert p["plan_digest"] == PLAN == plan_digest(p)
    assert g["progress_digest"] == PROGRESS == progress_digest(g)
    assert g == initial_progress(p, S, g["progress_id"], CREATED)

    assert p["plan_id"] == "4a7d18c6-2f71-4f7a-8c43-9e5d2b6f1a80"
    assert p["plan_version"] == 8
    assert p["definition_status"] == "READY_FOR_APPROVAL"
    assert p["environment"] == "DEVELOPMENT"
    assert p["authorization_window"] == {"binding_state": "BOUND", "starts_at": START, "expires_at": END}
    assert p["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"

    assert a["approval_id"] == "5bc4e639-f6d3-4fc4-8c74-1f10247111db"
    assert a["plan_id"] == p["plan_id"] and a["plan_version"] == 8
    assert a["plan_digest"] == PLAN and a["owner_identity"] == p["owner_identity"]
    assert a["decision"] == "APPROVE" and a["environment"] == "DEVELOPMENT"
    assert a["effective_at"] == START and a["expires_at"] == END
    assert a["approved_at"] == APPROVED and APPROVED < START
    assert a["status"] == "ACTIVE" and a["authority_scope"] == "EXACT_PLAN_ONLY"
    assert a["approval_digest"] == APPROVAL == approval_digest(a)

    assert r["project_reference"] == PROJECT and r["responsibility"] == "AUTH"
    assert r["fresh_provider_key_reference"] == KEY
    assert r["github_secret_binding_name"] == GH
    assert r["resource_version"] == "provider-adapter-positive-auth.v8"
    assert r["step5_executor_digest"] == EXECUTOR == raw(ROOT / "scripts/development_provider_adapter_positive_auth_v8.py")
    assert r["step5_workflow_digest"] == WORKFLOW == raw(ROOT / ".github/workflows/development-provider-adapter-positive-auth-v8-step5.yml")
    assert r["execution_rules"]["owner_approval_deadline"] == START
    assert r["execution_rules"]["window_expiry"] == END
    assert r["retry_authorized"] is False
    assert r["implementation_handoff_execution_authorized"] is False
    assert r["data_operation_authorized"] is False
    assert r["render_mutation_authorized"] is False
    assert r["n8n_operation_authorized"] is False
    assert r["staging_authorized"] is False
    assert r["production_authorized"] is False

    assert v6_x["overall_state"] == "STOPPED" and v6_x["progress_digest"] == V6_STOPPED
    assert canonical_digest(v6_failure) == V6_FAILURE
    assert retire_x["overall_state"] == "COMPLETED" and retire_x["progress_digest"] == V6_RETIREMENT
    assert canonical_digest(key_absence) == V6_KEY_ABSENCE
    assert canonical_digest(gh_absence) == V6_GH_ABSENCE
    assert recon_x["overall_state"] == "COMPLETED" and recon_x["progress_digest"] == V4_RECON_PROGRESS
    assert canonical_digest(recon_evidence) == V4_RECON_EVIDENCE

    assert canonical_digest(v7_late) == V7_LATE
    assert v7_late["outcome"] == "REJECTED_LATE_APPROVAL_NONCANONICALIZABLE"
    assert v7_late["approval_artifact_created"] is False
    assert v7_late["approval_canonicalized"] is False
    assert v7_late["continuation_rule"] == "CREATE_FRESH_FORWARD_ONLY_POSITIVE_AUTH_V8"
    assert all(v is False for v in v7_late["provider_effects"].values())

    assert r["required_v6_stopped_progress_digest"] == V6_STOPPED
    assert r["required_v6_plan_integrity_failure_evidence_digest"] == V6_FAILURE
    assert r["required_v6_retirement_progress_digest"] == V6_RETIREMENT
    assert r["required_v6_key_absence_evidence_digest"] == V6_KEY_ABSENCE
    assert r["required_v6_github_absence_evidence_digest"] == V6_GH_ABSENCE
    assert r["required_v4_binding_reconciliation_progress_digest"] == V4_RECON_PROGRESS
    assert r["required_v4_binding_reconciliation_evidence_digest"] == V4_RECON_EVIDENCE
    assert r["required_v7_late_rejection_evidence_digest"] == V7_LATE

    assert prep["canonical_main_at_preparation"] == "017bdb76273b7d1978a0960e835e0e7fc13b15e4"
    assert prep["resource_contract_digest"] == RESOURCE
    assert prep["source_bindings"]["executor"] == EXECUTOR
    assert prep["source_bindings"]["workflow"] == WORKFLOW
    assert prep["prerequisites"]["v7_late_rejection"] == V7_LATE
    assert prep["authorization_window"] == {"starts_at": START, "expires_at": END}
    assert all(v is False for v in prep["security_state"].values())

    assert len(p["steps"]) == 10
    assert all("positive-auth-v8" in step["step_id"] for step in p["steps"])
    assert all(step["resource"]["exact_version"] == "provider-adapter-positive-auth.v8" and step["resource"]["exact_digest"] == RESOURCE for step in p["steps"])
    for idx in (0, 6, 8):
        assert KEY in p["steps"][idx]["resource"]["resource_reference"]
        assert KEY in p["steps"][idx]["expected_postcondition"]
    assert "bound in the v7 resource" in p["steps"][3]["expected_postcondition"]
    assert "fresh v7 GitHub environment credential" in p["steps"][4]["expected_postcondition"]
    for idx in (0, 3):
        assert any(e["evidence_type"] == "auth.provider-adapter-positive-auth-v7.late-approval-rejected" and e["exact_digest"] == V7_LATE for e in p["steps"][idx]["required_evidence"])

    assert g["overall_state"] == "NOT_STARTED" and g["record_version"] == 1
    assert all((s["authorization_state"], s["execution_state"], s["verification_state"], s["authorization_consumed"]) == ("PENDING", "NOT_STARTED", "NOT_STARTED", False) for s in g["step_states"])

    assert correction["evidence_digest"] == CORRECTION == canonical_digest(
        {k: v for k, v in correction.items() if k != "evidence_digest"}
    )
    assert correction["classification"] == "REPOSITORY_STEP_ID_BINDING_CORRECTION_NO_PROVIDER_EFFECT"
    assert correction["original_record"]["defect"] == "STEP_ID_BINDING_MISMATCH"
    assert correction["corrected_record"]["step1_evidence_digest"] == STEP1
    assert correction["corrected_record"]["step2_evidence_digest"] == STEP2_FAILURE
    assert correction["corrected_record"]["execution_progress_digest"] == STOPPED
    assert all(v is False for k, v in correction["correction_scope"].items() if k != "repository_only")
    assert correction["correction_scope"]["repository_only"] is True

    assert canonical_digest(e1) == STEP1
    assert e1["step_id"] == p["ordered_step_ids"][0]
    assert e1["outcome"] == "SUCCEEDED_VERIFIED"
    assert e1["classification"] == "DEDICATED_PROVIDER_ADAPTER_POSITIVE_AUTH_V8_CREDENTIAL_CREATED"
    assert e1["owner_confirmed_created"] is True
    assert e1["credential_material_retained"] is False
    assert canonical_digest(e2) == STEP2_FAILURE
    assert e2["step_id"] == p["ordered_step_ids"][1]
    assert e2["outcome"] == "FAILED_PREEXECUTION_PLAN_INTEGRITY"
    assert e2["safe_error_code"] == "PLAN_STATE_INVALID"
    assert e2["sanitized_result"]["binding_created"] is False
    assert e2["sanitized_result"]["provider_mutation_performed"] is False
    assert e2["sanitized_result"]["stale_execution_references"] == [
        "step04.expected_postcondition.references-v7-resource",
        "step05.expected_postcondition.references-fresh-v7-github-credential",
    ]

    assert x["progress_digest"] == STOPPED == progress_digest(x)
    assert [s["step_id"] for s in x["step_states"]] == p["ordered_step_ids"]
    assert x["overall_state"] == "STOPPED" and x["record_version"] == 5
    assert x["updated_at"] == RECORDED
    assert (x["step_states"][0]["authorization_state"], x["step_states"][0]["execution_state"], x["step_states"][0]["verification_state"], x["step_states"][0]["authorization_consumed"]) == ("CONSUMED", "SUCCEEDED", "PASS", True)
    assert (x["step_states"][1]["authorization_state"], x["step_states"][1]["execution_state"], x["step_states"][1]["verification_state"], x["step_states"][1]["authorization_consumed"]) == ("CONSUMED", "FAILED", "FAIL", True)
    assert x["step_states"][1]["safe_error_code"] == "PLAN_STATE_INVALID"
    assert all((s["authorization_state"], s["execution_state"], s["verification_state"], s["authorization_consumed"]) == ("BLOCKED", "NOT_STARTED", "NOT_STARTED", False) for s in x["step_states"][2:])

    rendered = "\n".join((B / (N + suffix)).read_text() for suffix in (".resource.json", "-preparation.evidence.json", ".plan.json", ".progress.json", ".approval.json", "-step01-success.evidence.json", "-step02-plan-integrity-failure.evidence.json", ".execution-progress.json", "-recording-step-id-correction-v1.evidence.json"))
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", rendered) is None
    assert "gnuqaefotwgkwurjpyik" not in rendered
    for forbidden in ("service_role", "Bearer eyJ"):
        assert forbidden not in rendered

    print("DEVELOPMENT provider-adapter positive-auth v8: PASS (STOPPED; Step 1 credential created; Step 2 failed closed before GitHub binding on stale v7 execution wording; Steps 3-10 blocked; retirement required)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
