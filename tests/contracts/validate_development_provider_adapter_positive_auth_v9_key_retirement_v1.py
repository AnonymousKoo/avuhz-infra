from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

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

ROOT = Path(__file__).resolve().parents[2]
B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v9-key-retirement-v1"

RESOURCE = "sha256:a98671171b743883bd9124fa018f59d20b53f19f7e33587de5ff7fa7a4286da5"
PREP = "sha256:b85c459dc213ba03b66e6db31c349c1db0b9efa63553c5650ad23e8fd3408ed3"
PLAN = "sha256:9c200ac9b4ab7d81556b00dd6caa81e7f22c5a97969ac7c00c0446ee6df135d3"
PROGRESS = "sha256:54ab97062d88405a34ed1b17482a6ac511113a1886a2d50767655a373fc23dea"
STEP1_EVIDENCE = "sha256:053069275137f842faae2c807b479561165180df28d0cc18c92770f1be5847e5"
EXECUTION_PROGRESS = "sha256:b6d26b98a111106011a2c7d8cc86e2e729b0d0ed2213be93484b210ff1de90a6"
CREATED = "2026-10-06T18:02:00Z"
START = "2026-10-06T18:15:00Z"
END = "2026-10-06T23:00:00Z"
APPROVED = "2026-10-06T18:07:15Z"
APPROVAL = "sha256:43672c0a6a2ea21837716413d961c18d6535e303ad7125611c7216a9c3a7b996"
V9_STOP = "sha256:3f14c612807b8b956e30bf972c46090356a697d916036ade41d2096716e17417"
V9_STEP1 = "sha256:e794f45457172d917f6dded302231edeb7369253d54d1a51aa7f503eb7c84f10"
V9_STEP2 = "sha256:9576eddf1b2a55598cdfd4052126d592b21be652ceba4b2488641d046f600e7a"
V9_STEP5_FAIL = "sha256:d931a7de4f6a41bcfd7f072b30f86ecafa4cccc2a0cca5f4e6387fa942cf687a"


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
    step1_evidence = load(N + "-step1-success.evidence.json")
    x = load(N + ".execution-progress.json")

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

    assert p["definition_status"] == "READY_FOR_APPROVAL"
    assert p["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert p["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": START,
        "expires_at": END,
    }
    assert p["target"]["project_reference"] == "pwlhruwutoitnieactol"
    assert p["target"]["responsibility"] == "AUTH"

    assert a["approval_id"] == "6c9a2e41-7d53-4f8b-a261-9e3c5d7b1f40"
    assert a["plan_id"] == p["plan_id"]
    assert a["plan_version"] == 1
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

    assert prep["canonical_main_at_preparation"] == "ad2732012ec4e23ffc918eeeece69cdd0db01a84"
    assert prep["resource_contract_digest"] == RESOURCE
    assert prep["authorization_window"] == {"starts_at": START, "expires_at": END}
    assert prep["prerequisites"] == {
        "v9_stopped_progress": V9_STOP,
        "v9_step1_key_creation": V9_STEP1,
        "v9_step2_github_binding_creation": V9_STEP2,
        "v9_step5_authority_failure": V9_STEP5_FAIL,
        "v9_overall_state": "STOPPED",
        "v9_github_binding_created": True,
        "v9_step5_provider_mutation_attempted": False,
    }
    assert all(v is False for v in prep["security_state"].values())

    assert r["lineage"]["v9_execution_progress_digest"] == V9_STOP
    assert r["lineage"]["v9_step1_key_creation_evidence_digest"] == V9_STEP1
    assert r["lineage"]["v9_step2_github_binding_creation_evidence_digest"] == V9_STEP2
    assert r["lineage"]["v9_step5_authority_failure_evidence_digest"] == V9_STEP5_FAIL
    assert r["lineage"]["v9_overall_state"] == "STOPPED"
    assert r["lineage"]["v9_provider_mutation_attempted_in_step5"] is False
    assert r["lineage"]["v9_session_issued_in_step5"] is False
    assert r["target_key_reference"] == "impl_handoff_provider_adapter_positive_auth_v9_ephemeral"
    assert r["github_secret_binding_name"] == (
        "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V9_EPHEMERAL"
    )
    assert r["authorized_counts"] == {
        "supabase_key_delete": 1,
        "supabase_key_absence_read": 1,
        "github_environment_secret_delete": 1,
        "github_secret_absence_read": 1,
        "credential_create": 0,
        "session_issue": 0,
        "token_issue": 0,
        "implementation_handoff_execute": 0,
    }

    assert [s["operation"] for s in p["steps"]] == [
        "provider.auth-admin-credential.delete-dedicated-secret-key",
        "provider.auth-admin-credential.verify-dedicated-secret-key-absent",
        "provider.auth-secret-binding.delete-github-environment-reference",
        "provider.auth-secret-binding.verify-github-environment-reference-absent",
    ]
    assert all(
        s["resource"]["exact_version"] == "provider-adapter-positive-auth-v9-key-retirement.v1"
        and s["resource"]["exact_digest"] == RESOURCE
        for s in p["steps"]
    )
    step1 = p["steps"][0]
    assert any(
        e["evidence_type"] == "auth.provider-adapter-positive-auth.admin-credential.created"
        and e["exact_digest"] == V9_STEP1
        for e in step1["required_evidence"]
    )
    assert any(
        e["evidence_type"] == "authorization-plan.execution-progress"
        and e["exact_digest"] == V9_STOP
        for e in step1["required_evidence"]
    )
    assert any(
        e["evidence_type"] == "auth.provider-adapter-positive-auth.live-verified-logout-accepted"
        and e["exact_digest"] == V9_STEP5_FAIL
        for e in step1["required_evidence"]
    )
    assert any(
        e["evidence_type"] == "auth.provider-adapter-positive-auth-v9.key-retirement-v1.prepared"
        and e["exact_digest"] == PREP
        for e in step1["required_evidence"]
    )

    assert g["overall_state"] == "NOT_STARTED"
    assert g["record_version"] == 1
    assert canonical_digest(step1_evidence) == STEP1_EVIDENCE
    assert step1_evidence["plan_id"] == p["plan_id"]
    assert step1_evidence["approval_id"] == a["approval_id"]
    assert step1_evidence["project_reference"] == "pwlhruwutoitnieactol"
    assert step1_evidence["sanitized_result"] == {
        "key_name": "impl_handoff_provider_adapter_positive_auth_v9_ephemeral",
        "retirement_reported_by_owner": True,
        "credential_material_observed": False,
        "other_key_change_reported": False,
    }
    assert step1_evidence["independent_absence_verification_required"] is True
    assert x["progress_digest"] == EXECUTION_PROGRESS == progress_digest(x)
    assert x["record_version"] == 2
    assert x["overall_state"] == "IN_PROGRESS"
    first = x["step_states"][0]
    assert (
        first["authorization_state"],
        first["execution_state"],
        first["verification_state"],
        first["authorization_consumed"],
    ) == ("CONSUMED", "SUCCEEDED", "PASS", True)
    assert first["evidence"][0]["evidence_digest"] == STEP1_EVIDENCE
    assert all(
        (
            state["authorization_state"],
            state["execution_state"],
            state["verification_state"],
            state["authorization_consumed"],
        ) == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        for state in x["step_states"][1:]
    )

    rendered = "\n".join(
        (B / (N + suffix)).read_text()
        for suffix in (
            ".resource.json",
            "-preparation.evidence.json",
            ".plan.json",
            ".progress.json",
            ".approval.json",
            "-step1-success.evidence.json",
            ".execution-progress.json",
        )
    )
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", rendered) is None
    assert "gnuqaefotwgkwurjpyik" not in rendered
    assert "service_role" not in rendered
    assert "Bearer eyJ" not in rendered

    print(
        "DEVELOPMENT provider-adapter positive-auth v9 key retirement v1: PASS "
        "(IN_PROGRESS; Step 1 CONSUMED/SUCCEEDED/PASS; Step 2 pending; no auth retry)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
