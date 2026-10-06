#!/usr/bin/env python3
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
from avuhz_engineering.evidence_digest import evidence_digest
from avuhz_runtime.implementation_handoff import canonical_digest

ROOT = Path(__file__).resolve().parents[2]
B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v10"

RESOURCE = "sha256:cf26ec78208c27b9f878a7446c50214d16e1a30568bf3385fb650a58e49022a8"
PREP = "sha256:6564ac9afc3e24a4dd9d84883f8eaf64d9f3960933bfb2121a946e7f50d32931"
PLAN = "sha256:909276b7d894f68d01c0fadd1b4f8e1f354c2914d6f2cd658926aa099e977414"
PROGRESS = "sha256:4a5813efcacb2298e8b6aa35b0f9bd139f286df898fe4b6bbeff5582f7e553f4"
STEP1_EVIDENCE = "sha256:c90ee6dae85bc880703dd00dcd0a5813f92e86fa015b4c26392764601983eac4"
STEP2_EVIDENCE = "sha256:deac6b75bcad238ff7c47a91b6207ce3d0dee636243f429c9a9f85bd07d965df"
EXECUTION_PROGRESS = "sha256:dd1e950ba964a97609272d15a7faad64bcc9e98f8c474c0fe8ebb85d18f4111f"
EXECUTOR = "sha256:38aa2b6b57fddb3e6b9627c2686b4f7ab944ebbd2c5d3bc225434a78ecd21dba"
WORKFLOW = "sha256:66a1439bba1f9a372d70566a8d6b2bec47f15b046f4d0739dd5b70b3200c1d4b"
EVIDENCE_HELPER = "sha256:ceed8cb7681f0fc195c7bfff9cd4dd06dbaee728efbf29f52e61b982acd53d34"
CREATED = "2026-10-06T20:10:00Z"
START = "2026-10-06T20:45:00Z"
END = "2026-10-06T23:00:00Z"
APPROVED = "2026-10-06T20:25:29Z"
APPROVAL = "sha256:740a797f1523092658ca40ee422d0bba97171b980e1f28c735d66fa36b2beaa0"

V9_STOP = "sha256:3f14c612807b8b956e30bf972c46090356a697d916036ade41d2096716e17417"
V9_FAILURE = "sha256:d931a7de4f6a41bcfd7f072b30f86ecafa4cccc2a0cca5f4e6387fa942cf687a"
V9_RETIREMENT = "sha256:f63c3c1ce9d3cd450dc74d77f5b42324f257b485305eaddac815458a54ae349e"
V9_KEY_ABSENCE = "sha256:02186a947b099da0f9854a3b6c056cf7342b54d631edeb77b20803f31d6bda0e"
V9_GITHUB_ABSENCE = "sha256:38d525130844b42194dd222c85ceae61788aac42b96ca8331148f3d9316f92e0"


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
    x = load(N + ".execution-progress.json")

    validate_plan(p, S)
    validate_progress(p, g, S)
    validate_progress(p, x, S)
    validate_approval(p, a, S, START)

    assert r["contract_digest"] == RESOURCE == canonical_digest(
        {k: v for k, v in r.items() if k != "contract_digest"}
    )
    assert prep["evidence_digest"] == PREP == evidence_digest(prep)
    assert p["plan_digest"] == PLAN == plan_digest(p)
    assert g["progress_digest"] == PROGRESS == progress_digest(g)
    assert g == initial_progress(p, S, g["progress_id"], CREATED)

    assert p["plan_id"] == "c6a4f231-8d5e-4b79-a210-7e3c9d6f5a42"
    assert p["plan_version"] == 10
    assert p["definition_status"] == "READY_FOR_APPROVAL"
    assert p["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert p["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": START,
        "expires_at": END,
    }
    assert p["target"]["project_reference"] == "pwlhruwutoitnieactol"
    assert p["target"]["responsibility"] == "AUTH"

    assert a["approval_id"] == "a4e7c2d9-51b8-4f63-9c20-7d1e5a8b3f46"
    assert a["plan_id"] == p["plan_id"]
    assert a["plan_version"] == 10
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

    assert r["resource_version"] == "provider-adapter-positive-auth.v10"
    assert r["boundary"] == N
    assert r["fresh_provider_key_reference"] == (
        "impl_handoff_provider_adapter_positive_auth_v10_ephemeral"
    )
    assert r["github_secret_binding_name"] == (
        "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V10_EPHEMERAL"
    )
    assert r["step5_executor_digest"] == EXECUTOR == raw(
        ROOT / "scripts/development_provider_adapter_positive_auth_v10.py"
    )
    assert r["step5_workflow_digest"] == WORKFLOW == raw(
        ROOT / ".github/workflows/development-provider-adapter-positive-auth-v10-step5.yml"
    )
    assert r["evidence_digest_source_digest"] == EVIDENCE_HELPER == raw(
        ROOT / "src/avuhz_engineering/evidence_digest.py"
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

    assert prep["canonical_source_main"] == "d5bb339efcbb3e1281aa886d882e95e6bac1a60f"
    assert prep["resource_contract_digest"] == RESOURCE
    assert prep["authorization_window"] == {"starts_at": START, "expires_at": END}
    assert prep["predecessor_state"] == {
        "v9_overall_state": "STOPPED",
        "v9_stopped_progress_digest": V9_STOP,
        "v9_step5_authority_failure_evidence_digest": V9_FAILURE,
        "v9_retirement_v1_overall_state": "COMPLETED",
        "v9_retirement_v1_progress_digest": V9_RETIREMENT,
        "v9_key_absence_evidence_digest": V9_KEY_ABSENCE,
        "v9_github_absence_evidence_digest": V9_GITHUB_ABSENCE,
    }
    assert prep["whole_boundary_integrity"]["active_version"] == "v10"
    assert prep["whole_boundary_integrity"]["stale_active_v9_namespace_allowed"] is False
    assert prep["whole_boundary_integrity"]["evidence_body_digest_helper_required"] is True
    assert prep["whole_boundary_integrity"]["evidence_digest_source_digest"] == EVIDENCE_HELPER
    assert all(v is False for v in prep["security_state"].values())

    v9_stop = load(
        "development-implementation-handoff-provider-adapter-positive-auth-v9.execution-progress.json"
    )
    v9_failure = load(
        "development-implementation-handoff-provider-adapter-positive-auth-v9-step05-authority-preflight-failure.evidence.json"
    )
    v9_retirement = load(
        "development-implementation-handoff-provider-adapter-positive-auth-v9-key-retirement-v1.execution-progress.json"
    )
    v9_key = load(
        "development-implementation-handoff-provider-adapter-positive-auth-v9-key-retirement-v1-step2-success.evidence.json"
    )
    v9_github = load(
        "development-implementation-handoff-provider-adapter-positive-auth-v9-key-retirement-v1-step4-success.evidence.json"
    )
    assert v9_stop["overall_state"] == "STOPPED"
    assert v9_stop["progress_digest"] == V9_STOP == r["required_v9_stopped_progress_digest"]
    assert evidence_digest(v9_failure) == V9_FAILURE == r["required_v9_step5_authority_failure_evidence_digest"]
    assert v9_failure["safe_error_code"] == "AUTHORITY_INVALID"
    assert v9_failure["sanitized_result"]["provider_mutation_attempted"] is False
    assert v9_retirement["overall_state"] == "COMPLETED"
    assert v9_retirement["progress_digest"] == V9_RETIREMENT == r["required_v9_retirement_progress_digest"]
    assert evidence_digest(v9_key) == V9_KEY_ABSENCE == r["required_v9_key_absence_evidence_digest"]
    assert evidence_digest(v9_github) == V9_GITHUB_ABSENCE == r["required_v9_github_absence_evidence_digest"]

    assert len(p["steps"]) == 10
    assert [step["ordinal"] for step in p["steps"]] == list(range(1, 11))
    assert all(
        step["resource"]["exact_version"] == "provider-adapter-positive-auth.v10"
        and step["resource"]["exact_digest"] == RESOURCE
        for step in p["steps"]
    )
    for idx in (0, 3):
        required = {(e["evidence_type"], e["exact_digest"]) for e in p["steps"][idx]["required_evidence"]}
        assert ("auth.provider-adapter-positive-auth-v10.preparation.observed", PREP) in required
        assert ("authorization-plan.execution-progress", V9_STOP) in required
        assert ("auth.provider-adapter-positive-auth.live-verified-logout-accepted", V9_FAILURE) in required
        assert ("authorization-plan.execution-progress", V9_RETIREMENT) in required
        assert ("auth.provider-adapter-positive-auth.admin-credential.absence-verified", V9_KEY_ABSENCE) in required
        assert ("auth.provider-adapter-positive-auth.github-binding.absence-verified", V9_GITHUB_ABSENCE) in required

    assert g["overall_state"] == "NOT_STARTED"
    assert g["record_version"] == 1
    assert all(
        (
            state["authorization_state"],
            state["execution_state"],
            state["verification_state"],
            state["authorization_consumed"],
        ) == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        for state in g["step_states"]
    )

    assert evidence_digest(step1_evidence) == STEP1_EVIDENCE
    assert step1_evidence["plan_id"] == p["plan_id"]
    assert step1_evidence["approval_id"] == a["approval_id"]
    assert step1_evidence["project_reference"] == "pwlhruwutoitnieactol"
    assert step1_evidence["owner_confirmed_created"] is True
    assert step1_evidence["credential_material_retained"] is False
    assert step1_evidence["sanitized_result"] == {
        "classification": "DEDICATED_PROVIDER_ADAPTER_POSITIVE_AUTH_V10_CREDENTIAL_CREATED",
        "resource_reference": "supabase:pwlhruwutoitnieactol:secret-key:impl_handoff_provider_adapter_positive_auth_v10_ephemeral",
        "provider_key_kind": "secret",
        "logical_key_name": "impl_handoff_provider_adapter_positive_auth_v10_ephemeral",
        "dedicated_scope": "development-provider-adapter-positive-auth-v10-only",
    }

    assert evidence_digest(step2_evidence) == STEP2_EVIDENCE
    assert step2_evidence["plan_id"] == p["plan_id"]
    assert step2_evidence["approval_id"] == a["approval_id"]
    assert step2_evidence["repository"] == "AnonymousKoo/avuhz-infra"
    assert step2_evidence["environment_reference"] == "development"
    assert step2_evidence["credential_material_retained"] is False
    assert step2_evidence["sanitized_result"] == {
        "classification": "PROVIDER_ADAPTER_POSITIVE_AUTH_V10_GITHUB_BINDING_CREATED",
        "resource_reference": "github:AnonymousKoo/avuhz-infra:environment:development:secret:AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V10_EPHEMERAL",
        "repository": "AnonymousKoo/avuhz-infra",
        "environment": "development",
        "secret_name": "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V10_EPHEMERAL",
        "binding_created": True,
        "source_credential_reference": "supabase:pwlhruwutoitnieactol:secret-key:impl_handoff_provider_adapter_positive_auth_v10_ephemeral",
    }

    assert x["progress_digest"] == EXECUTION_PROGRESS == progress_digest(x)
    assert x["record_version"] == 3
    assert x["overall_state"] == "IN_PROGRESS"
    first, second = x["step_states"][:2]
    for state in (first, second):
        assert (
            state["authorization_state"],
            state["execution_state"],
            state["verification_state"],
            state["authorization_consumed"],
        ) == ("CONSUMED", "SUCCEEDED", "PASS", True)
    assert first["evidence"][0]["evidence_digest"] == STEP1_EVIDENCE
    assert second["evidence"][0]["evidence_digest"] == STEP2_EVIDENCE
    assert all(
        (
            state["authorization_state"],
            state["execution_state"],
            state["verification_state"],
            state["authorization_consumed"],
        ) == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        for state in x["step_states"][2:]
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
            ".execution-progress.json",
        )
    )
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", rendered) is None
    assert "gnuqaefotwgkwurjpyik" not in rendered
    assert "Bearer eyJ" not in rendered
    assert "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V9_EPHEMERAL" not in p.__str__()
    assert "impl_handoff_provider_adapter_positive_auth_v9_ephemeral" not in p.__str__()

    print(
        "DEVELOPMENT provider-adapter positive-auth v10: PASS "
        "(IN_PROGRESS; Steps 1-2 CONSUMED/SUCCEEDED/PASS; Step 3 pending; "
        "credential material never retained)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
