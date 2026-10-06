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
N = "development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v1"

RESOURCE = "sha256:3083d8e1b34fc5b806ab248deb4cda5aa4d43a0bfe757ba01abc70e7d50b2260"
PREP = "sha256:506e6ddf8c2b47397bac023cd128e757c51698f7e5ad36296ccffbf9c8396f28"
PLAN = "sha256:007735081fd7c4bc3d122a3475ff97d3a7a8983b60016c1347a45e0ad89dd5cb"
PROGRESS = "sha256:a598ce72e22cb9082915b251860b3966d753b589dea6095e24f75920d0a254ea"
CREATED = "2026-10-06T21:50:00Z"
START = "2026-10-06T22:15:00Z"
END = "2026-10-06T23:00:00Z"
APPROVED = "2026-10-06T21:55:36Z"
APPROVAL = "sha256:23ca76ffd209a9c2e76d38416b952b1e7319b6d30789fbd1fde4a83ffb9474cb"
STEP1_EVIDENCE = "sha256:35044d1166daa983e06781334c05d0002f877992cc9d9ca2ebe6a8bff597815e"
STEP2_EVIDENCE = "sha256:cfaeca271afa9a51db7ff0390f45548a6e7b9e1864436c51e7d3acd1a89ae0e7"
EXECUTION_PROGRESS = "sha256:980bd163d03623f901d1f80e0fd25fbb70a8e06f1e3de1620af29cfb56c6e5a2"
V10_STOP = "sha256:38e26a596ebe6d3429c60f5f5cc8a49d13dc2da8868eb1f4bc75c42a11c74cd0"
V10_STEP1 = "sha256:c90ee6dae85bc880703dd00dcd0a5813f92e86fa015b4c26392764601983eac4"
V10_STEP2 = "sha256:deac6b75bcad238ff7c47a91b6207ce3d0dee636243f429c9a9f85bd07d965df"
V10_STEP5_FAIL = "sha256:d55ff4f7bcca05b03c5fc878f5fa2a09d95cd3b36b1716e181e4cd8bf3df2228"


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
    step2_evidence = load(N + "-step2-success.evidence.json")
    x = load(N + ".execution-progress.json")

    validate_plan(p, S)
    validate_progress(p, g, S)
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
    assert p["plan_id"] == "8d3a6f21-5c74-4b9e-a102-7f6d3c5e8b41"

    assert a["approval_id"] == "7e4b2c91-6d35-4f8a-b120-9c5e3d7a6f41"
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

    assert prep["canonical_main_at_preparation"] == "a0d8974bac32a51198df320025a6bf1261383fb6"
    assert prep["resource_contract_digest"] == RESOURCE
    assert prep["authorization_window"] == {"starts_at": START, "expires_at": END}
    assert prep["prerequisites"] == {
        "v10_stopped_progress": V10_STOP,
        "v10_step1_key_creation": V10_STEP1,
        "v10_step2_github_binding_creation": V10_STEP2,
        "v10_step5_authority_failure": V10_STEP5_FAIL,
        "v10_overall_state": "STOPPED",
        "v10_github_binding_created": True,
        "v10_step5_provider_mutation_attempted": False,
    }
    assert all(v is False for v in prep["security_state"].values())

    assert r["lineage"]["v10_execution_progress_digest"] == V10_STOP
    assert r["lineage"]["v10_step1_key_creation_evidence_digest"] == V10_STEP1
    assert r["lineage"]["v10_step2_github_binding_creation_evidence_digest"] == V10_STEP2
    assert r["lineage"]["v10_step5_authority_failure_evidence_digest"] == V10_STEP5_FAIL
    assert r["lineage"]["v10_overall_state"] == "STOPPED"
    assert r["lineage"]["v10_provider_mutation_attempted_in_step5"] is False
    assert r["lineage"]["v10_session_issued_in_step5"] is False
    assert r["target_key_reference"] == "impl_handoff_provider_adapter_positive_auth_v10_ephemeral"
    assert r["github_secret_binding_name"] == (
        "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V10_EPHEMERAL"
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
        s["resource"]["exact_version"] == "provider-adapter-positive-auth-v10-key-retirement.v1"
        and s["resource"]["exact_digest"] == RESOURCE
        for s in p["steps"]
    )
    step1 = p["steps"][0]
    assert any(
        e["evidence_type"] == "auth.provider-adapter-positive-auth.admin-credential.created"
        and e["exact_digest"] == V10_STEP1
        for e in step1["required_evidence"]
    )
    assert any(
        e["evidence_type"] == "authorization-plan.execution-progress"
        and e["exact_digest"] == V10_STOP
        for e in step1["required_evidence"]
    )
    assert any(
        e["evidence_type"] == "auth.provider-adapter-positive-auth.live-verified-logout-accepted"
        and e["exact_digest"] == V10_STEP5_FAIL
        for e in step1["required_evidence"]
    )
    assert any(
        e["evidence_type"] == "auth.provider-adapter-positive-auth-v10.key-retirement-v1.prepared"
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
        "key_name": "impl_handoff_provider_adapter_positive_auth_v10_ephemeral",
        "retirement_reported_by_owner": True,
        "credential_material_observed": False,
        "other_key_change_reported": False,
    }
    assert step1_evidence["independent_absence_verification_required"] is True
    assert canonical_digest(step2_evidence) == STEP2_EVIDENCE
    assert step2_evidence["plan_id"] == p["plan_id"]
    assert step2_evidence["approval_id"] == a["approval_id"]
    assert step2_evidence["project_reference"] == "pwlhruwutoitnieactol"
    assert step2_evidence["sanitized_result"] == {
        "key_name": "impl_handoff_provider_adapter_positive_auth_v10_ephemeral",
        "absence_reported_by_owner": True,
        "credential_material_observed": False,
        "other_key_inspected": False,
        "provider_mutation_performed": False,
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
            "-step1-success.evidence.json",
            "-step2-success.evidence.json",
            ".execution-progress.json",
        )
    )
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", rendered) is None
    assert "gnuqaefotwgkwurjpyik" not in rendered
    assert "service_role" not in rendered
    assert "Bearer eyJ" not in rendered

    print(
        "DEVELOPMENT provider-adapter positive-auth v10 key retirement v1: PASS "
        "(IN_PROGRESS; Steps 1-2 CONSUMED/SUCCEEDED/PASS; Step 3 pending; no auth retry)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
