#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import validate_development_provider_adapter_positive_auth_v14_continuation_v1 as continuation
from avuhz_engineering.authorization_plan import initial_progress, plan_digest, progress_digest, validate_plan, validate_progress
from avuhz_engineering.evidence_digest import evidence_digest
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v14-continuation-v1-corrective-cleanup-retirement-v1"

PLAN_ID = "84c2e761-3d95-4ab8-b520-6f1e9d3c7a42"
PLAN_DIGEST = "sha256:e57d45366fdfb740d75dd4d044a1a1f94e8f7064fb59d7df1346037d3f9502f4"
RESOURCE_DIGEST = "sha256:9351b23974715a563f279cef43202ac967e98d6c5a6817483d6434706dda158e"
PREP_DIGEST = "sha256:c7d75fe424b8228f2bdc93ddfc3046b1386481b010a10be5261609a2c8e2a7a5"
PROGRESS_ID = "5d8a3c71-2e64-4fb9-a310-7c5e1d8b6f24"
PROGRESS_DIGEST = "sha256:e45e0e05b12b9d9bc10ff40c8868fde7b8f324e340f42ee134c3de813ace5481"
CREATED = "2026-10-08T11:42:33Z"
START = "2026-10-08T12:00:00Z"
END = "2026-10-08T16:00:00Z"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
KEY = "impl_handoff_provider_adapter_positive_auth_v14_ephemeral"
GH = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V14_EPHEMERAL"
FAILURE = "sha256:63c1246fb571cc86cf01bbb994942c36d4438f9cd720028114abd53d3b5144aa"
STOPPED = "sha256:9bcf3c8a65985a96c3f4f1a8f9095f376a92be73639ea3ea414621551c2e100b"


def load(suffix: str) -> dict:
    return json.loads((B / f"{N}{suffix}").read_text())


def main() -> int:
    continuation.main()
    resource = load(".resource.json")
    prep = load("-preparation.evidence.json")
    plan = load(".plan.json")
    progress = load(".progress.json")

    validate_plan(plan, S)
    validate_progress(plan, progress, S)

    assert resource["contract_digest"] == RESOURCE_DIGEST == canonical_digest(
        {k: v for k, v in resource.items() if k != "contract_digest"}
    )
    assert prep["evidence_digest"] == PREP_DIGEST == evidence_digest(prep)
    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 1
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["authorization_window"] == {
        "binding_state": "BOUND", "starts_at": START, "expires_at": END
    }
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"

    assert resource["project_reference"] == PROJECT
    assert resource["fresh_provider_key_reference"] == KEY
    assert resource["github_secret_binding_name"] == GH
    assert resource["lineage"]["stopped_continuation_plan_id"] == "7fb19d54-8a32-4c6e-b741-2d9f5a03c861"
    assert resource["lineage"]["stopped_continuation_execution_progress_digest"] == STOPPED
    assert resource["lineage"]["stopped_continuation_step1_failure_evidence_digest"] == FAILURE
    assert resource["lineage"]["failed_workflow_run_id"] == 37770555664
    assert resource["lineage"]["failed_execution_sha"] == "2c9c92e1f49f6e911600978d53f33e29b5550f7b"

    session = resource["session_state_verification"]
    assert session["interaction_surface"] == "supabase.mcp.execute_sql"
    assert session["credential_class"] == "NONE"
    assert session["query_count"] == 1
    assert session["result_fields"] == ["session_count", "refresh_token_count"]
    assert session["expected_result"] == {"session_count": 0, "refresh_token_count": 0}
    assert session["aggregate_only"] is True
    assert session["raw_rows_authorized"] is False
    assert session["additional_sql_authorized"] is False
    assert session["retry_authorized"] is False

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
    assert resource["failure_handling"]["unknown_session_state_at_entry"] is True
    assert resource["failure_handling"]["zero_state_required_before_retirement"] is True
    assert resource["failure_handling"]["retry_failed_positive_auth_authorized"] is False

    assert prep["provider_authority"] == "NONE"
    assert prep["external_provider_contact"] == "PROHIBITED"
    assert prep["canonical_main_at_start"] == "c3340647ba7e46deac9b2c7d03734490f4b322ff"
    assert prep["lineage"]["stopped_continuation_execution_progress_digest"] == STOPPED
    assert prep["lineage"]["stopped_continuation_step1_failure_evidence_digest"] == FAILURE
    assert all(value is False for value in prep["security_state"].values())

    steps = plan["steps"]
    assert len(steps) == 5
    assert [s["ordinal"] for s in steps] == [1,2,3,4,5]
    assert [s["execution_class"] for s in steps] == [
        "PROVIDER_READ","PROVIDER_MUTATION","PROVIDER_MUTATION","PROVIDER_READ","PROVIDER_READ"
    ]
    assert steps[0]["operation"] == "provider.auth-session-state.inspect-read-only-via-supabase-mcp"
    assert steps[0]["credential_policy"] == {
        "permitted": False, "allowed_classes": ["NONE"], "values_stored": False
    }
    assert KEY in steps[1]["resource"]["resource_reference"]
    assert GH in steps[2]["resource"]["resource_reference"]
    assert KEY in steps[3]["resource"]["resource_reference"]
    assert GH in steps[4]["resource"]["resource_reference"]
    for idx in range(1,5):
        assert steps[idx]["dependency_step_ids"] == [steps[idx-1]["step_id"]]

    first = {(x["evidence_type"], x["exact_digest"]) for x in steps[0]["required_evidence"]}
    for item in (
        ("auth.provider-adapter-positive-auth.live-verified-logout-accepted", FAILURE),
        ("authorization-plan.execution-progress", STOPPED),
        ("auth.provider-adapter-positive-auth.admin-credential.created", "sha256:d4aff55bac16e73efc867b327ef88eab79fd3f0db6dcac04fd82233e34cf1b18"),
        ("auth.provider-adapter-positive-auth.github-binding.created", "sha256:62ee203e20be12f515e698cd69a10ced3422f46eb4b7f21e67ba157fc53adab1"),
        ("auth.provider-adapter-positive-auth.github-binding.verified", "sha256:3590b89ce68436bb0109025b08869d7a4184a7207f65b52b67dca38e9d9395e0"),
        ("auth.provider-adapter-positive-auth.preflight.verified", "sha256:a81f43f32718325822785e6c246f90f9f161e93a3b377301ba83a607c7e3b8b2"),
        ("auth.provider-adapter-positive-auth.corrective-cleanup-retirement.prepared", PREP_DIGEST),
    ):
        assert item in first

    assert progress == initial_progress(plan, S, PROGRESS_ID, CREATED)
    assert progress["progress_digest"] == PROGRESS_DIGEST == progress_digest(progress)
    assert progress["overall_state"] == "NOT_STARTED"
    assert all(
        (x["authorization_state"],x["execution_state"],x["verification_state"],x["authorization_consumed"])
        == ("PENDING","NOT_STARTED","NOT_STARTED",False)
        for x in progress["step_states"]
    )
    assert not (B / f"{N}.approval.json").exists()
    assert not (B / f"{N}.execution-progress.json").exists()

    rendered = "\n".join((B / f"{N}{suffix}").read_text() for suffix in (
        ".resource.json","-preparation.evidence.json",".plan.json",".progress.json"
    ))
    assert DATA_PROJECT not in rendered
    assert "sb_secret_" not in rendered
    assert "sb_publishable_" not in rendered

    print(
        "DEVELOPMENT v14 continuation corrective cleanup v1: PASS "
        "(READY_FOR_APPROVAL; zero-state read before retirement; no auth retry; no new credentials)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
