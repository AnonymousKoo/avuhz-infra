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

import validate_development_provider_adapter_positive_auth_v4_continuation_v1 as continuation
from avuhz_engineering.authorization_plan import initial_progress, plan_digest, progress_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v4-corrective-cleanup-retirement-v1"

PLAN_ID = "c4d14e3c-72fe-57f7-ae9a-3b9ea97fa74a"
PLAN_DIGEST = "sha256:6c3ad1d1e00c32744b0fd9cd5ff647c9cf795be818dc2c765529af738ef55bd1"
RESOURCE_ID = "42ff0a3b-4a8c-51fa-8dae-33975ac44144"
RESOURCE_DIGEST = "sha256:73780080a5009fef93de09e0beab087b1208f63331bb0749081407f9c0d52ef1"
PREP_DIGEST = "sha256:a0ef1e57e3e2ab5c2d738f62e723965151a6dfd1e3de9e35f3acd1473d71fb6d"
PROGRESS_ID = "752e0523-3524-5ce7-a7f4-5239291ac25f"
PROGRESS_DIGEST = "sha256:dc1c79e43dbe6f684a6e14151a7af0ce0cd379214c0d586646853d2c9a8c0f42"
CREATED_AT = "2026-10-05T02:14:33Z"
WINDOW_START = "2026-10-05T02:30:00Z"
WINDOW_END = "2026-10-05T06:30:00Z"

PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
KEY_NAME = "impl_handoff_provider_adapter_positive_auth_v4_ephemeral"
GH_SECRET = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V4_EPHEMERAL"
FAILURE_DIGEST = "sha256:d0adabce4a18b043eba5204b9896e8a454a4061d90a690a8a86df20b7852441d"
STOPPED_DIGEST = "sha256:42ad20cde3ab60c8b040139ff34a6078d7097050d43e9a74cdc352dada0bd2db"
KEY_CREATED = "sha256:69cfb113f70f7e87ac681c7c0123dc338808f129a9f2fe534661b98805796302"
GH_CREATED = "sha256:947336db2db2cc49029949d363b9cc34904ce0753d424887cc22504a9f1a779e"
GH_VERIFIED = "sha256:b32dba957f080e4f0df22d3dd572afd2e2172c0f63c157f1a8328ca11a9aea0d"
CONT_PLAN_RAW = "sha256:49963ca068a62de1bbb220e8416c8103b5fe7d1cfb868e9f93deeea7af7bee51"
CONT_APPROVAL_RAW = "sha256:c980e33ee7e66f63b95762124fc6c024b68a5077650bfa5de6fe76518754ff53"
CONT_FAILURE_RAW = "sha256:01c8133c6264acc207392e7ccea6a0453d7257b09a32df477c77f40e48540355"
CONT_EXEC_RAW = "sha256:027a0a1d4cb10b50bb17744c82724db0a375982b453d720c5a5ba2f814260e03"

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

    validate_plan(plan, S)
    validate_progress(plan, progress, S)

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
    assert resource["resource_version"] == "provider-adapter-positive-auth-v4-corrective-cleanup-retirement.v1"
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
    assert all(s["resource"]["exact_version"] == "provider-adapter-positive-auth-v4-corrective-cleanup-retirement.v1" for s in steps)
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
    assert not (B / (N + ".approval.json")).exists()
    assert not (B / (N + ".execution-progress.json")).exists()
    assert not list(B.glob(N + "-step*.evidence.json"))

    cont = "development-implementation-handoff-provider-adapter-positive-auth-v4-continuation-v1"
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
        ".resource.json", "-preparation.evidence.json", ".plan.json", ".progress.json"
    ))
    for forbidden in ("sb_secret_", "Bearer eyJ", "service_role_key", '"access_token":', '"refresh_token":'):
        assert forbidden not in rendered
    assert re.search(r"postgres(?:ql)?://[^\s/:]+:[^\s/@]+@", rendered, re.I) is None

    print(
        "DEVELOPMENT provider-adapter positive-auth v4 corrective cleanup/retirement v1: PASS "
        "(READY_FOR_APPROVAL; pristine five-step boundary; zero-state required before retirement; "
        "failed live-auth retry prohibited; no provider authority)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
