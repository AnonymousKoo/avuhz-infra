#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import initial_progress, plan_digest, progress_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_runtime.schema_registry import SchemaRegistry

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v4-step4-surface-correction-v1"
V4 = "development-implementation-handoff-provider-adapter-positive-auth-v4"

PLAN_ID = "7b692f74-c75f-5f07-ab20-0caa0340cc76"
PLAN_DIGEST = "sha256:e21360c0b07359a29cf2fe168aab5f11a53f48842b1c27c1f1f49cbbf2a8d351"
PROGRESS_ID = "cb3eddce-b37e-597f-8689-2808a5845773"
PROGRESS_DIGEST = "sha256:443beb55606bd71937bcef2297937ba86cbf479869dda04dd991bd6caa33ee38"
RESOURCE_DIGEST = "sha256:4b91f437a8868b0b76fc6a2685ef9db95d52766df8e7409e9e51afb5e7a6ece8"
PREP_DIGEST = "sha256:ec8dbf2927d80c959522c9a96b7d37be374671d894e47209915693946cd156b5"
QUERY_DIGEST = "sha256:0d785af10877d43bd4d886a534438dc21a6dd4471ac80194630feef29af73f8e"
CREATED_AT = "2026-10-05T00:05:30Z"
WINDOW_START = "2026-10-05T01:00:00Z"
WINDOW_END = "2026-10-05T05:00:00Z"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"

V4_PLAN_ID = "dd18445f-1bde-5523-9f5f-82231b39abde"
V4_PLAN_DIGEST = "sha256:77d92723177eae2dc690566496710c3a7520bf3d329926ddf1b5894929d7ed5a"
V4_APPROVAL_ID = "976971bf-f20c-5dc3-8895-d4e7cd2d1d16"
V4_APPROVAL_DIGEST = "sha256:31ede5908db0a9b29a21f27602ca3dd7708bdbaafcb9bb5ae25c829999eb81d6"
V4_STOPPED_PROGRESS = "sha256:89597fb31105b2398295ba8c0be4534c7de80e7813b673e108db83a57a301c9c"
V4_SCOPE_DRIFT_EVID = "sha256:15548bdd48fa9df3f78b2a8b84888c3b191fcd510c07c50db0ce64fded5ae6d3"
V4_STEP3_EVID = "sha256:b32dba957f080e4f0df22d3dd572afd2e2172c0f63c157f1a8328ca11a9aea0d"
V4_HIST_RESULT = "sha256:9cdd1a5df610cc4e193da53e03a74b108a0ebb0875cb16dc82bf6320516d846e"


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
    v4_stop = load(V4 + ".execution-progress.json")
    v4_drift = load(V4 + "-step04-scope-drift.evidence.json")
    v4_step3 = load(V4 + "-step03-success.evidence.json")

    registry = SchemaRegistry(S)
    validator = Draft202012Validator(
        registry.expanded("urn:avuhz:schema:contracts:orchestration:bounded-authorization-plan:v2"),
        format_checker=FormatChecker(),
    )
    schema_errors = sorted(validator.iter_errors(plan), key=lambda e: list(e.absolute_path))
    if schema_errors:
        for error in schema_errors:
            print("CORRECTION_SCHEMA_ERROR", list(error.absolute_path), error.message)
        raise AssertionError("correction plan schema invalid")
    validate_plan(plan, S)
    validate_progress(plan, progress, S)

    assert plan["plan_id"] == PLAN_ID and plan["plan_version"] == 1
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["created_at"] == CREATED_AT
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert not (B / (N + ".approval.json")).exists()
    assert not (B / (N + ".execution-progress.json")).exists()
    assert not list(B.glob(N + "-step*-*.evidence.json"))

    assert resource["contract_digest"] == RESOURCE_DIGEST == canonical_digest(
        {k: v for k, v in resource.items() if k != "contract_digest"}
    )
    assert resource["boundary"] == N
    assert resource["resource_version"] == "positive-auth-v4-step4-surface-correction.v1"
    assert resource["project_reference"] == PROJECT
    assert DATA_PROJECT not in json.dumps(resource)
    assert resource["interaction_surface"] == "supabase.mcp.execute_sql"
    assert resource["credential_class"] == "NONE"
    assert resource["query_sha256"] == QUERY_DIGEST == "sha256:" + hashlib.sha256(
        resource["diagnostic_sql"].encode()
    ).hexdigest()
    assert resource["query_count"] == 1
    assert resource["aggregate_only"] is True
    assert resource["expected_result"] == {
        "auth_user_count": 2,
        "target_identity_count": 1,
        "target_password_null_count": 1,
        "target_tenant_exact_count": 1,
        "session_count": 0,
        "refresh_token_count": 0,
    }
    for key in (
        "provider_mutation_authorized",
        "identity_change_authorized",
        "password_state_change_authorized",
        "tenant_binding_authorized",
        "allowlist_binding_authorized",
        "token_issue_authorized",
        "session_issue_authorized",
        "hook_change_authorized",
        "data_operation_authorized",
        "render_operation_authorized",
        "n8n_operation_authorized",
        "staging_authorized",
        "production_authorized",
        "raw_row_return_authorized",
        "credential_material_access_authorized",
        "github_binding_read_or_change_authorized",
        "additional_sql_authorized",
        "retry_authorized",
        "positive_auth_v4_progress_change_authorized",
        "step5_or_later_authorized",
    ):
        assert resource[key] is False

    assert resource["lineage"] == {
        "v4_plan_id": V4_PLAN_ID,
        "v4_plan_digest": V4_PLAN_DIGEST,
        "v4_approval_id": V4_APPROVAL_ID,
        "v4_approval_digest": V4_APPROVAL_DIGEST,
        "v4_stopped_progress_digest": V4_STOPPED_PROGRESS,
        "v4_step4_scope_drift_evidence_digest": V4_SCOPE_DRIFT_EVID,
        "v4_step3_github_binding_verified_evidence_digest": V4_STEP3_EVID,
        "historical_scope_drift_result_digest": V4_HIST_RESULT,
    }

    assert prep["evidence_digest"] == PREP_DIGEST == canonical_digest(
        {k: v for k, v in prep.items() if k != "evidence_digest"}
    )
    assert prep["evidence_type"] == "auth.provider-adapter-positive-auth-v4.step4-surface-correction.prepared"
    assert prep["provider_authority"] == "NONE"
    assert prep["external_provider_contact"] == "PROHIBITED"
    assert prep["resource_contract_digest"] == RESOURCE_DIGEST
    assert prep["selected_diagnostic"]["interaction_surface"] == "supabase.mcp.execute_sql"
    assert prep["selected_diagnostic"]["credential_class"] == "NONE"
    assert prep["selected_diagnostic"]["query_sha256"] == QUERY_DIGEST
    assert prep["selected_diagnostic"]["query_count"] == 1
    assert prep["selected_diagnostic"]["aggregate_only"] is True
    assert prep["historical_observation"] == {
        "scope_drift_evidence_digest": V4_SCOPE_DRIFT_EVID,
        "counts_match_expected": True,
        "historical_result_digest": V4_HIST_RESULT,
        "certifying_effect": False,
        "reuse_as_current_result_authorized": False,
    }
    assert all(value is False for value in prep["security_state"].values())

    assert v4_stop["plan_id"] == V4_PLAN_ID
    assert v4_stop["plan_digest"] == V4_PLAN_DIGEST
    assert v4_stop["overall_state"] == "STOPPED"
    assert v4_stop["progress_digest"] == V4_STOPPED_PROGRESS == progress_digest(v4_stop)
    assert (v4_stop["step_states"][3]["authorization_state"],
            v4_stop["step_states"][3]["execution_state"],
            v4_stop["step_states"][3]["verification_state"],
            v4_stop["step_states"][3]["authorization_consumed"]) == (
                "CONSUMED", "FAILED", "FAIL", True
            )
    assert v4_stop["step_states"][3]["safe_error_code"] == "AUTHORITY_INVALID"
    assert all(
        s["authorization_state"] == "BLOCKED"
        and s["execution_state"] == "NOT_STARTED"
        and s["verification_state"] == "NOT_STARTED"
        and s["authorization_consumed"] is False
        for s in v4_stop["step_states"][4:]
    )

    assert raw(B / (V4 + "-step04-scope-drift.evidence.json")) == V4_SCOPE_DRIFT_EVID
    assert v4_drift["outcome"] == "FAILED_SCOPE_DRIFT"
    assert v4_drift["safe_error_code"] == "AUTHORITY_INVALID"
    assert v4_drift["actual_execution"]["interaction_surface"] == "supabase.mcp.execute_sql"
    assert v4_drift["sanitized_result"]["counts_match_expected"] is True
    assert v4_drift["sanitized_result"]["preflight_certified"] is False
    assert v4_drift["result_digest"] == V4_HIST_RESULT
    assert v4_drift["verification_observation"]["step5_may_continue"] is False

    assert raw(B / (V4 + "-step03-success.evidence.json")) == V4_STEP3_EVID
    assert v4_step3["outcome"] == "SUCCEEDED_VERIFIED"

    step = plan["steps"][0]
    assert plan["ordered_step_ids"] == [step["step_id"]]
    assert step["ordinal"] == 1
    assert step["execution_class"] == "PROVIDER_READ"
    assert step["resource"]["exact_digest"] == RESOURCE_DIGEST
    assert step["resource"]["exact_version"] == "positive-auth-v4-step4-surface-correction.v1"
    assert step["operation"] == "provider.auth-state.inspect-aggregate-only-via-supabase-mcp"
    assert step["credential_policy"] == {
        "permitted": False,
        "allowed_classes": ["NONE"],
        "values_stored": False,
    }
    required = {(x["evidence_type"], x["exact_digest"]) for x in step["required_evidence"]}
    assert ("auth.provider-adapter-positive-auth-v4.step4-surface-correction.prepared", PREP_DIGEST) in required
    assert ("auth.provider-adapter-positive-auth.preflight.verified", V4_SCOPE_DRIFT_EVID) in required
    assert ("authorization-plan.execution-progress", V4_STOPPED_PROGRESS) in required
    assert ("auth.provider-adapter-positive-auth.github-binding.verified", V4_STEP3_EVID) in required
    assert "positive-auth-v4.progress.advance" in step["prohibited_actions"]
    assert "positive-auth-v4.step4.mark-success" in step["prohibited_actions"]
    assert "positive-auth.step5-or-later.execute" in step["prohibited_actions"]
    assert "query.retry" in step["prohibited_actions"]
    assert "provider.mutation" in step["prohibited_actions"]
    assert "supabase.mcp.execute_sql" in step["expected_postcondition"]
    assert "never changes stopped v4 progress" in step["expected_postcondition"]

    assert progress == initial_progress(plan, S, PROGRESS_ID, CREATED_AT)
    assert progress["progress_digest"] == PROGRESS_DIGEST == progress_digest(progress)
    assert progress["overall_state"] == "NOT_STARTED"

    rendered = "\n".join(
        (B / (N + suffix)).read_text()
        for suffix in (
            ".resource.json",
            "-preparation.evidence.json",
            ".plan.json",
            ".progress.json",
        )
    )
    for forbidden in ("Bearer eyJ", '"access_token":', '"refresh_token":', "service_role_key"):
        assert forbidden not in rendered
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", rendered) is None
    assert re.search(r"postgres(?:ql)?://[^\s/:]+:[^\s/@]+@", rendered, re.I) is None

    print(
        "DEVELOPMENT provider-adapter positive-auth v4 Step-4 surface correction v1: PASS "
        "(READY_FOR_APPROVAL; pristine; exact one-query Supabase MCP read; v4 remains STOPPED; "
        "no retry, mutation, credential access, or Step-5 authority)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
