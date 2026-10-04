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
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v3"

PLAN_ID = "8a31fb79-9e7e-53d8-b0b0-f14b611da37a"
PLAN_DIGEST = "sha256:9d6ce4ff12450657dcda89650fe7b3207db6f179794cfb48eff8ebb81ad143d9"
PROGRESS_ID = "4f301e2f-34dc-5dc3-9373-e46e8dc9d830"
PROGRESS_DIGEST = "sha256:3e05c70c7ac1938f6ac9f2dab7fdde3910c215517cc542e1dec63de8c5b42474"
RESOURCE_DIGEST = "sha256:d89ae6b20765a47dbd76b19761fbee832947e18591333a0a1cc3aa25c45fa9c9"
PREP_DIGEST = "sha256:c97bf6eeebed0df9259a07904d72d9e5101b72a3fa33d173bd7c084d9417bc16"
APPROVAL_ID = "f69cb520-1336-5281-ae51-13bdb242ee7d"
APPROVAL_DIGEST = "sha256:e79e433af146c5260368087833e56ce98f16babc018ccd477515f0fc09a8b672"
APPROVAL_FILE_DIGEST = "sha256:2897f44696c7f2bf857bcf4f5039064bc9913f328f13b4177d2011bded6b09ba"
APPROVED_AT = "2026-10-04T20:18:23Z"
QUERY_DIGEST = "sha256:0d785af10877d43bd4d886a534438dc21a6dd4471ac80194630feef29af73f8e"
CREATED_AT = "2026-10-04T19:53:50Z"
WINDOW_START = "2026-10-04T20:30:00Z"
WINDOW_END = "2026-10-05T00:30:00Z"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
KEY = "impl_handoff_provider_adapter_positive_auth_v3_ephemeral"
GH = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V3_EPHEMERAL"
PASSWORDLESS = "sha256:26a90c35357ac14b23d1b7f17e18762e958248462d53aed168985dba249cbb10"
TENANT = "sha256:42a33b97e8ab5c8fd9c7972d5d4a9cad57d06135ea9a05952ed6f669026c3936"
ALLOWLIST = "sha256:07b1103c5a90a04849e4cc6c4d9c303adcf09b7a639086ae88a90979ad301325"
RUNTIME = "sha256:f49f6882f2e6ec0274935137a52c7b7c942bfbe0bc72baebca143a90aedc5345"
RUNTIME_PROGRESS = "sha256:762fc38748aeb4483a5b26179a703e687bab13e7f5c73160b29a3a77d4480e5c"
FAILURE = "sha256:27c324aa9f0c155fb5c75125cdc4ce24bb160e1bf06af1fd2d08bd75039180c9"
STOPPED = "sha256:730f4c0a7b6393223c85cd5746472e1227bb9c77d174e8644075c4dc1722bd6b"
CLEAN_ZERO = "sha256:5a4183d202fc94f948b25e9c60a59136e9b81687728bf02ecb116ceba25709d1"
CLEAN_KEY_ABSENT = "sha256:338e9648389d857871c816d9e4ad5c814300c3a92de45671da77e2564274a60f"
CLEAN_GH_ABSENT = "sha256:318709e7c83d2e701552b4daaa9769120ccade381c3aeaf179132489f9ff3de4"
CLEAN_PROGRESS = "sha256:e48fe89e45b47e31b5439ccefe2240ab0edc3e9f2e377d10c2f799e617bc08a4"
PREWINDOW_RETIREMENT_N = "development-implementation-handoff-provider-adapter-positive-auth-v3-prewindow-key-retirement-v1"
PREWINDOW_INCIDENT_DIGEST = "sha256:38bd6282b4da2453e100335b5666cb7edac65d8d91216b6e175315b7d99ac39a"
PREWINDOW_RETIREMENT_PLAN_DIGEST = "sha256:4b70a82966dad56ca9ff4c9c680356dbfa6bba48a71acc3780655a84da15ff2b"
PREWINDOW_RETIREMENT_PROGRESS_DIGEST = "sha256:54e65db1c2a3a84b3c19d233072df1488eba1ca320610f9f6054c9a2ab46a1ae"
PREWINDOW_RETIREMENT_APPROVAL_DIGEST = "sha256:229c3617af12c6ffad91b261364beb8ed46a71ae7936ebf080186c8471783a18"
PREWINDOW_RETIREMENT_APPROVAL_FILE_DIGEST = "sha256:dcaf061267208e9fec4f376b53b43cd0254613b217ba9b9285511fcfe019f392"
PREWINDOW_RETIREMENT_EXECUTION_PROGRESS_DIGEST = "sha256:01a186c84fa434f4570aa4b840d2436813f2f1fdaf97994cf752c1d217e67f0a"
PREWINDOW_RETIREMENT_STEP1_EVIDENCE_DIGEST = "sha256:23791e31d64420458293042c433cc4c52fe20040bddbc4de78e7f783ebd4f3a2"


def load(name: str) -> dict:
    value = json.loads((B / name).read_text())
    assert isinstance(value, dict)
    return value


def raw(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    r = load(N + ".resource.json")
    prep = load(N + "-preparation.evidence.json")
    p = load(N + ".plan.json")
    g = load(N + ".progress.json")
    a = load(N + ".approval.json")

    validate_plan(p, S)
    validate_progress(p, g, S)
    validate_approval(p, a, S, WINDOW_START)

    assert p["plan_id"] == PLAN_ID
    assert p["plan_version"] == 3
    assert p["plan_digest"] == PLAN_DIGEST == plan_digest(p)
    assert p["definition_status"] == "READY_FOR_APPROVAL"
    assert p["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert p["environment"] == "DEVELOPMENT"
    assert p["target"]["project_reference"] == PROJECT
    assert p["target"]["responsibility"] == "AUTH"
    assert p["created_at"] == CREATED_AT
    assert p["authorization_window"] == {
        "binding_state": "BOUND", "starts_at": WINDOW_START, "expires_at": WINDOW_END,
    }
    assert raw(B / (N + ".approval.json")) == APPROVAL_FILE_DIGEST
    assert a["approval_id"] == APPROVAL_ID
    assert a["plan_id"] == PLAN_ID and a["plan_version"] == 3 and a["plan_digest"] == PLAN_DIGEST
    assert a["owner_identity"] == "github:AnonymousKoo" and a["decision"] == "APPROVE"
    assert a["environment"] == "DEVELOPMENT" and a["authority_scope"] == "EXACT_PLAN_ONLY"
    assert a["effective_at"] == WINDOW_START and a["expires_at"] == WINDOW_END
    assert a["approved_at"] == APPROVED_AT and a["status"] == "ACTIVE"
    assert a["approval_digest"] == APPROVAL_DIGEST == approval_digest(a)
    assert not (B / (N + ".execution-progress.json")).exists()
    assert not list(B.glob(N + "-step*-*.evidence.json"))
    prewindow_incident = load(PREWINDOW_RETIREMENT_N + "-incident.evidence.json")
    prewindow_plan = load(PREWINDOW_RETIREMENT_N + ".plan.json")
    prewindow_progress = load(PREWINDOW_RETIREMENT_N + ".progress.json")
    prewindow_approval = load(PREWINDOW_RETIREMENT_N + ".approval.json")
    prewindow_execution = load(PREWINDOW_RETIREMENT_N + ".execution-progress.json")
    assert prewindow_incident["evidence_digest"] == PREWINDOW_INCIDENT_DIGEST
    assert prewindow_incident["authorization_assessment"]["v3_step1_recordable_as_authorized"] is False
    assert prewindow_incident["authorization_assessment"]["v3_must_remain_blocked_until_retirement_complete"] is True
    assert prewindow_plan["plan_digest"] == PREWINDOW_RETIREMENT_PLAN_DIGEST
    assert prewindow_plan["definition_status"] == "READY_FOR_APPROVAL"
    assert prewindow_plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert prewindow_progress["progress_digest"] == PREWINDOW_RETIREMENT_PROGRESS_DIGEST
    assert prewindow_progress["overall_state"] == "NOT_STARTED"
    assert raw(B / (PREWINDOW_RETIREMENT_N + ".approval.json")) == PREWINDOW_RETIREMENT_APPROVAL_FILE_DIGEST
    assert prewindow_approval["approval_digest"] == PREWINDOW_RETIREMENT_APPROVAL_DIGEST
    assert prewindow_approval["status"] == "ACTIVE" and prewindow_approval["decision"] == "APPROVE"
    assert prewindow_execution["progress_digest"] == PREWINDOW_RETIREMENT_EXECUTION_PROGRESS_DIGEST == progress_digest(prewindow_execution)
    assert prewindow_execution["overall_state"] == "IN_PROGRESS"
    assert (prewindow_execution["step_states"][0]["authorization_state"], prewindow_execution["step_states"][0]["execution_state"], prewindow_execution["step_states"][0]["verification_state"], prewindow_execution["step_states"][0]["authorization_consumed"]) == ("CONSUMED","SUCCEEDED","PASS",True)
    assert prewindow_execution["step_states"][0]["evidence"][0]["evidence_digest"] == PREWINDOW_RETIREMENT_STEP1_EVIDENCE_DIGEST
    assert all((x["authorization_state"],x["execution_state"],x["verification_state"],x["authorization_consumed"]) == ("PENDING","NOT_STARTED","NOT_STARTED",False) for x in prewindow_execution["step_states"][1:])

    assert r["contract_digest"] == RESOURCE_DIGEST == canonical_digest(
        {k: v for k, v in r.items() if k != "contract_digest"}
    )
    assert r["resource_version"] == "provider-adapter-positive-auth.v3"
    assert r["boundary"] == N
    assert r["project_reference"] == PROJECT
    assert DATA_PROJECT not in json.dumps(r)
    assert r["fresh_provider_key_reference"] == KEY
    assert len(KEY) <= 64 and re.fullmatch(r"[a-z0-9_]+", KEY)
    assert r["github_secret_binding_name"] == GH
    assert r["step5_executor_digest"] == raw(ROOT / "scripts/development_provider_adapter_positive_auth_v3.py")
    assert r["step5_workflow_digest"] == raw(ROOT / ".github/workflows/development-provider-adapter-positive-auth-v3-step5.yml")
    assert r["token_lifecycle_source_digest"] == raw(ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py")
    assert r["identity_policy_source_digest"] == raw(ROOT / "src/avuhz_service/development_supabase_identity.py")
    assert r["jwt_verifier_source_digest"] == raw(ROOT / "src/avuhz_service/development_supabase_jwt.py")

    pre = r["preflight_contract"]
    assert pre["interaction_surface"] == "supabase.dashboard.sql-editor"
    assert pre["project_reference"] == PROJECT
    assert pre["credential_class"] == "OWNER_INTERACTIVE_SESSION"
    assert pre["query_sha256"] == QUERY_DIGEST == "sha256:" + hashlib.sha256(pre["query"].encode()).hexdigest()
    assert pre["query_count"] == 1
    assert pre["result_fields"] == [
        "auth_user_count", "target_identity_count", "target_password_null_count",
        "target_tenant_exact_count", "session_count", "refresh_token_count",
    ]
    assert pre["expected_result"] == {
        "auth_user_count": 2, "target_identity_count": 1, "target_password_null_count": 1,
        "target_tenant_exact_count": 1, "session_count": 0, "refresh_token_count": 0,
    }
    assert pre["aggregate_only"] is True and pre["raw_rows_authorized"] is False
    assert pre["additional_sql_authorized"] is False and pre["retry_authorized"] is False

    diagnostics = r["failure_diagnostics"]
    assert diagnostics["safe_error_code_retained"] is True
    assert diagnostics["exception_text_retained"] is False
    assert diagnostics["provider_payload_retained"] is False
    assert diagnostics["credential_or_token_material_retained"] is False
    for code in ("ACCESS_JWT_VALIDATION_FAILED", "LIVE_AUTH_PROBE_FAILED", "POSITIVE_AUTH_FAILED_LOGOUT_UNVERIFIED"):
        assert code in diagnostics["allowed_safe_codes"]

    assert prep["evidence_digest"] == PREP_DIGEST == canonical_digest(
        {k: v for k, v in prep.items() if k != "evidence_digest"}
    )
    assert prep["evidence_type"] == "auth.provider-adapter-positive-auth-v3.preparation.observed"
    assert prep["resource_contract_digest"] == RESOURCE_DIGEST
    assert prep["observation_only"] is True
    assert prep["prerequisites"] == {
        "passwordless": PASSWORDLESS,
        "tenant_binding": TENANT,
        "allowlist": ALLOWLIST,
        "render_v11_runtime": RUNTIME,
        "render_v11_progress": RUNTIME_PROGRESS,
        "failed_continuation_evidence": FAILURE,
        "failed_continuation_progress": STOPPED,
        "corrective_cleanup_zero_state": CLEAN_ZERO,
        "corrective_cleanup_key_absence": CLEAN_KEY_ABSENT,
        "corrective_cleanup_github_absence": CLEAN_GH_ABSENT,
        "corrective_cleanup_progress": CLEAN_PROGRESS,
    }
    assert all(value is False for value in prep["security_state"].values())

    # Bind immutable stopped/cleanup history rather than reusing old authority.
    failed = load("development-implementation-handoff-provider-adapter-positive-auth-continuation-v1-step1-failure.evidence.json")
    stopped = load("development-implementation-handoff-provider-adapter-positive-auth-continuation-v1.execution-progress.json")
    clean = load("development-implementation-handoff-provider-adapter-positive-auth-corrective-cleanup-retirement-v1.execution-progress.json")
    assert raw(B / "development-implementation-handoff-provider-adapter-positive-auth-continuation-v1-step1-failure.evidence.json") == FAILURE
    assert failed["outcome"] == "FAILED_UNVERIFIED" and failed["authority_state"]["retry_authorized"] is False
    assert stopped["overall_state"] == "STOPPED" and stopped["progress_digest"] == STOPPED == progress_digest(stopped)
    assert clean["overall_state"] == "COMPLETED" and clean["progress_digest"] == CLEAN_PROGRESS == progress_digest(clean)
    assert all(
        (s["authorization_state"], s["execution_state"], s["verification_state"], s["authorization_consumed"])
        == ("CONSUMED", "SUCCEEDED", "PASS", True)
        for s in clean["step_states"]
    )
    assert raw(B / "development-implementation-handoff-provider-adapter-positive-auth-corrective-cleanup-retirement-v1-step1-success.evidence.json") == CLEAN_ZERO
    assert raw(B / "development-implementation-handoff-provider-adapter-positive-auth-corrective-cleanup-retirement-v1-step4-success.evidence.json") == CLEAN_KEY_ABSENT
    assert raw(B / "development-implementation-handoff-provider-adapter-positive-auth-corrective-cleanup-retirement-v1-step5-success.evidence.json") == CLEAN_GH_ABSENT

    assert len(p["steps"]) == 10
    assert p["ordered_step_ids"] == [s["step_id"] for s in p["steps"]]
    assert [s["ordinal"] for s in p["steps"]] == list(range(1, 11))
    assert all("positive-auth-v3" in s["step_id"] for s in p["steps"])
    assert all(s["resource"]["exact_version"] == "provider-adapter-positive-auth.v3" for s in p["steps"])
    assert all(s["resource"]["exact_digest"] == RESOURCE_DIGEST for s in p["steps"])
    assert [s["execution_class"] for s in p["steps"]] == [
        "PROVIDER_MUTATION", "PROVIDER_MUTATION", "PROVIDER_READ", "PROVIDER_READ", "PROVIDER_MUTATION",
        "PROVIDER_READ", "PROVIDER_MUTATION", "PROVIDER_MUTATION", "PROVIDER_READ", "PROVIDER_READ",
    ]
    assert [s["operation"] for s in p["steps"]] == [
        "provider.auth-admin-credential.create-dedicated-secret-key",
        "provider.auth-secret-binding.create-github-environment-reference",
        "provider.auth-secret-binding.verify-github-environment-reference",
        "provider.auth-state.inspect-aggregate-only",
        "provider.auth-session.provider-adapter-recover-validate-live-probe-and-logout-global",
        "provider.auth-session-state.inspect-read-only",
        "provider.auth-admin-credential.delete-dedicated-secret-key",
        "provider.auth-secret-binding.delete-github-environment-reference",
        "provider.auth-admin-credential.verify-dedicated-secret-key-absent",
        "provider.auth-secret-binding.verify-github-environment-reference-absent",
    ]
    assert p["steps"][3]["dependency_step_ids"] == [p["steps"][2]["step_id"]]
    assert "exact query text and SHA-256 are bound" in p["steps"][3]["expected_postcondition"]
    assert p["steps"][4]["credential_policy"] == {
        "permitted": True,
        "allowed_classes": ["SUPABASE_AUTH_ADMIN_EPHEMERAL"],
        "values_stored": False,
        "ephemeral_handling": p["steps"][4]["credential_policy"]["ephemeral_handling"],
    }
    assert "ImplementationHandoff execution" in p["steps"][4]["expected_postcondition"]
    assert "retry" in p["steps"][4]["expected_postcondition"]
    for s in (p["steps"][0], p["steps"][6], p["steps"][8]):
        assert KEY in s["resource"]["resource_reference"]
    for s in (p["steps"][1], p["steps"][2], p["steps"][7], p["steps"][9]):
        assert GH in s["resource"]["resource_reference"]

    first = {(x["evidence_type"], x["exact_digest"]) for x in p["steps"][0]["required_evidence"]}
    for item in (
        ("auth.provider-adapter-positive-auth-v3.preparation.observed", PREP_DIGEST),
        ("auth.provider-adapter-passwordless-state.verified", PASSWORDLESS),
        ("auth.provider-adapter-tenant-metadata.verified", TENANT),
        ("server.capability-policy.verified", ALLOWLIST),
        ("runtime.render.post-deploy-runtime.verified", RUNTIME),
        ("auth.provider-adapter-positive-auth.live-verified-logout-accepted", FAILURE),
        ("auth.provider-adapter-positive-auth.cleanup.verified", CLEAN_ZERO),
        ("auth.provider-adapter-positive-auth.admin-credential.absence-verified", CLEAN_KEY_ABSENT),
        ("auth.provider-adapter-positive-auth.github-binding.absence-verified", CLEAN_GH_ABSENT),
    ):
        assert item in first

    assert g == initial_progress(p, S, PROGRESS_ID, CREATED_AT)
    assert g["progress_digest"] == PROGRESS_DIGEST == progress_digest(g)
    assert g["overall_state"] == "NOT_STARTED"
    assert all(
        (s["authorization_state"], s["execution_state"], s["verification_state"], s["authorization_consumed"])
        == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        and not s["evidence"] and not s["binding_assertions"]
        for s in g["step_states"]
    )

    rendered = "\n".join((B / (N + suffix)).read_text() for suffix in (
        ".resource.json", "-preparation.evidence.json", ".plan.json", ".progress.json", ".approval.json"
    ))
    for forbidden in ("Bearer eyJ", '"access_token":', '"refresh_token":', "service_role_key"):
        assert forbidden not in rendered
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", rendered) is None
    assert re.search(r"postgres(?:ql)?://[^\s/:]+:[^\s/@]+@", rendered, re.I) is None

    print(
        "DEVELOPMENT provider-adapter positive-auth v3: PASS "
        "(APPROVED / BLOCKED_BY_IN_PROGRESS_PREWINDOW_RETIREMENT; retirement Step 1 PASS; Steps 2-3 pending; "
        "premature key creation remains non-recordable as authorized v3 Step 1)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
