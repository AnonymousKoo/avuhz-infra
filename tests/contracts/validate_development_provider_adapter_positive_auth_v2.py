#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import initial_progress, plan_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v2"

PLAN_ID = "58c9c75c-6488-54e2-924e-d87c3d99432b"
PLAN_DIGEST = "sha256:03cb244d3ee92cde2e279c27f74a6d6ac36d22ed83d988e5c06bcd5ebd320edd"
PROGRESS_ID = "53a67dff-1f58-55c8-a9cb-c516093d2cdf"
PROGRESS_DIGEST = "sha256:1f47aec9d95d7a996077cca6c3c73f5c12b2c344182e93cbe37633cfc68886d4"
RESOURCE_DIGEST = "sha256:45c912a3364d8568b03b962eaae774a3de9183d9c80efb36f1004d978feb4556"
PREP_DIGEST = "sha256:45b2d594ba236941ca068c0c5b511cb73b878deac126b76ae852a0efe4a22999"
CORRECTIVE_RETIREMENT_DIGEST = "sha256:6013b08f1e11475d368a0a34c1d347d5d87d1a3baff04cbdf236c9dc88e917bc"
KEY_NAME = "impl_handoff_provider_adapter_positive_auth_v1_ephemeral"
INVALID_OLD_KEY_NAME = "implementation-handoff-provider-adapter-positive-auth-v1-ephemeral"


def load(name: str):
    return json.loads((B / name).read_text())


def raw(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    r = load(N + ".resource.json")
    correction = load(N + "-corrective-retirement.evidence.json")
    prep = load(N + "-preparation.evidence.json")
    p = load(N + ".plan.json")
    g = load(N + ".progress.json")

    validate_plan(p, S)
    validate_progress(p, g, S)

    assert not (B / (N + ".approval.json")).exists()
    assert not (B / (N + ".execution-progress.json")).exists()

    assert p["plan_id"] == PLAN_ID
    assert p["plan_version"] == 2
    assert p["plan_digest"] == PLAN_DIGEST == plan_digest(p)
    assert p["definition_status"] == "READY_FOR_APPROVAL"
    assert p["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert p["environment"] == "DEVELOPMENT"
    assert p["target"]["project_reference"] == "pwlhruwutoitnieactol"
    assert p["target"]["responsibility"] == "AUTH"
    assert p["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": "2026-10-04T05:30:00Z",
        "expires_at": "2026-10-04T08:30:00Z",
    }

    assert r["contract_digest"] == RESOURCE_DIGEST == canonical_digest(
        {k: v for k, v in r.items() if k != "contract_digest"}
    )
    assert r["fresh_provider_key_reference"] == KEY_NAME
    assert len(KEY_NAME) <= 64
    assert re.fullmatch(r"[a-z0-9_]+", KEY_NAME)

    assert correction["evidence_digest"] == CORRECTIVE_RETIREMENT_DIGEST == canonical_digest(
        {k: v for k, v in correction.items() if k != "evidence_digest"}
    )
    assert correction["project_reference"] == "pwlhruwutoitnieactol"
    assert correction["exact_key_name"] == KEY_NAME
    assert correction["owner_confirmed_deleted"] is True
    assert correction["credential_material_read"] is False
    assert correction["credential_material_retained"] is False
    assert correction["provider_mutation_observed_by_agent"] is False

    assert prep["evidence_digest"] == PREP_DIGEST == canonical_digest(
        {k: v for k, v in prep.items() if k != "evidence_digest"}
    )
    assert prep["evidence_type"] == "auth.provider-adapter-positive-auth-v2.preparation.observed"
    assert prep["resource_contract_digest"] == RESOURCE_DIGEST
    assert prep["prerequisites"]["corrective_key_retirement"] == CORRECTIVE_RETIREMENT_DIGEST
    assert prep["observation_only"] is True
    assert all(value is False for value in prep["security_state"].values())

    assert r["step5_executor_digest"] == raw(ROOT / "scripts/development_provider_adapter_positive_auth_v1.py")
    assert r["step5_workflow_digest"] == raw(ROOT / ".github/workflows/development-provider-adapter-positive-auth-v1-step5.yml")

    assert len(p["steps"]) == 10
    assert p["ordered_step_ids"] == [step["step_id"] for step in p["steps"]]
    assert all("positive-auth-v2" in step["step_id"] for step in p["steps"])
    assert all(step["resource"]["exact_digest"] == RESOURCE_DIGEST for step in p["steps"])
    assert all(step["resource"]["exact_version"] == "provider-adapter-positive-auth.v2" for step in p["steps"])

    first_required = p["steps"][0]["required_evidence"]
    assert any(
        item["evidence_type"] == "auth.provider-adapter-positive-auth.corrective-admin-credential.retired"
        and item["exact_digest"] == CORRECTIVE_RETIREMENT_DIGEST
        for item in first_required
    )

    for step in (p["steps"][0], p["steps"][6], p["steps"][8]):
        assert KEY_NAME in step["resource"]["resource_reference"]

    assert r["github_secret_binding_name"] == "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V1_EPHEMERAL"
    assert p["steps"][4]["credential_policy"]["allowed_classes"] == ["SUPABASE_AUTH_ADMIN_EPHEMERAL"]
    assert p["steps"][4]["credential_policy"]["values_stored"] is False

    assert g == initial_progress(p, S, PROGRESS_ID, p["created_at"])
    assert g["progress_digest"] == PROGRESS_DIGEST
    assert g["overall_state"] == "NOT_STARTED"
    assert all(
        state["authorization_state"] == "PENDING"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and state["authorization_consumed"] is False
        and not state["evidence"]
        for state in g["step_states"]
    )

    rendered = "".join(
        (B / (N + suffix)).read_text()
        for suffix in (
            ".resource.json",
            "-corrective-retirement.evidence.json",
            "-preparation.evidence.json",
            ".plan.json",
            ".progress.json",
        )
    )
    assert INVALID_OLD_KEY_NAME not in rendered
    for forbidden in (
        "postgresql://",
        "postgres://",
        "Bearer eyJ",
        '"secret_value"',
        '"service_role_key"',
        '"access_token"',
        '"refresh_token"',
        "sb_secret_",
    ):
        assert forbidden not in rendered

    print(
        "DEVELOPMENT provider-adapter positive-auth v2: PASS "
        "(READY_FOR_APPROVAL; pristine; Supabase-valid exact key label; "
        "owner-confirmed corrective retirement bound; no approval/provider authority)"
    )


if __name__ == "__main__":
    main()
