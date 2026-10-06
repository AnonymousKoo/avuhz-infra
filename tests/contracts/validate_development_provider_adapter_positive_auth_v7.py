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
    initial_progress,
    plan_digest,
    progress_digest,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v7"
V6 = "development-implementation-handoff-provider-adapter-positive-auth-v6"
V6_RETIRE = "development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v4"
V4_RECON = "development-implementation-handoff-provider-adapter-positive-auth-v4-github-binding-absence-reconciliation-v1"

PROJECT = "pwlhruwutoitnieactol"
KEY = "impl_handoff_provider_adapter_positive_auth_v7_ephemeral"
GH = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V7_EPHEMERAL"
CREATED = "2026-10-06T04:42:51Z"
START = "2026-10-06T05:15:00Z"
END = "2026-10-06T08:00:00Z"

RESOURCE = "sha256:de278af29ec71af2afb2734abb0ab25cbc7add6d3003c0cacacd4621af198019"
PREP = "sha256:81100087a6c0d1c2d9d231298329dab5ed38e0abe26a9d8217a614cc9b94ab47"
PLAN = "sha256:4a067f4884186a7bb447d1ae3eb3248daeb2e024c586a97b3d564cc366f0011c"
PROGRESS = "sha256:92a2b69c3ae7b5d0016c35322e31491e7e2c8b40a464b311ec19aecdecd7521a"

EXECUTOR = "sha256:0b66e5c6ef5c832502ffcaa2f818afb8e1bed3f616779c18d21f31dec1ad7384"
WORKFLOW = "sha256:d62352de84441f2b67975abcc001ec376ddcb9866279c9538f3e61c15d9f7e0b"
V6_STOPPED = "sha256:c5d7bf0545ca10f453f4ac9775edccb1a2eb5e63efa7966225b95f5e5659df6f"
V6_FAILURE = "sha256:fdd233c078ee3e60bae0dd95128535526dc073759c54ee5cd21c8070cac15937"
V6_RETIREMENT = "sha256:b988dd98a2623e5831f007d65238940095725050a9cb8fc32e0dcba0cdb7ef0a"
V6_KEY_ABSENCE = "sha256:96e9371c01dcf15e061823c35df159d4627f79b06884af3c4edf6c48d08e2770"
V6_GH_ABSENCE = "sha256:a92e3926482aaed1ac19c241aef6d23b0079f47e1087c77bc65797dd11f99d76"
V4_RECON_PROGRESS = "sha256:57365c1791a9548568bb19515f70270e80b4ff1e4f3fa26f4560ebb6a3a572e9"
V4_RECON_EVIDENCE = "sha256:1c0b6abf5a3e49ffd9dec1b2573918f4e7046ae7dd0144e6d31645d09bcf2773"


def load(name: str) -> dict:
    return json.loads((B / name).read_text())


def raw(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    r = load(N + ".resource.json")
    prep = load(N + "-preparation.evidence.json")
    p = load(N + ".plan.json")
    g = load(N + ".progress.json")

    v6_x = load(V6 + ".execution-progress.json")
    v6_failure = load(V6 + "-step02-plan-integrity-failure.evidence.json")
    retire_x = load(V6_RETIRE + ".execution-progress.json")
    key_absence = load(V6_RETIRE + "-step2-success.evidence.json")
    gh_absence = load(V6_RETIRE + "-step3-success.evidence.json")
    recon_x = load(V4_RECON + ".execution-progress.json")
    recon_evidence = load(V4_RECON + "-step1-success.evidence.json")

    validate_plan(p, S)
    validate_progress(p, g, S)

    assert r["contract_digest"] == RESOURCE == canonical_digest(
        {k: v for k, v in r.items() if k != "contract_digest"}
    )
    assert prep["evidence_digest"] == PREP == canonical_digest(
        {k: v for k, v in prep.items() if k != "evidence_digest"}
    )
    assert p["plan_digest"] == PLAN == plan_digest(p)
    assert g["progress_digest"] == PROGRESS == progress_digest(g)
    assert g == initial_progress(p, S, g["progress_id"], CREATED)

    assert p["plan_id"] == "f3c4d8b1-9e8a-4f2d-9b07-5a7c8d2e1f66"
    assert p["plan_version"] == 7
    assert p["definition_status"] == "READY_FOR_APPROVAL"
    assert p["environment"] == "DEVELOPMENT"
    assert p["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": START,
        "expires_at": END,
    }
    assert p["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"

    assert r["project_reference"] == PROJECT
    assert r["responsibility"] == "AUTH"
    assert r["fresh_provider_key_reference"] == KEY
    assert r["github_secret_binding_name"] == GH
    assert r["resource_version"] == "provider-adapter-positive-auth.v7"
    assert r["step5_executor_digest"] == EXECUTOR == raw(
        ROOT / "scripts/development_provider_adapter_positive_auth_v7.py"
    )
    assert r["step5_workflow_digest"] == WORKFLOW == raw(
        ROOT / ".github/workflows/development-provider-adapter-positive-auth-v7-step5.yml"
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

    assert v6_x["overall_state"] == "STOPPED"
    assert v6_x["progress_digest"] == V6_STOPPED
    assert canonical_digest(v6_failure) == V6_FAILURE
    assert v6_failure["outcome"] == "FAILED_PREEXECUTION_PLAN_INTEGRITY"
    assert v6_failure["safe_error_code"] == "PLAN_STATE_INVALID"

    assert retire_x["overall_state"] == "COMPLETED"
    assert retire_x["progress_digest"] == V6_RETIREMENT
    assert canonical_digest(key_absence) == V6_KEY_ABSENCE
    assert canonical_digest(gh_absence) == V6_GH_ABSENCE
    assert recon_x["overall_state"] == "COMPLETED"
    assert recon_x["progress_digest"] == V4_RECON_PROGRESS
    assert canonical_digest(recon_evidence) == V4_RECON_EVIDENCE

    assert r["required_v6_stopped_progress_digest"] == V6_STOPPED
    assert r["required_v6_plan_integrity_failure_evidence_digest"] == V6_FAILURE
    assert r["required_v6_retirement_progress_digest"] == V6_RETIREMENT
    assert r["required_v6_key_absence_evidence_digest"] == V6_KEY_ABSENCE
    assert r["required_v6_github_absence_evidence_digest"] == V6_GH_ABSENCE
    assert r["required_v4_binding_reconciliation_progress_digest"] == V4_RECON_PROGRESS
    assert r["required_v4_binding_reconciliation_evidence_digest"] == V4_RECON_EVIDENCE

    assert prep["canonical_main_at_preparation"] == "af96a22db3d8f9716bc514044cb9468b13b25b16"
    assert prep["resource_contract_digest"] == RESOURCE
    assert prep["source_bindings"]["executor"] == EXECUTOR
    assert prep["source_bindings"]["workflow"] == WORKFLOW
    assert prep["prerequisites"]["v6_stopped_progress"] == V6_STOPPED
    assert prep["prerequisites"]["v6_retirement_progress"] == V6_RETIREMENT
    assert prep["prerequisites"]["v4_binding_reconciliation_progress"] == V4_RECON_PROGRESS
    assert prep["authorization_window"] == {"starts_at": START, "expires_at": END}
    assert all(v is False for v in prep["security_state"].values())

    assert len(p["steps"]) == 10
    assert all("positive-auth-v7" in step["step_id"] for step in p["steps"])
    assert all(
        step["resource"]["exact_version"] == "provider-adapter-positive-auth.v7"
        and step["resource"]["exact_digest"] == RESOURCE
        for step in p["steps"]
    )
    for idx in (0, 6, 8):
        assert KEY in p["steps"][idx]["resource"]["resource_reference"]
        assert KEY in p["steps"][idx]["expected_postcondition"]

    assert "bound in the v7 resource" in p["steps"][3]["expected_postcondition"]
    assert "fresh v7 GitHub environment credential" in p["steps"][4]["expected_postcondition"]
    assert p["steps"][3]["operation"] == "provider.auth-state.inspect-aggregate-only-via-supabase-mcp"
    assert p["steps"][5]["operation"] == "provider.auth-session-state.inspect-read-only-via-supabase-mcp"
    assert p["steps"][3]["credential_policy"] == {
        "permitted": False,
        "allowed_classes": ["NONE"],
        "values_stored": False,
    }
    assert p["steps"][5]["credential_policy"] == {
        "permitted": False,
        "allowed_classes": ["NONE"],
        "values_stored": False,
    }

    assert g["overall_state"] == "NOT_STARTED"
    assert g["record_version"] == 1
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
    assert not (B / (N + ".approval.json")).exists()
    assert not (B / (N + ".execution-progress.json")).exists()

    rendered = "\n".join(
        (B / (N + suffix)).read_text()
        for suffix in (
            ".resource.json",
            "-preparation.evidence.json",
            ".plan.json",
            ".progress.json",
        )
    )
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", rendered) is None
    assert "gnuqaefotwgkwurjpyik" not in rendered
    assert "fresh v5 GitHub environment credential" not in rendered
    assert "bound in the v5 resource" not in rendered
    for forbidden in ("service_role", "Bearer eyJ"):
        assert forbidden not in rendered

    print(
        "DEVELOPMENT provider-adapter positive-auth v7: PASS "
        "(PREPARED / UNAPPROVED / UNEXECUTED; fresh v7 source and predecessor cleanup bound)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
