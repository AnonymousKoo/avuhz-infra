#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from avuhz_engineering.evidence_digest import evidence_digest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

SCRIPT = ROOT / "scripts/development_provider_adapter_positive_auth_v14_continuation_v1.py"
WORKFLOW = ROOT / ".github/workflows/development-provider-adapter-positive-auth-v14-continuation-v1-step1.yml"
FAILURE = ROOT / "contracts/plans/v1/development-implementation-handoff-provider-adapter-positive-auth-v14-step05-authorization-preflight-failure.evidence.json"


def main() -> int:
    spec = importlib.util.spec_from_file_location(
        "development_provider_adapter_positive_auth_v14_continuation_v1",
        SCRIPT,
    )
    assert spec and spec.loader
    executor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(executor)

    source = SCRIPT.read_text()
    workflow = WORKFLOW.read_text()
    failure = json.loads(FAILURE.read_text())

    assert executor.BOUNDARY.endswith("provider-adapter-positive-auth-v14-continuation-v1")
    assert executor.ADMIN_ENV == "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V14_EPHEMERAL"
    assert executor.CONFIRMATION == "RUN_PROVIDER_ADAPTER_POSITIVE_AUTH_V14_CONTINUATION_V1_STEP1"
    assert executor.PROJECT == "pwlhruwutoitnieactol"
    assert executor.ORIGINAL_PLAN_DIGEST == "sha256:8da4655cf8167a661935f88e340fe51d7da1821db807e9254ffca88b8b9ef47f"
    assert executor.ORIGINAL_PROGRESS_DIGEST == "sha256:4d3e44ca05339f980bbf5cced174f67f70d992b70456e9a94a64668ec643a096"
    assert executor.ORIGINAL_FAILURE_EVIDENCE == "sha256:ddd3884f1edebc06d2c608a066146235c5864d10680e95a277140fb04261c1bc"

    assert "fresh_auth_admin_key_create_count_authorized" in source
    assert "github_secret_binding_create_count_authorized" in source
    assert "!= 0" in source
    assert "fresh_auth_admin_key_delete_count_authorized" in source
    assert "github_secret_binding_delete_count_authorized" in source
    assert "plan_digest(plan)" in source
    assert "progress_digest(progress)" in source
    assert "validate_plan(plan, SCHEMA_ROOT)" in source
    assert "validate_progress(plan, progress, SCHEMA_ROOT)" in source
    assert "validate_plan(original" not in source
    assert "validate_progress(original" not in source

    assert "RUN_PROVIDER_ADAPTER_POSITIVE_AUTH_V14_CONTINUATION_V1_STEP1" in workflow
    assert "GITHUB_RUN_NUMBER" in workflow and '"1"' in workflow
    assert "GITHUB_RUN_ATTEMPT" in workflow
    assert "secrets.AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V14_EPHEMERAL" in workflow
    assert "persist-credentials: false" in workflow
    assert "permissions:\n  contents: read" in workflow

    assert evidence_digest(failure) == executor.ORIGINAL_FAILURE_EVIDENCE
    assert failure["outcome"] == "FAILED_CLOSED_BEFORE_SECRET_RESOLUTION"
    assert failure["root_cause_safe_code"] == "SCHEMA_INVALID"
    assert failure["execution_observation"]["secret_resolution_attempted"] is False
    assert failure["execution_observation"]["provider_mutation_attempted"] is False
    assert failure["execution_observation"]["retry_occurred"] is False
    assert all(value is False for value in failure["security_state"].values())

    print(
        "DEVELOPMENT provider-adapter positive-auth v14 continuation v1 source: PASS "
        "(reuses existing v14 key/binding; zero create authority; one fresh continuation run; "
        "v14 failure bound before secret resolution; no provider authority)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
