#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

SCRIPT = ROOT / "scripts/development_provider_adapter_positive_auth_v8.py"
WORKFLOW = ROOT / ".github/workflows/development-provider-adapter-positive-auth-v8-step5.yml"


def main() -> int:
    spec = importlib.util.spec_from_file_location(
        "development_provider_adapter_positive_auth_v8",
        SCRIPT,
    )
    assert spec and spec.loader
    executor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(executor)

    source = SCRIPT.read_text()
    workflow = WORKFLOW.read_text()
    rendered = source + "\n" + workflow

    assert executor.BOUNDARY == (
        "development-implementation-handoff-provider-adapter-positive-auth-v8"
    )
    assert executor.STEP_ID == (
        "development.implementation-handoff.provider-adapter-positive-auth-v8."
        "step.05.authenticate-live-and-logout-global"
    )
    assert executor.ADMIN_ENV == (
        "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V8_EPHEMERAL"
    )
    assert executor.CONFIRMATION == "RUN_PROVIDER_ADAPTER_POSITIVE_AUTH_V8_STEP5"
    assert executor.PROJECT == "pwlhruwutoitnieactol"
    assert executor.PREDECESSOR_BOUNDARY.endswith("positive-auth-v6")
    assert executor.PREDECESSOR_RETIREMENT.endswith("positive-auth-v6-key-retirement-v4")
    assert executor.V4_BINDING_RECONCILIATION.endswith(
        "positive-auth-v4-github-binding-absence-reconciliation-v1"
    )
    assert executor.V7_LATE_REJECTION.endswith(
        "positive-auth-v7-late-window-rejection"
    )

    assert "provider-adapter-positive-auth.v8" in source
    assert "provider-adapter-positive-auth.v5" not in source
    assert "fresh v5" not in source
    assert "v5 Steps" not in source
    assert "POSITIVE_AUTH_V6_EPHEMERAL" not in rendered
    assert "impl_handoff_provider_adapter_positive_auth_v6_ephemeral" not in rendered

    assert "scripts/development_provider_adapter_positive_auth_v8.py" in workflow
    assert "RUN_PROVIDER_ADAPTER_POSITIVE_AUTH_V8_STEP5" in workflow
    assert (
        "secrets.AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V8_EPHEMERAL"
        in workflow
    )
    assert "persist-credentials: false" in workflow
    assert "permissions:\n  contents: read" in workflow

    assert "required_v6_stopped_progress_digest" in source
    assert "required_v6_plan_integrity_failure_evidence_digest" in source
    assert "required_v6_retirement_progress_digest" in source
    assert "required_v6_key_absence_evidence_digest" in source
    assert "required_v6_github_absence_evidence_digest" in source
    assert "required_v4_binding_reconciliation_progress_digest" in source
    assert "required_v4_binding_reconciliation_evidence_digest" in source
    assert "required_v7_late_rejection_evidence_digest" in source

    print(
        "DEVELOPMENT provider-adapter positive-auth v8 source: PASS "
        "(repository-only; fresh v8 namespace; predecessor cleanup bound; "
        "no provider authority)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
