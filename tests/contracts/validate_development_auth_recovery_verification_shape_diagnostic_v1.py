#!/usr/bin/env python3
"""Validate blocked DEVELOPMENT AUTH recovery-shape diagnostic plan/progress."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    initial_progress,
    plan_digest,
    progress_digest,
    validate_plan,
    validate_progress,
)

BASE = ROOT / "contracts/plans/v1"
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BOUNDARY = "development-auth-recovery-verification-shape-diagnostic-v1"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
PLAN_ID = "e18e04fa-03e5-402d-8e41-3e8e916095d4"
PLAN_DIGEST = "sha256:e5bb429506d0cca9ae7d27578a1518a30a055a971983672b6f4e7ea097ccce65"
PROGRESS_ID = "74960d56-a49e-4cda-b084-5a102ca67bde"
PROGRESS_DIGEST = "sha256:9fb402d552a9bc2a9e350d29436b9ec52e37cc48751a7590733ddeb3fac2fcbf"
CREATED_AT = "2026-09-28T00:00:00Z"
UPDATED_AT = "2026-09-28T00:10:00Z"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
STEP_ID = "development.auth.recovery-shape-diagnostic-v1.step.01.inspect-sanitized-shape-once"
OPERATION = "provider.auth-recovery-verification.inspect-sanitized-shape-once"
PRIMITIVE_DIGEST = "sha256:19c7c16c8cc495e0b4ab886ab897804251245c979b536498b14c7d94086809ce"
FAILURE_DIGEST = "sha256:8344c3e26c26f464bcefa880251ac7619bfc6087a8a17e9c0987db4a843191eb"
BLOCKER = "binding.development.auth.recovery-shape-diagnostic-v1.admin-credential-reference"
EVIDENCE = "auth.recovery-verification.sanitized-shape.observed"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 1
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
    assert plan["definition_status"] == "DRAFT_BLOCKED"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"
    assert DATA_PROJECT not in json.dumps(plan)
    assert plan["created_at"] == CREATED_AT
    assert plan["authorization_window"] == {
        "binding_state": "UNRESOLVED_BLOCKER",
        "starts_at": None,
        "expires_at": None,
    }
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["ordered_step_ids"] == [STEP_ID]

    step = plan["steps"][0]
    assert step["operation"] == OPERATION
    assert step["execution_class"] == "PROVIDER_MUTATION"
    assert step["resource"]["exact_digest"] == PRIMITIVE_DIGEST
    assert step["required_evidence"] == [{
        "evidence_type": "auth.cleanup-v4.failure.observed",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": FAILURE_DIGEST,
    }]
    assert step["credential_policy"]["allowed_classes"] == ["SUPABASE_AUTH_ADMIN_EPHEMERAL"]
    assert step["credential_policy"]["values_stored"] is False
    assert step["unresolved_bindings"] == [BLOCKER]
    blocker = next(x for x in step["binding_declarations"] if x["binding_id"] == BLOCKER)
    assert blocker["phase"] == "UNRESOLVED_BLOCKER"
    assert blocker["digest_policy"] == "PROHIBITED"
    assert blocker["persistence_policy"] == "PROHIBITED"
    assert blocker["source_step_id"] is None and blocker["evidence_type"] is None
    assert step["produced_evidence"] == [{
        "evidence_type": EVIDENCE,
        "established_binding_ids": ["binding.development.auth.recovery-shape-diagnostic-v1.sanitized-shape"],
        "digest_policy": "REQUIRED",
    }]
    for prohibited in (
        "session.cleanup", "global-logout.execute", "provider.retry",
        "raw-provider-payload.persist", "token.persist", "pii.return",
    ):
        assert prohibited in step["prohibited_actions"]

    assert progress == initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, UPDATED_AT)
    assert progress["progress_digest"] == PROGRESS_DIGEST == progress_digest(progress)
    assert progress["overall_state"] == "NOT_STARTED"
    state = progress["step_states"][0]
    assert (state["authorization_state"], state["execution_state"], state["verification_state"]) == (
        "PENDING", "NOT_STARTED", "NOT_STARTED"
    )
    assert state["authorization_consumed"] is False
    assert state["evidence"] == [] and state["binding_assertions"] == []
    assert not (BASE / f"{BOUNDARY}.approval.json").exists()
    assert not (BASE / f"{BOUNDARY}.execution-progress.json").exists()
    assert not list(BASE.glob(f"{BOUNDARY}-step*.evidence.json"))

    print("DEVELOPMENT AUTH recovery-shape diagnostic plan/progress: PASS (blocked; no execution authority)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
