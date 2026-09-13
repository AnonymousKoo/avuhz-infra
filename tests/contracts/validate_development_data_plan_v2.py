#!/usr/bin/env python3
"""Fail-closed canonical-binding diagnostic for DEVELOPMENT DATA v2."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import approval_digest, plan_digest, progress_digest
from avuhz_runtime.implementation_handoff import canonical_digest

PLAN_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.plan.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.approval.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.progress.json"


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict), path
    return value


def main() -> int:
    plan = load(PLAN_PATH)
    approval = load(APPROVAL_PATH)
    progress = load(PROGRESS_PATH)

    corrected_plan = copy.deepcopy(plan)
    seen: dict[str, tuple[str, str]] = {}
    for step in corrected_plan["steps"]:
        for declaration in step.get("binding_declarations", []):
            exact = declaration.get("preapproval_value")
            if exact is None:
                continue
            corrected = canonical_digest(exact["value"])
            exact["exact_digest"] = corrected
            seen[declaration["binding_id"]] = (exact["value"], corrected)

    corrected_plan["plan_digest"] = plan_digest(corrected_plan)

    corrected_approval = copy.deepcopy(approval)
    corrected_approval["plan_digest"] = corrected_plan["plan_digest"]
    corrected_approval["approval_digest"] = approval_digest(corrected_approval)
    corrected_approval_bytes = (
        json.dumps(corrected_approval, indent=2, ensure_ascii=True) + "\n"
    ).encode("utf-8")

    corrected_progress = copy.deepcopy(progress)
    corrected_progress["plan_digest"] = corrected_plan["plan_digest"]
    corrected_progress["progress_digest"] = progress_digest(corrected_progress)

    print("DEVELOPMENT_DATA_V2_BINDING_DIAGNOSTIC")
    for binding_id in sorted(seen):
        value, digest = seen[binding_id]
        print(f"BINDING={binding_id}|VALUE={value}|DIGEST={digest}")
    print("PLAN_DIGEST=" + corrected_plan["plan_digest"])
    print("APPROVAL_DIGEST=" + corrected_approval["approval_digest"])
    print("PROGRESS_DIGEST=" + corrected_progress["progress_digest"])
    print("APPROVAL_FILE_DIGEST=sha256:" + hashlib.sha256(corrected_approval_bytes).hexdigest())
    raise SystemExit("binding diagnostic intentionally fails closed")


if __name__ == "__main__":
    raise SystemExit(main())
