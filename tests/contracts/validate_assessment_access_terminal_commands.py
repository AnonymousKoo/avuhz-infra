#!/usr/bin/env python3
import copy, sys
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from avuhz_runtime.schema_registry import SchemaRegistry

IDS = ("expire-assessment-access-payload", "revoke-assessment-access-payload", "close-assessment-access-for-agreement-end-payload")

def main():
    registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
    valid = {"assessment_access_grant_id": "a3000000-0000-4000-8000-000000000015"}
    forbidden = ({}, {"tenant_id": "a3000000-0000-4000-8000-000000000002"}, {"status": "EXPIRED"}, {"expires_at": "2030-02-14T15:00:00Z"}, {"agreement_ended": True}, {"closure_reason": "AGREEMENT_ENDED"}, {"metadata": {}}, {"credentials": {}}, {"provider_payload": {}}, {"arbitrary": "forbidden"})
    for name in IDS:
        validator = Draft202012Validator(registry.expanded(f"urn:avuhz:schema:contracts:commands:{name}:v1"))
        if list(validator.iter_errors(valid)): raise SystemExit(f"terminal command validation: FAIL: {name} valid payload rejected")
        for mutation in forbidden:
            candidate = copy.deepcopy(valid); candidate.update(mutation)
            if mutation == {}: candidate = {}

            if not list(validator.iter_errors(candidate)): raise SystemExit(f"terminal command validation: FAIL: {name} accepted forbidden payload")
    print("terminal command validation: PASS (3 positive, 30 negative)")

if __name__ == "__main__": main()
