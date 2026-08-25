#!/usr/bin/env python3
import copy, sys
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from avuhz_runtime.schema_registry import SchemaRegistry
SCHEMA_ID = "urn:avuhz:schema:contracts:commands:verify-assessment-access-payload:v1"
def main():
    validator = Draft202012Validator(SchemaRegistry(ROOT / "contracts/schemas/v1").expanded(SCHEMA_ID))
    valid = {"assessment_access_grant_id": "a3000000-0000-4000-8000-000000000015"}
    if list(validator.iter_errors(valid)): raise SystemExit("verify-assessment-access validation: FAIL: valid payload rejected")
    for name, update in (("missing grant ID", {}), ("tenant", {"tenant_id": "a3000000-0000-4000-8000-000000000002"}), ("success", {"success": True}), ("verified_at", {"verified_at": "2030-01-15T15:00:00Z"}), ("expires_at", {"expires_at": "2030-02-14T15:00:00Z"}), ("credentials", {"credentials": {}}), ("provider payload", {"provider_payload": {}}), ("metadata", {"metadata": {}}), ("extra", {"arbitrary": "forbidden"})):
        candidate = copy.deepcopy(valid); candidate.update(update); candidate = {} if name == "missing grant ID" else candidate
        if not list(validator.iter_errors(candidate)): raise SystemExit(f"verify-assessment-access validation: FAIL: {name} accepted")
    print("verify-assessment-access validation: PASS (1 positive, 9 negative)")
if __name__ == "__main__":
    main()
