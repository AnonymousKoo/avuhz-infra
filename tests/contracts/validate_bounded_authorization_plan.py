#!/usr/bin/env python3
"""Run the exact v14 bounded-authorization validator plus v15 approval inventory compatibility."""
from __future__ import annotations

import hashlib
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LEGACY_PATH = Path(__file__).with_name("validate_bounded_authorization_plan_v14_legacy.py")
V15_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v15.approval.json"
)
V15_APPROVAL_FILE_DIGEST = (
    "sha256:769afbb92b53f42db80a18ff0235d9c0171589786b16202652ef608c010ef673"
)

loader = SourceFileLoader("avuhz_bounded_authorization_plan_v14_legacy", str(LEGACY_PATH))
spec = spec_from_loader(loader.name, loader)
if spec is None:
    raise SystemExit("unable to load exact legacy bounded-authorization validator")
legacy = module_from_spec(spec)
loader.exec_module(legacy)

# Historical evidence keeps its original logical path strings. Only the physical
# files used to verify the immutable digests moved out of automatic migrations.
legacy.IDENTITY_MIGRATION_PATH = (
    ROOT
    / "supabase/provider-artifacts/development-auth/history/v1/20260908132000_development_auth_migration_identity_v1.sql"
)
legacy.HOOK_MIGRATION_PATH = (
    ROOT
    / "supabase/provider-artifacts/development-auth/history/v1/20260908133000_development_auth_custom_access_token_hook_v1.sql"
)
legacy.SEAL_MIGRATION_PATH = (
    ROOT
    / "supabase/provider-artifacts/development-auth/history/v1/20260908134000_development_auth_migration_identity_seal_v1.sql"
)
legacy.IDENTITY_TEST_PATH = (
    ROOT
    / "tests/migrations/history/development-auth/v1/development_auth_migration_identity_v1.py.snapshot"
)
legacy.HOOK_TEST_PATH = (
    ROOT
    / "tests/migrations/history/development-auth/v1/development_auth_custom_access_token_hook_v1.py.snapshot"
)
legacy.SEAL_TEST_PATH = (
    ROOT
    / "tests/migrations/history/development-auth/v1/development_auth_migration_identity_seal_v1.py.snapshot"
)


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    approvals_root = ROOT / "contracts/plans/v1"
    expected_approval_paths = {
        legacy.V8_APPROVAL_PATH,
        legacy.V9_APPROVAL_PATH,
        legacy.V10_APPROVAL_PATH,
        legacy.V11_APPROVAL_PATH,
        legacy.V12_APPROVAL_PATH,
        legacy.V13_APPROVAL_PATH,
        legacy.V14_APPROVAL_PATH,
        V15_APPROVAL_PATH,
    }
    actual_approval_paths = set(approvals_root.glob("*approval*.json"))
    if actual_approval_paths != expected_approval_paths:
        raise SystemExit(
            "approval artifact set differs from the exact authorized v8-v15 approvals"
        )
    if file_digest(V15_APPROVAL_PATH) != V15_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized v15 approval file digest mismatch")

    # The preserved v14 validator must see its original exact v8-v14 inventory.
    # Filter only the newly added v15 approval for that one historical glob call,
    # then restore pathlib immediately. The full v8-v15 inventory is checked above.
    original_glob = Path.glob

    def compatibility_glob(self: Path, pattern: str):
        values = original_glob(self, pattern)
        if self == approvals_root and pattern == "*approval*.json":
            return (path for path in values if path != V15_APPROVAL_PATH)
        return values

    Path.glob = compatibility_glob
    try:
        result = legacy.main()
    finally:
        Path.glob = original_glob

    if result != 0:
        return result
    print("bounded authorization-plan v15 approval inventory compatibility: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
