#!/usr/bin/env python3
"""Run the exact v14 bounded-authorization validator plus later approval inventory compatibility."""
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
V16_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v16.approval.json"
)
V16_APPROVAL_FILE_DIGEST = (
    "sha256:9c1251084937314b0dcdc9df165370d845aaec30dbf692d8264eb4b45706068b"
)
V19_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v19.approval.json"
)
V19_APPROVAL_FILE_DIGEST = (
    "sha256:b62c4808b508b1afd5e3cc15d339dceb6231f9b3933e0862533379447a224544"
)
V21_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v21.approval.json"
)
V21_APPROVAL_FILE_DIGEST = (
    "sha256:5d8ae8463774fdb964379fc26238551200f4561a5d35b280b69ce9c9800f0fb9"
)
V22_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v22.approval.json"
)
V22_APPROVAL_FILE_DIGEST = (
    "sha256:7a633546900c00f502a33d5d5434499337489e2dc92701e94738322dd9571d20"
)
V24_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v24.approval.json"
)
V24_APPROVAL_FILE_DIGEST = (
    "sha256:1dfe97b377cf75d52b3660a0dfd8db648950fa4228b7ff42ba90151efa649cb2"
)
V25_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v25.approval.json"
)
V25_APPROVAL_FILE_DIGEST = (
    "sha256:ef122cf1b6c28853fe047c52a66ca096993e7b7ea05fd79c16d96f045821dfbd"
)
DATA_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-integration-v1.approval.json"
)
DATA_V1_APPROVAL_FILE_DIGEST = (
    "sha256:da44f85800453644c1cc4008c6209fa212633444cdade417d2b945b2f8c8d359"
)
DATA_V2_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-integration-v2.approval.json"
)
DATA_V2_APPROVAL_FILE_DIGEST = (
    "sha256:e0de76806b98dcb7cf837a562e4eeb198112e81a4318b432b1143bf510cf11ee"
)
DATA_V3_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-integration-v3.approval.json"
)
DATA_V3_APPROVAL_FILE_DIGEST = (
    "sha256:c8e31cdcbb9e89956797d016f005178702cac553ed6b50321f6b40fba1a84583"
)
DATA_SEARCH_PATH_REPAIR_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-search-path-repair-v1.approval.json"
)
DATA_SEARCH_PATH_REPAIR_V1_APPROVAL_FILE_DIGEST = (
    "sha256:bad4b3bccb211b386d4d7f064672ab08649635de6c2a4fa2e13284594f112643"
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
        V16_APPROVAL_PATH,
        V19_APPROVAL_PATH,
        V21_APPROVAL_PATH,
        V22_APPROVAL_PATH,
        V25_APPROVAL_PATH,
        DATA_V1_APPROVAL_PATH,
        DATA_V2_APPROVAL_PATH,
        DATA_V3_APPROVAL_PATH,
        DATA_SEARCH_PATH_REPAIR_V1_APPROVAL_PATH,
    }
    if V24_APPROVAL_PATH.exists():
        expected_approval_paths.add(V24_APPROVAL_PATH)
    actual_approval_paths = set(approvals_root.glob("*approval*.json"))
    if actual_approval_paths != expected_approval_paths:
        raise SystemExit(
            "approval artifact set differs from the exact authorized AUTH v8-v16 plus v19/v21/v22, optional exact v24, exact v25, and DATA v1-v3 and DATA search-path-repair v1 approvals"
        )
    if file_digest(V15_APPROVAL_PATH) != V15_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized v15 approval file digest mismatch")
    if file_digest(V16_APPROVAL_PATH) != V16_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized v16 approval file digest mismatch")
    if file_digest(V19_APPROVAL_PATH) != V19_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized v19 approval file digest mismatch")
    if file_digest(V21_APPROVAL_PATH) != V21_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized v21 approval file digest mismatch")
    if file_digest(V22_APPROVAL_PATH) != V22_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized v22 approval file digest mismatch")
    if V24_APPROVAL_PATH.exists() and file_digest(V24_APPROVAL_PATH) != V24_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized v24 approval file digest mismatch")
    if file_digest(V25_APPROVAL_PATH) != V25_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized v25 approval file digest mismatch")
    if file_digest(DATA_V1_APPROVAL_PATH) != DATA_V1_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact canonical DEVELOPMENT DATA v1 approval file digest mismatch")
    if file_digest(DATA_V2_APPROVAL_PATH) != DATA_V2_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized DEVELOPMENT DATA v2 approval file digest mismatch")
    if file_digest(DATA_V3_APPROVAL_PATH) != DATA_V3_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized DEVELOPMENT DATA v3 approval file digest mismatch")
    if (
        file_digest(DATA_SEARCH_PATH_REPAIR_V1_APPROVAL_PATH)
        != DATA_SEARCH_PATH_REPAIR_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit(
            "exact authorized DEVELOPMENT DATA search-path-repair v1 approval file digest mismatch"
        )

    # The preserved v14 validator must see its original exact v8-v14 inventory.
    # Filter only later approvals for that one historical glob call, then restore
    # pathlib immediately. The full current approval inventory is checked above.
    original_glob = Path.glob

    def compatibility_glob(self: Path, pattern: str):
        values = original_glob(self, pattern)
        if self == approvals_root and pattern == "*approval*.json":
            return (
                path
                for path in values
                if path not in {
                    V15_APPROVAL_PATH,
                    V16_APPROVAL_PATH,
                    V19_APPROVAL_PATH,
                    V21_APPROVAL_PATH,
                    V22_APPROVAL_PATH,
                    V24_APPROVAL_PATH,
                    V25_APPROVAL_PATH,
                    DATA_V1_APPROVAL_PATH,
                    DATA_V2_APPROVAL_PATH,
                    DATA_V3_APPROVAL_PATH,
                    DATA_SEARCH_PATH_REPAIR_V1_APPROVAL_PATH,
                }
            )
        return values

    Path.glob = compatibility_glob
    try:
        result = legacy.main()
    finally:
        Path.glob = original_glob

    if result != 0:
        return result
    print("bounded authorization-plan approval inventory compatibility: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
