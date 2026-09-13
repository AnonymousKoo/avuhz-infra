#!/usr/bin/env python3
"""Run the exact v14 bounded-authorization validator with relocated history paths."""
from __future__ import annotations

from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LEGACY_PATH = Path(__file__).with_name("validate_bounded_authorization_plan_v14_legacy.py")

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


if __name__ == "__main__":
    raise SystemExit(legacy.main())
