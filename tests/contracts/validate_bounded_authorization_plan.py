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
V26_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v26.approval.json"
)
V26_APPROVAL_FILE_DIGEST = (
    "sha256:4d7b8b08c7e934754b5988578575e313bc2ae15f3ca1f648732e7bb2d9d3c911"
)
V27_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v27.approval.json"
)
V27_APPROVAL_FILE_DIGEST = (
    "sha256:c9fae3414c77863904a5f28c912edfc78c9756f186c040258e551be708922e00"
)
V28_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v28.approval.json"
)
V28_APPROVAL_FILE_DIGEST = (
    "sha256:45c9dce1f521bd734b608d5a62fdc69043dca02c00508bfb5d9c05fa799e0f5d"
)
V31_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v31.approval.json"
)
V31_APPROVAL_FILE_DIGEST = (
    "sha256:374e2cddd7d0403cb5fbf49c634b46b8ea303f8a3af946c271a3b3d81341209a"
)
V32_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v32.approval.json"
)
V32_APPROVAL_FILE_DIGEST = (
    "sha256:3347347132b5d60942f4e43aae3ec67da980d1b90a6c0e1554ef25dae065bf22"
)
V32_SESSION_INSPECTION_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-v32-session-inspection-v1.approval.json"
)
V32_SESSION_INSPECTION_V1_APPROVAL_FILE_DIGEST = (
    "sha256:e181dd2d193b9cb1fbb167387ff171080e1db58da95e2477f8bcaf77e8b52997"
)
V32_SESSION_ATTRIBUTION_OWNER_INTERACTIVE_V1_APPROVAL_PATH = (
    ROOT
    / "contracts/plans/v1/development-auth-v32-session-attribution-owner-interactive-v1.approval.json"
)
V32_SESSION_ATTRIBUTION_OWNER_INTERACTIVE_V1_APPROVAL_FILE_DIGEST = (
    "sha256:6fcc8148b7fcafec3213baf26240eeaa147bc4242bdf8653ca4425e9561f2755"
)
V32_SYNTHETIC_SESSION_CLEANUP_V1_APPROVAL_PATH = (
    ROOT
    / "contracts/plans/v1/development-auth-v32-synthetic-session-cleanup-v1.approval.json"
)
V32_SYNTHETIC_SESSION_CLEANUP_V1_APPROVAL_FILE_DIGEST = (
    "sha256:f73aa8bd87768cf944a266316ac2779ae7b7a9b9868ff331a73cabbe6d7aeaa8"
)
V32_CREDENTIAL_REPAIR_V1_APPROVAL_PATH = (
    ROOT
    / "contracts/plans/v1/development-auth-v32-synthetic-session-cleanup-credential-repair-v1.approval.json"
)
V32_CREDENTIAL_REPAIR_V1_APPROVAL_FILE_DIGEST = (
    "sha256:c904810ac2187895ff5f4d3464bc5e8b906a3cb031daa05cf97ade9dddd36a53"
)
V32_SYNTHETIC_SESSION_CLEANUP_V2_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-v32-synthetic-session-cleanup-v2.approval.json"
)
V32_SYNTHETIC_SESSION_CLEANUP_V2_APPROVAL_FILE_DIGEST = (
    "sha256:b33723376547c4d47e7ecc6a7fedcbecca9944b8578aeeb11978624912f42ddc"
)
V32_SYNTHETIC_SESSION_CLEANUP_V4_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-v32-synthetic-session-cleanup-v4.approval.json"
)
V32_SYNTHETIC_SESSION_CLEANUP_V4_APPROVAL_FILE_DIGEST = (
    "sha256:22cb5f5577df8a93ce90940d76503cf4f5250d71db886e600d5b32c2d0c64e5a"
)
V32_SESSION_STATE_REBASELINE_OWNER_INTERACTIVE_V1_APPROVAL_PATH = (
    ROOT
    / "contracts/plans/v1/development-auth-v32-session-state-rebaseline-owner-interactive-v1.approval.json"
)
V32_SESSION_STATE_REBASELINE_OWNER_INTERACTIVE_V1_APPROVAL_FILE_DIGEST = (
    "sha256:9973a0880bba000298b3f87b21118bb35e4411161d5c96291619100acec46a60"
)
RECOVERY_SHAPE_DIAGNOSTIC_V2_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-recovery-verification-shape-diagnostic-v2.approval.json"
)
RECOVERY_SHAPE_DIAGNOSTIC_V2_APPROVAL_FILE_DIGEST = (
    "sha256:d5f1826c95a6c01a7c1fa542eaeec6b165e0e14b64648a56867030b1c1c79d8c"
)
RECOVERY_PREDICATE_DIAGNOSTIC_V4_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-recovery-verification-predicate-diagnostic-v4.approval.json"
)
RECOVERY_PREDICATE_DIAGNOSTIC_V4_APPROVAL_FILE_DIGEST = (
    "sha256:8d72236c3410bb191df3e462f2c0d71b31bf71422272bf8d3968e2df6d8968b5"
)
REPAIRED_RECOVERY_LIFECYCLE_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-repaired-recovery-lifecycle-v1.approval.json"
)
REPAIRED_RECOVERY_LIFECYCLE_V2_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-repaired-recovery-lifecycle-v2.approval.json"
)
REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_PROVISION_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-repaired-recovery-lifecycle-credential-provision-v1.approval.json"
)
REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_BINDING_CONTINUATION_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-repaired-recovery-lifecycle-credential-binding-continuation-v1.approval.json"
)
REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_RETIREMENT_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-repaired-recovery-lifecycle-credential-retirement-v1.approval.json"
)
SYNTHETIC_TOKEN_VALIDATION_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-synthetic-token-validation-v1.approval.json"
)
SYNTHETIC_TOKEN_VALIDATION_V2_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-synthetic-token-validation-v2.approval.json"
)
SYNTHETIC_TOKEN_VALIDATION_V3_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-synthetic-token-validation-v3.approval.json"
)
SYNTHETIC_TOKEN_VALIDATION_V3_CREDENTIAL_RETIREMENT_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-synthetic-token-validation-v3-credential-retirement-v1.approval.json"
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
DATA_RUNTIME_LOGIN_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-runtime-login-v1.approval.json"
)
DATA_RUNTIME_LOGIN_V1_APPROVAL_FILE_DIGEST = (
    "sha256:00f4957c1a8b4fef1d2ebdb081bae75b40b00934e67159cc05e7ecc185f3bc5c"
)
DATA_RUNTIME_LOGIN_V2_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-runtime-login-v2.approval.json"
)
DATA_RUNTIME_LOGIN_V2_APPROVAL_FILE_DIGEST = (
    "sha256:ffa2c4476421b2f18caad7ab8323330d60ef64f460ac0bb924d4849a15cccf55"
)
DATA_RUNTIME_LOGIN_V4_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-runtime-login-v4.approval.json"
)
DATA_RUNTIME_LOGIN_V4_APPROVAL_FILE_DIGEST = (
    "sha256:0a45e942b5a711fa2b53dd21c086288d342183d5821d1d8739706d1dfd6f9c75"
)
DATA_RUNTIME_LOGIN_V5_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-runtime-login-v5.approval.json"
)
DATA_RUNTIME_LOGIN_V5_APPROVAL_FILE_DIGEST = (
    "sha256:28ea5df488aa12e85c4eec8b63aedd4b74582baf4d38d69351d9bedd1d6a54c7"
)
DATA_RUNTIME_LOGIN_V6_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-runtime-login-v6.approval.json"
)
DATA_RUNTIME_LOGIN_V6_APPROVAL_FILE_DIGEST = (
    "sha256:f3aa5ce81504047365c84cfaa56f40a786ae54f724605ca88836112e4d111127"
)
DATA_RUNTIME_LOGIN_V8_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-runtime-login-v8.approval.json"
)
DATA_RUNTIME_LOGIN_V8_APPROVAL_FILE_DIGEST = (
    "sha256:ba4596d613074ed11087f57d69c32ff88f6da5976f265e16d9ca59620113fc82"
)
DATA_RUNTIME_LOGIN_V10_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-runtime-login-v10.approval.json"
)
DATA_RUNTIME_LOGIN_V10_APPROVAL_FILE_DIGEST = (
    "sha256:0edd0886c8080ca59b0a11a97263ffdde90bc0e24dc582c0596d98e1f10dbc96"
)
DATA_RUNTIME_LOGIN_V11_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-runtime-login-v11.approval.json"
)
DATA_RUNTIME_LOGIN_V11_APPROVAL_FILE_DIGEST = (
    "sha256:0c8d4aa56b1c87cc8070c4c13a784858d459b8d3d72da9dec9ec0c9886a37b43"
)
DATA_RUNTIME_LOGIN_V12_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-runtime-login-v12.approval.json"
)
DATA_RUNTIME_LOGIN_V12_APPROVAL_FILE_DIGEST = (
    "sha256:37e63350a2a3cdd6e16c6e962ad1e74ed4cd9016ec9d8e757583298e02174b29"
)
DATA_RUNTIME_LOGIN_V13_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-runtime-login-v13.approval.json"
)
DATA_RUNTIME_LOGIN_V13_APPROVAL_FILE_DIGEST = (
    "sha256:e23109eca03ca180368e4fa74537390e27269d21134f21b835e23b02c1ae8f94"
)
DATA_RUNTIME_LOGIN_V15_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-runtime-login-v15.approval.json"
)
DATA_RUNTIME_LOGIN_V15_APPROVAL_FILE_DIGEST = (
    "sha256:f4e04df684674cfc2744024a11f4325dc2c76abcf81623679d63819cf4e97735"
)
RENDER_DATA_SECRET_BINDING_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-data-secret-binding-v1.approval.json"
)
RENDER_DATA_SECRET_BINDING_V1_APPROVAL_FILE_DIGEST = (
    "sha256:8c04f1a2437e62ed6957189f1140e719c8f89b3d61cafcf5bae57e0d7a32f595"
)
RENDER_DATA_SECRET_BINDING_V2_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-data-secret-binding-v2.approval.json"
)
RENDER_DATA_SECRET_BINDING_V2_APPROVAL_FILE_DIGEST = (
    "sha256:ac47ed08cee129d6e64010279cb19435e3b816f23db84b32b1de83c620ce2948"
)
RENDER_DATA_SECRET_BINDING_CORRECTION_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-data-secret-binding-correction-v1.approval.json"
)
RENDER_DATA_SECRET_BINDING_CORRECTION_V1_APPROVAL_FILE_DIGEST = (
    "sha256:3c13a8478fd971975f6628cb7d7864874ad51098cd4d9692bea21b3bf3a6cae6"
)
RENDER_DATA_SUPAVISOR_SESSION_DSN_V2_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-data-supavisor-session-dsn-v2.approval.json"
)
RENDER_DATA_SUPAVISOR_SESSION_DSN_V2_APPROVAL_FILE_DIGEST = (
    "sha256:d33ecffafbb2553a6b74e1022559db6534f9400556f94e7c0908982ee261d7bd"
)
RENDER_DEPLOYMENT_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-deployment-v1.approval.json"
)
RENDER_DEPLOYMENT_V1_APPROVAL_FILE_DIGEST = (
    "sha256:3e2257bb10ab7d20e425752dad91b13f0168ed6952588e6200b42824dc49fa82"
)
RENDER_DEPLOYMENT_V2_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-deployment-v2.approval.json"
)
RENDER_DEPLOYMENT_V2_APPROVAL_FILE_DIGEST = (
    "sha256:4560b65bcbac81375f0bb9fe53f4bcf90e84130dd7608ab6fc6caa9a6ce541a3"
)
RENDER_DEPLOYMENT_V3_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-deployment-v3.approval.json"
)
RENDER_DEPLOYMENT_V3_APPROVAL_FILE_DIGEST = (
    "sha256:97d84fb242cb2366b9b4f72788399b264fbb34f8a1230f235cbc7a7b17372cf2"
)
RENDER_DEPLOYMENT_V4_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-deployment-v4.approval.json"
)
RENDER_DEPLOYMENT_V4_APPROVAL_FILE_DIGEST = (
    "sha256:ae8d5c82eb73f5c45bf06b62eb4d9acd308597d6910ef80c944e4226544a3582"
)
RENDER_DEPLOYMENT_V5_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-deployment-v5.approval.json"
)
RENDER_DEPLOYMENT_V5_APPROVAL_FILE_DIGEST = (
    "sha256:cc61d7f49936a75c158b7785223f20dd822f31f745701d07b1f537940d79adce"
)
RENDER_DEPLOYMENT_V7_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-deployment-v7.approval.json"
)
RENDER_DEPLOYMENT_V7_APPROVAL_FILE_DIGEST = (
    "sha256:2ed369ccffc9d02d3e2f1da8345349a28d491996d68e3adf708ef8ee9cfd4cf7"
)
RENDER_DEPLOYMENT_V8_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-deployment-v8.approval.json"
)
RENDER_DEPLOYMENT_V8_APPROVAL_FILE_DIGEST = (
    "sha256:c515021103ea04203c393fbfd9dca762928c7185fef4b40d89cc0eaa3da3f104"
)
RENDER_DEPLOYMENT_V10_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-deployment-v10.approval.json"
)
RENDER_DEPLOYMENT_V10_APPROVAL_FILE_DIGEST = (
    "sha256:a8f7019a7eb489bcf605ff568a7d34aa9861ff71ae287557bd4f458ac3e879c9"
)
IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-implementation-handoff-provider-adapter-auth-v1.approval.json"
)
IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_V1_APPROVAL_FILE_DIGEST = (
    "sha256:c97daa6aea89024328ef01aec5a2147b91e5ea1e193966196de22aa9645b267e"
)
IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_CREDENTIAL_REPAIR_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-implementation-handoff-provider-adapter-auth-credential-repair-v1.approval.json"
)
IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_CREDENTIAL_REPAIR_V1_APPROVAL_FILE_DIGEST = (
    "sha256:b8b5249f0a4813626c74712fe99620c7625ace1a843b1d2d4db07a64f0ef1277"
)
RENDER_RUNTIME_CONFIG_REPAIR_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-runtime-config-repair-v1.approval.json"
)
RENDER_RUNTIME_CONFIG_REPAIR_V1_APPROVAL_FILE_DIGEST = (
    "sha256:2957313e8833e7f8219fddc36ef96fb587f9a90d947b4c19ac4c061d92f847fe"
)
RENDER_RUNTIME_CONFIG_REPAIR_V4_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-runtime-config-repair-v4.approval.json"
)
RENDER_RUNTIME_CONFIG_REPAIR_V4_APPROVAL_FILE_DIGEST = (
    "sha256:f10934709c7ae1f19053af322f1bb91a026bc1d1f05aab470f85bc373cfdf6e5"
)
RENDER_RUNTIME_CONFIG_REPAIR_V6_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-runtime-config-repair-v6.approval.json"
)
RENDER_RUNTIME_CONFIG_REPAIR_V6_APPROVAL_FILE_DIGEST = (
    "sha256:73e195ce493906e8c19acfceffc0efbb91cd048ce2f4d27a523cf86c0268a730"
)
RENDER_RUNTIME_CONFIG_FINAL_VERIFICATION_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-render-runtime-config-final-verification-v1.approval.json"
)
RENDER_RUNTIME_CONFIG_FINAL_VERIFICATION_V1_APPROVAL_FILE_DIGEST = (
    "sha256:a5c12a93dd2cc1f79f64a934cc08dc8106f6402f8fada5d3344ac60b5e851d9f"
)
DATA_CATALOG_RLS_VALIDATION_V1_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-data-catalog-rls-validation-v1.approval.json"
)
DATA_CATALOG_RLS_VALIDATION_V1_APPROVAL_FILE_DIGEST = (
    "sha256:b9adf8923d0aff6ed8a25b2465fb873fcad6ba87e103f05a49d6f4cb8e17d46c"
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
        V26_APPROVAL_PATH,
        V27_APPROVAL_PATH,
        V28_APPROVAL_PATH,
        V32_APPROVAL_PATH,
        V32_SESSION_INSPECTION_V1_APPROVAL_PATH,
        V32_SESSION_ATTRIBUTION_OWNER_INTERACTIVE_V1_APPROVAL_PATH,
        V32_SYNTHETIC_SESSION_CLEANUP_V1_APPROVAL_PATH,
        V32_CREDENTIAL_REPAIR_V1_APPROVAL_PATH,
        V32_SYNTHETIC_SESSION_CLEANUP_V2_APPROVAL_PATH,
        V32_SYNTHETIC_SESSION_CLEANUP_V4_APPROVAL_PATH,
        V32_SESSION_STATE_REBASELINE_OWNER_INTERACTIVE_V1_APPROVAL_PATH,
        RECOVERY_SHAPE_DIAGNOSTIC_V2_APPROVAL_PATH,
        DATA_V1_APPROVAL_PATH,
        DATA_V2_APPROVAL_PATH,
        DATA_V3_APPROVAL_PATH,
        DATA_SEARCH_PATH_REPAIR_V1_APPROVAL_PATH,
    }
    if DATA_RUNTIME_LOGIN_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(DATA_RUNTIME_LOGIN_V1_APPROVAL_PATH)
    if DATA_RUNTIME_LOGIN_V2_APPROVAL_PATH.exists():
        expected_approval_paths.add(DATA_RUNTIME_LOGIN_V2_APPROVAL_PATH)
    if DATA_RUNTIME_LOGIN_V4_APPROVAL_PATH.exists():
        expected_approval_paths.add(DATA_RUNTIME_LOGIN_V4_APPROVAL_PATH)
    if DATA_RUNTIME_LOGIN_V5_APPROVAL_PATH.exists():
        expected_approval_paths.add(DATA_RUNTIME_LOGIN_V5_APPROVAL_PATH)
    if DATA_RUNTIME_LOGIN_V6_APPROVAL_PATH.exists():
        expected_approval_paths.add(DATA_RUNTIME_LOGIN_V6_APPROVAL_PATH)
    if DATA_RUNTIME_LOGIN_V8_APPROVAL_PATH.exists():
        expected_approval_paths.add(DATA_RUNTIME_LOGIN_V8_APPROVAL_PATH)
    if DATA_RUNTIME_LOGIN_V10_APPROVAL_PATH.exists():
        expected_approval_paths.add(DATA_RUNTIME_LOGIN_V10_APPROVAL_PATH)
    if DATA_RUNTIME_LOGIN_V11_APPROVAL_PATH.exists():
        expected_approval_paths.add(DATA_RUNTIME_LOGIN_V11_APPROVAL_PATH)
    if DATA_RUNTIME_LOGIN_V12_APPROVAL_PATH.exists():
        expected_approval_paths.add(DATA_RUNTIME_LOGIN_V12_APPROVAL_PATH)
    if DATA_RUNTIME_LOGIN_V13_APPROVAL_PATH.exists():
        expected_approval_paths.add(DATA_RUNTIME_LOGIN_V13_APPROVAL_PATH)
    if DATA_RUNTIME_LOGIN_V15_APPROVAL_PATH.exists():
        expected_approval_paths.add(DATA_RUNTIME_LOGIN_V15_APPROVAL_PATH)
    if RENDER_DATA_SECRET_BINDING_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_DATA_SECRET_BINDING_V1_APPROVAL_PATH)
    if RENDER_DATA_SECRET_BINDING_V2_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_DATA_SECRET_BINDING_V2_APPROVAL_PATH)
    if RENDER_DATA_SECRET_BINDING_CORRECTION_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_DATA_SECRET_BINDING_CORRECTION_V1_APPROVAL_PATH)
    if RENDER_DATA_SUPAVISOR_SESSION_DSN_V2_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_DATA_SUPAVISOR_SESSION_DSN_V2_APPROVAL_PATH)
    if RENDER_DEPLOYMENT_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_DEPLOYMENT_V1_APPROVAL_PATH)
    if RENDER_DEPLOYMENT_V2_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_DEPLOYMENT_V2_APPROVAL_PATH)
    if RENDER_DEPLOYMENT_V3_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_DEPLOYMENT_V3_APPROVAL_PATH)
    if RENDER_DEPLOYMENT_V4_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_DEPLOYMENT_V4_APPROVAL_PATH)
    if RENDER_DEPLOYMENT_V5_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_DEPLOYMENT_V5_APPROVAL_PATH)
    if RENDER_DEPLOYMENT_V7_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_DEPLOYMENT_V7_APPROVAL_PATH)
    if RENDER_DEPLOYMENT_V8_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_DEPLOYMENT_V8_APPROVAL_PATH)
    if RENDER_DEPLOYMENT_V10_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_DEPLOYMENT_V10_APPROVAL_PATH)
    if IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_V1_APPROVAL_PATH)
    if IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_CREDENTIAL_REPAIR_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_CREDENTIAL_REPAIR_V1_APPROVAL_PATH)
    if RENDER_RUNTIME_CONFIG_REPAIR_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_RUNTIME_CONFIG_REPAIR_V1_APPROVAL_PATH)
    if RENDER_RUNTIME_CONFIG_REPAIR_V4_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_RUNTIME_CONFIG_REPAIR_V4_APPROVAL_PATH)
    if RENDER_RUNTIME_CONFIG_REPAIR_V6_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_RUNTIME_CONFIG_REPAIR_V6_APPROVAL_PATH)
    if RENDER_RUNTIME_CONFIG_FINAL_VERIFICATION_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(RENDER_RUNTIME_CONFIG_FINAL_VERIFICATION_V1_APPROVAL_PATH)
    if DATA_CATALOG_RLS_VALIDATION_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(DATA_CATALOG_RLS_VALIDATION_V1_APPROVAL_PATH)
    if V24_APPROVAL_PATH.exists():
        expected_approval_paths.add(V24_APPROVAL_PATH)
    if V31_APPROVAL_PATH.exists():
        expected_approval_paths.add(V31_APPROVAL_PATH)
    if RECOVERY_PREDICATE_DIAGNOSTIC_V4_APPROVAL_PATH.exists():
        expected_approval_paths.add(RECOVERY_PREDICATE_DIAGNOSTIC_V4_APPROVAL_PATH)
    if REPAIRED_RECOVERY_LIFECYCLE_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(REPAIRED_RECOVERY_LIFECYCLE_V1_APPROVAL_PATH)
    if REPAIRED_RECOVERY_LIFECYCLE_V2_APPROVAL_PATH.exists():
        expected_approval_paths.add(REPAIRED_RECOVERY_LIFECYCLE_V2_APPROVAL_PATH)
    if REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_PROVISION_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_PROVISION_V1_APPROVAL_PATH)
    if REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_BINDING_CONTINUATION_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_BINDING_CONTINUATION_V1_APPROVAL_PATH)
    if REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_RETIREMENT_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_RETIREMENT_V1_APPROVAL_PATH)
    if SYNTHETIC_TOKEN_VALIDATION_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(SYNTHETIC_TOKEN_VALIDATION_V1_APPROVAL_PATH)
    if SYNTHETIC_TOKEN_VALIDATION_V2_APPROVAL_PATH.exists():
        expected_approval_paths.add(SYNTHETIC_TOKEN_VALIDATION_V2_APPROVAL_PATH)
    if SYNTHETIC_TOKEN_VALIDATION_V3_APPROVAL_PATH.exists():
        expected_approval_paths.add(SYNTHETIC_TOKEN_VALIDATION_V3_APPROVAL_PATH)
    if SYNTHETIC_TOKEN_VALIDATION_V3_CREDENTIAL_RETIREMENT_V1_APPROVAL_PATH.exists():
        expected_approval_paths.add(SYNTHETIC_TOKEN_VALIDATION_V3_CREDENTIAL_RETIREMENT_V1_APPROVAL_PATH)
    actual_approval_paths = set(approvals_root.glob("*approval*.json"))
    if actual_approval_paths != expected_approval_paths:
        raise SystemExit(
            "approval artifact set differs from the exact authorized canonical AUTH/DATA/Render/shared-adapter approval inventory"
        )
    if (
        RENDER_DATA_SUPAVISOR_SESSION_DSN_V2_APPROVAL_PATH.exists()
        and file_digest(RENDER_DATA_SUPAVISOR_SESSION_DSN_V2_APPROVAL_PATH)
        != RENDER_DATA_SUPAVISOR_SESSION_DSN_V2_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("exact authorized Render Supavisor session DSN v2 approval file digest mismatch")
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
    if file_digest(V26_APPROVAL_PATH) != V26_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized v26 approval file digest mismatch")
    if file_digest(V27_APPROVAL_PATH) != V27_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized v27 approval file digest mismatch")
    if file_digest(V28_APPROVAL_PATH) != V28_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized v28 approval file digest mismatch")
    if V31_APPROVAL_PATH.exists() and file_digest(V31_APPROVAL_PATH) != V31_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized v31 approval file digest mismatch")
    if file_digest(V32_APPROVAL_PATH) != V32_APPROVAL_FILE_DIGEST:
        raise SystemExit("exact authorized v32 approval file digest mismatch")
    if (
        file_digest(V32_SESSION_INSPECTION_V1_APPROVAL_PATH)
        != V32_SESSION_INSPECTION_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("exact authorized v32 session inspection v1 approval file digest mismatch")
    if (
        file_digest(V32_SESSION_ATTRIBUTION_OWNER_INTERACTIVE_V1_APPROVAL_PATH)
        != V32_SESSION_ATTRIBUTION_OWNER_INTERACTIVE_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit(
            "exact authorized v32 owner-interactive session attribution v1 approval file digest mismatch"
        )
    if (
        file_digest(V32_SYNTHETIC_SESSION_CLEANUP_V1_APPROVAL_PATH)
        != V32_SYNTHETIC_SESSION_CLEANUP_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit(
            "exact authorized v32 synthetic-session cleanup v1 approval file digest mismatch"
        )
    if (
        file_digest(V32_CREDENTIAL_REPAIR_V1_APPROVAL_PATH)
        != V32_CREDENTIAL_REPAIR_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit(
            "exact authorized v32 cleanup credential-repair v1 approval file digest mismatch"
        )
    if (
        file_digest(V32_SYNTHETIC_SESSION_CLEANUP_V2_APPROVAL_PATH)
        != V32_SYNTHETIC_SESSION_CLEANUP_V2_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("exact authorized v32 synthetic-session cleanup v2 approval file digest mismatch")
    if (
        file_digest(V32_SYNTHETIC_SESSION_CLEANUP_V4_APPROVAL_PATH)
        != V32_SYNTHETIC_SESSION_CLEANUP_V4_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("exact authorized v32 synthetic-session cleanup v4 approval file digest mismatch")
    if (
        file_digest(V32_SESSION_STATE_REBASELINE_OWNER_INTERACTIVE_V1_APPROVAL_PATH)
        != V32_SESSION_STATE_REBASELINE_OWNER_INTERACTIVE_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("exact authorized v32 session-state rebaseline v1 approval file digest mismatch")
    if (
        file_digest(RECOVERY_SHAPE_DIAGNOSTIC_V2_APPROVAL_PATH)
        != RECOVERY_SHAPE_DIAGNOSTIC_V2_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("exact authorized recovery-shape diagnostic v2 approval file digest mismatch")
    if (
        RECOVERY_PREDICATE_DIAGNOSTIC_V4_APPROVAL_PATH.exists()
        and file_digest(RECOVERY_PREDICATE_DIAGNOSTIC_V4_APPROVAL_PATH)
        != RECOVERY_PREDICATE_DIAGNOSTIC_V4_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("exact authorized recovery-predicate diagnostic v4 approval file digest mismatch")
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

    if (
        DATA_RUNTIME_LOGIN_V1_APPROVAL_PATH.exists()
        and file_digest(DATA_RUNTIME_LOGIN_V1_APPROVAL_PATH)
        != DATA_RUNTIME_LOGIN_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit(
            "exact authorized DEVELOPMENT DATA runtime-login v1 approval file digest mismatch"
        )

    if (
        DATA_RUNTIME_LOGIN_V2_APPROVAL_PATH.exists()
        and file_digest(DATA_RUNTIME_LOGIN_V2_APPROVAL_PATH)
        != DATA_RUNTIME_LOGIN_V2_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit(
            "exact authorized DEVELOPMENT DATA runtime-login v2 approval file digest mismatch"
        )

    if (
        DATA_RUNTIME_LOGIN_V4_APPROVAL_PATH.exists()
        and file_digest(DATA_RUNTIME_LOGIN_V4_APPROVAL_PATH)
        != DATA_RUNTIME_LOGIN_V4_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit(
            "exact authorized DEVELOPMENT DATA runtime-login v4 approval file digest mismatch"
        )

    if (
        DATA_RUNTIME_LOGIN_V5_APPROVAL_PATH.exists()
        and file_digest(DATA_RUNTIME_LOGIN_V5_APPROVAL_PATH)
        != DATA_RUNTIME_LOGIN_V5_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit(
            "exact authorized DEVELOPMENT DATA runtime-login v5 approval file digest mismatch"
        )

    if (
        DATA_RUNTIME_LOGIN_V6_APPROVAL_PATH.exists()
        and file_digest(DATA_RUNTIME_LOGIN_V6_APPROVAL_PATH)
        != DATA_RUNTIME_LOGIN_V6_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit(
            "exact authorized DEVELOPMENT DATA runtime-login v6 approval file digest mismatch"
        )

    if (DATA_RUNTIME_LOGIN_V8_APPROVAL_PATH.exists() and file_digest(DATA_RUNTIME_LOGIN_V8_APPROVAL_PATH) != DATA_RUNTIME_LOGIN_V8_APPROVAL_FILE_DIGEST):
        raise SystemExit("exact authorized DEVELOPMENT DATA runtime-login v8 approval file digest mismatch")

    if (DATA_RUNTIME_LOGIN_V10_APPROVAL_PATH.exists() and file_digest(DATA_RUNTIME_LOGIN_V10_APPROVAL_PATH) != DATA_RUNTIME_LOGIN_V10_APPROVAL_FILE_DIGEST):
        raise SystemExit("exact authorized DEVELOPMENT DATA runtime-login v10 approval file digest mismatch")

    if (DATA_RUNTIME_LOGIN_V13_APPROVAL_PATH.exists() and file_digest(DATA_RUNTIME_LOGIN_V13_APPROVAL_PATH) != DATA_RUNTIME_LOGIN_V13_APPROVAL_FILE_DIGEST):
        raise SystemExit("DEVELOPMENT DATA runtime-login v13 approval file digest mismatch")
    if (DATA_RUNTIME_LOGIN_V15_APPROVAL_PATH.exists() and file_digest(DATA_RUNTIME_LOGIN_V15_APPROVAL_PATH) != DATA_RUNTIME_LOGIN_V15_APPROVAL_FILE_DIGEST):
        raise SystemExit("DEVELOPMENT DATA runtime-login v15 approval file digest mismatch")
    if (
        RENDER_DATA_SECRET_BINDING_V1_APPROVAL_PATH.exists()
        and file_digest(RENDER_DATA_SECRET_BINDING_V1_APPROVAL_PATH)
        != RENDER_DATA_SECRET_BINDING_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render DATA secret-binding v1 approval file digest mismatch")
    if (
        RENDER_DATA_SECRET_BINDING_V2_APPROVAL_PATH.exists()
        and file_digest(RENDER_DATA_SECRET_BINDING_V2_APPROVAL_PATH)
        != RENDER_DATA_SECRET_BINDING_V2_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render DATA secret-binding v2 approval file digest mismatch")
    if (
        RENDER_DATA_SECRET_BINDING_CORRECTION_V1_APPROVAL_PATH.exists()
        and file_digest(RENDER_DATA_SECRET_BINDING_CORRECTION_V1_APPROVAL_PATH)
        != RENDER_DATA_SECRET_BINDING_CORRECTION_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render DATA secret-binding correction v1 approval file digest mismatch")
    if (
        RENDER_DEPLOYMENT_V1_APPROVAL_PATH.exists()
        and file_digest(RENDER_DEPLOYMENT_V1_APPROVAL_PATH)
        != RENDER_DEPLOYMENT_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render deployment v1 approval file digest mismatch")
    if (
        RENDER_DEPLOYMENT_V2_APPROVAL_PATH.exists()
        and file_digest(RENDER_DEPLOYMENT_V2_APPROVAL_PATH)
        != RENDER_DEPLOYMENT_V2_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render deployment v2 approval file digest mismatch")
    if (
        RENDER_DEPLOYMENT_V3_APPROVAL_PATH.exists()
        and file_digest(RENDER_DEPLOYMENT_V3_APPROVAL_PATH)
        != RENDER_DEPLOYMENT_V3_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render deployment v3 approval file digest mismatch")
    if (
        RENDER_DEPLOYMENT_V4_APPROVAL_PATH.exists()
        and file_digest(RENDER_DEPLOYMENT_V4_APPROVAL_PATH)
        != RENDER_DEPLOYMENT_V4_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render deployment v4 approval file digest mismatch")
    if (
        RENDER_DEPLOYMENT_V5_APPROVAL_PATH.exists()
        and file_digest(RENDER_DEPLOYMENT_V5_APPROVAL_PATH)
        != RENDER_DEPLOYMENT_V5_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render deployment v5 approval file digest mismatch")
    if (
        RENDER_DEPLOYMENT_V7_APPROVAL_PATH.exists()
        and file_digest(RENDER_DEPLOYMENT_V7_APPROVAL_PATH)
        != RENDER_DEPLOYMENT_V7_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render deployment v7 approval file digest mismatch")
    if (
        RENDER_DEPLOYMENT_V8_APPROVAL_PATH.exists()
        and file_digest(RENDER_DEPLOYMENT_V8_APPROVAL_PATH)
        != RENDER_DEPLOYMENT_V8_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render deployment v8 approval file digest mismatch")
    if (
        RENDER_DEPLOYMENT_V10_APPROVAL_PATH.exists()
        and file_digest(RENDER_DEPLOYMENT_V10_APPROVAL_PATH)
        != RENDER_DEPLOYMENT_V10_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render deployment v10 approval file digest mismatch")
    if (
        IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_V1_APPROVAL_PATH.exists()
        and file_digest(IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_V1_APPROVAL_PATH)
        != IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT ImplementationHandoff provider-adapter Auth v1 approval file digest mismatch")
    if (
        IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_CREDENTIAL_REPAIR_V1_APPROVAL_PATH.exists()
        and file_digest(IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_CREDENTIAL_REPAIR_V1_APPROVAL_PATH)
        != IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_CREDENTIAL_REPAIR_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT ImplementationHandoff provider-adapter Auth credential repair v1 approval file digest mismatch")
    if (
        RENDER_RUNTIME_CONFIG_REPAIR_V1_APPROVAL_PATH.exists()
        and file_digest(RENDER_RUNTIME_CONFIG_REPAIR_V1_APPROVAL_PATH)
        != RENDER_RUNTIME_CONFIG_REPAIR_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render runtime config repair v1 approval file digest mismatch")
    if (
        RENDER_RUNTIME_CONFIG_REPAIR_V4_APPROVAL_PATH.exists()
        and file_digest(RENDER_RUNTIME_CONFIG_REPAIR_V4_APPROVAL_PATH)
        != RENDER_RUNTIME_CONFIG_REPAIR_V4_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render runtime config repair v4 approval file digest mismatch")
    if (
        RENDER_RUNTIME_CONFIG_REPAIR_V6_APPROVAL_PATH.exists()
        and file_digest(RENDER_RUNTIME_CONFIG_REPAIR_V6_APPROVAL_PATH)
        != RENDER_RUNTIME_CONFIG_REPAIR_V6_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render runtime config repair v6 approval file digest mismatch")
    if (
        RENDER_RUNTIME_CONFIG_FINAL_VERIFICATION_V1_APPROVAL_PATH.exists()
        and file_digest(RENDER_RUNTIME_CONFIG_FINAL_VERIFICATION_V1_APPROVAL_PATH)
        != RENDER_RUNTIME_CONFIG_FINAL_VERIFICATION_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit("DEVELOPMENT Render runtime config final verification v1 approval file digest mismatch")
    if (
        DATA_CATALOG_RLS_VALIDATION_V1_APPROVAL_PATH.exists()
        and file_digest(DATA_CATALOG_RLS_VALIDATION_V1_APPROVAL_PATH)
        != DATA_CATALOG_RLS_VALIDATION_V1_APPROVAL_FILE_DIGEST
    ):
        raise SystemExit(
            "DEVELOPMENT DATA catalog/RLS validation v1 approval file digest mismatch"
        )
    if (DATA_RUNTIME_LOGIN_V12_APPROVAL_PATH.exists() and file_digest(DATA_RUNTIME_LOGIN_V12_APPROVAL_PATH) != DATA_RUNTIME_LOGIN_V12_APPROVAL_FILE_DIGEST):
        raise SystemExit("DEVELOPMENT DATA runtime-login v12 approval file digest mismatch")
    if (DATA_RUNTIME_LOGIN_V11_APPROVAL_PATH.exists() and file_digest(DATA_RUNTIME_LOGIN_V11_APPROVAL_PATH) != DATA_RUNTIME_LOGIN_V11_APPROVAL_FILE_DIGEST):
        raise SystemExit("exact authorized DEVELOPMENT DATA runtime-login v11 approval file digest mismatch")

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
                    V26_APPROVAL_PATH,
                    V27_APPROVAL_PATH,
                    V28_APPROVAL_PATH,
                    V31_APPROVAL_PATH,
                    V32_APPROVAL_PATH,
                    V32_SESSION_INSPECTION_V1_APPROVAL_PATH,
                    V32_SESSION_ATTRIBUTION_OWNER_INTERACTIVE_V1_APPROVAL_PATH,
                    V32_SYNTHETIC_SESSION_CLEANUP_V1_APPROVAL_PATH,
                    V32_CREDENTIAL_REPAIR_V1_APPROVAL_PATH,
                    V32_SYNTHETIC_SESSION_CLEANUP_V2_APPROVAL_PATH,
                    V32_SYNTHETIC_SESSION_CLEANUP_V4_APPROVAL_PATH,
                    V32_SESSION_STATE_REBASELINE_OWNER_INTERACTIVE_V1_APPROVAL_PATH,
                    RECOVERY_SHAPE_DIAGNOSTIC_V2_APPROVAL_PATH,
                    DATA_V1_APPROVAL_PATH,
                    DATA_V2_APPROVAL_PATH,
                    DATA_V3_APPROVAL_PATH,
                    DATA_SEARCH_PATH_REPAIR_V1_APPROVAL_PATH,
                    DATA_RUNTIME_LOGIN_V1_APPROVAL_PATH,
                    DATA_RUNTIME_LOGIN_V2_APPROVAL_PATH,
                    DATA_RUNTIME_LOGIN_V4_APPROVAL_PATH,
                    DATA_RUNTIME_LOGIN_V5_APPROVAL_PATH,
                    DATA_RUNTIME_LOGIN_V6_APPROVAL_PATH,
                    DATA_RUNTIME_LOGIN_V8_APPROVAL_PATH,
                    DATA_RUNTIME_LOGIN_V10_APPROVAL_PATH,
                    DATA_RUNTIME_LOGIN_V11_APPROVAL_PATH,
                    DATA_RUNTIME_LOGIN_V12_APPROVAL_PATH,
                    DATA_RUNTIME_LOGIN_V13_APPROVAL_PATH,
                    DATA_RUNTIME_LOGIN_V15_APPROVAL_PATH,
                    DATA_CATALOG_RLS_VALIDATION_V1_APPROVAL_PATH,
                    RENDER_DATA_SECRET_BINDING_V1_APPROVAL_PATH,
                    RENDER_DATA_SECRET_BINDING_V2_APPROVAL_PATH,
                    RENDER_DATA_SECRET_BINDING_CORRECTION_V1_APPROVAL_PATH,
                    RENDER_DEPLOYMENT_V1_APPROVAL_PATH,
                    RENDER_DEPLOYMENT_V2_APPROVAL_PATH,
                    RENDER_RUNTIME_CONFIG_REPAIR_V1_APPROVAL_PATH,
                }
                | ({RENDER_DEPLOYMENT_V3_APPROVAL_PATH} if RENDER_DEPLOYMENT_V3_APPROVAL_PATH.exists() else set())
                | ({RENDER_DEPLOYMENT_V4_APPROVAL_PATH} if RENDER_DEPLOYMENT_V4_APPROVAL_PATH.exists() else set())
                | ({RENDER_DEPLOYMENT_V5_APPROVAL_PATH} if RENDER_DEPLOYMENT_V5_APPROVAL_PATH.exists() else set())
                | ({RENDER_DEPLOYMENT_V7_APPROVAL_PATH} if RENDER_DEPLOYMENT_V7_APPROVAL_PATH.exists() else set())
                | ({RENDER_DEPLOYMENT_V8_APPROVAL_PATH} if RENDER_DEPLOYMENT_V8_APPROVAL_PATH.exists() else set())
                | ({RENDER_DEPLOYMENT_V10_APPROVAL_PATH} if RENDER_DEPLOYMENT_V10_APPROVAL_PATH.exists() else set())
                | ({IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_V1_APPROVAL_PATH} if IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_V1_APPROVAL_PATH.exists() else set())
                | ({IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_CREDENTIAL_REPAIR_V1_APPROVAL_PATH} if IMPLEMENTATION_HANDOFF_PROVIDER_ADAPTER_AUTH_CREDENTIAL_REPAIR_V1_APPROVAL_PATH.exists() else set())
                | ({RENDER_RUNTIME_CONFIG_REPAIR_V4_APPROVAL_PATH} if RENDER_RUNTIME_CONFIG_REPAIR_V4_APPROVAL_PATH.exists() else set())
                | ({RENDER_RUNTIME_CONFIG_REPAIR_V6_APPROVAL_PATH} if RENDER_RUNTIME_CONFIG_REPAIR_V6_APPROVAL_PATH.exists() else set())
                | ({RENDER_RUNTIME_CONFIG_FINAL_VERIFICATION_V1_APPROVAL_PATH} if RENDER_RUNTIME_CONFIG_FINAL_VERIFICATION_V1_APPROVAL_PATH.exists() else set())
                | ({RECOVERY_PREDICATE_DIAGNOSTIC_V4_APPROVAL_PATH} if RECOVERY_PREDICATE_DIAGNOSTIC_V4_APPROVAL_PATH.exists() else set())
                | ({REPAIRED_RECOVERY_LIFECYCLE_V1_APPROVAL_PATH} if REPAIRED_RECOVERY_LIFECYCLE_V1_APPROVAL_PATH.exists() else set())
                | ({REPAIRED_RECOVERY_LIFECYCLE_V2_APPROVAL_PATH} if REPAIRED_RECOVERY_LIFECYCLE_V2_APPROVAL_PATH.exists() else set())
                | ({REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_PROVISION_V1_APPROVAL_PATH} if REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_PROVISION_V1_APPROVAL_PATH.exists() else set())
                | ({REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_BINDING_CONTINUATION_V1_APPROVAL_PATH} if REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_BINDING_CONTINUATION_V1_APPROVAL_PATH.exists() else set())
                | ({REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_RETIREMENT_V1_APPROVAL_PATH} if REPAIRED_RECOVERY_LIFECYCLE_CREDENTIAL_RETIREMENT_V1_APPROVAL_PATH.exists() else set())
                | ({SYNTHETIC_TOKEN_VALIDATION_V1_APPROVAL_PATH} if SYNTHETIC_TOKEN_VALIDATION_V1_APPROVAL_PATH.exists() else set())
                | ({SYNTHETIC_TOKEN_VALIDATION_V2_APPROVAL_PATH} if SYNTHETIC_TOKEN_VALIDATION_V2_APPROVAL_PATH.exists() else set())
                | ({SYNTHETIC_TOKEN_VALIDATION_V3_APPROVAL_PATH} if SYNTHETIC_TOKEN_VALIDATION_V3_APPROVAL_PATH.exists() else set())
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
