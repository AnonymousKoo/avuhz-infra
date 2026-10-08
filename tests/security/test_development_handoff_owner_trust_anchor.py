"""Offline DEVELOPMENT public-key pin candidate: exact key, exact scope, no authority."""
from __future__ import annotations

import base64
import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src")]

from avuhz_engineering.development_handoff_owner_trust_anchor import (
    DevelopmentTrustAnchorStop,
    ENV_FINGERPRINT, ENV_PUBLIC_KEY,
    OWNER_ED25519_FINGERPRINT, OWNER_ED25519_PUBLIC_KEY_BASE64,
    prepare_development_owner_trust_anchor_candidate,
)
from avuhz_engineering.development_handoff_approval_gate import EXPECTED_OWNER
from avuhz_engineering.development_source_bound_handoff_lifecycle import REPOSITORY
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF,
)


class DevelopmentPublicKeyTrustAnchorPreparationTests(unittest.TestCase):
    def setUp(self):
        self.env = {
            ENV_PUBLIC_KEY: OWNER_ED25519_PUBLIC_KEY_BASE64,
            ENV_FINGERPRINT: OWNER_ED25519_FINGERPRINT,
        }
        self.scope = {
            "observed_repository": REPOSITORY,
            "observed_environment": "development",
            "observed_owner_identity": EXPECTED_OWNER,
            "observed_auth_project_ref": DEVELOPMENT_AUTH_PROJECT_REF,
            "observed_data_project_ref": DEVELOPMENT_DATA_PROJECT_REF,
        }

    def check(self, *, env=None, **changed_scope):
        return prepare_development_owner_trust_anchor_candidate(
            environment_values=self.env if env is None else env,
            **{**self.scope, **changed_scope},
        )

    def test_exact_owner_supplied_raw_public_key_and_sha256_are_consistent(self):
        raw = base64.b64decode(OWNER_ED25519_PUBLIC_KEY_BASE64, validate=True)
        self.assertEqual(len(raw), 32)
        self.assertEqual(
            "sha256:" + hashlib.sha256(raw).hexdigest(), OWNER_ED25519_FINGERPRINT
        )
        result = self.check()
        self.assertEqual(result.public_key, raw)
        self.assertEqual(result.public_key_fingerprint, OWNER_ED25519_FINGERPRINT)
        self.assertTrue(result.source_pinned_public_key_matched)
        self.assertTrue(result.supplied_environment_values_matched)

    def test_proposed_pin_grants_no_owner_identity_or_provider_authority(self):
        result = self.check()
        self.assertFalse(result.actual_github_environment_setting_verified)
        self.assertFalse(result.independent_owner_identity_verified)
        self.assertFalse(result.owner_key_enrolled_in_trusted_runner)
        self.assertFalse(result.signed_stage_approvals_verified)
        self.assertFalse(result.credential_resolution_authorized)
        self.assertFalse(result.live_command_authorized)

    def test_missing_extra_and_wrong_type_values_fail_closed(self):
        for env in (
            {},
            {ENV_PUBLIC_KEY: OWNER_ED25519_PUBLIC_KEY_BASE64},
            {**self.env, "ANOTHER": "untrusted"},
            {**self.env, ENV_FINGERPRINT: None},
            {**self.env, ENV_PUBLIC_KEY: b"not-a-string"},
        ):
            with self.subTest(env=repr(env)), self.assertRaisesRegex(
                DevelopmentTrustAnchorStop, "HANDOFF_OWNER_ANCHOR_VALUES_INVALID"
            ):
                self.check(env=env)

    def test_wrong_fingerprint_key_and_whitespace_fail(self):
        raw = base64.b64decode(OWNER_ED25519_PUBLIC_KEY_BASE64)
        changed_key = base64.b64encode(bytes([raw[0] ^ 1]) + raw[1:]).decode()
        for env in (
            {**self.env, ENV_PUBLIC_KEY: changed_key},
            {**self.env, ENV_PUBLIC_KEY: OWNER_ED25519_PUBLIC_KEY_BASE64 + " "},
            {**self.env, ENV_FINGERPRINT: "sha256:" + "0" * 64},
            {**self.env, ENV_FINGERPRINT: OWNER_ED25519_FINGERPRINT.upper()},
        ):
            with self.subTest(env=repr(env)), self.assertRaisesRegex(
                DevelopmentTrustAnchorStop, "HANDOFF_OWNER_ANCHOR_VALUE_MISMATCH"
            ):
                self.check(env=env)

    def test_wrong_github_repository_owner_and_environment_denied(self):
        for change in (
            {"observed_repository": "AnonymousKoo/other-repo"},
            {"observed_owner_identity": "github:untrusted"},
            {"observed_environment": "production"},
            {"observed_environment": "staging"},
            {"observed_environment": ""},
        ):
            with self.subTest(scope=change), self.assertRaisesRegex(
                DevelopmentTrustAnchorStop, "HANDOFF_OWNER_ANCHOR_SCOPE_INVALID"
            ):
                self.check(**change)

    def test_auth_and_data_projects_cannot_be_conflated(self):
        for change in (
            {"observed_auth_project_ref": DEVELOPMENT_DATA_PROJECT_REF},
            {"observed_data_project_ref": DEVELOPMENT_AUTH_PROJECT_REF},
            {"observed_auth_project_ref": DEVELOPMENT_DATA_PROJECT_REF,
             "observed_data_project_ref": DEVELOPMENT_AUTH_PROJECT_REF},
        ):
            with self.subTest(scope=change), self.assertRaisesRegex(
                DevelopmentTrustAnchorStop, "HANDOFF_OWNER_ANCHOR_SCOPE_INVALID"
            ):
                self.check(**change)

    def test_never_confuse_local_fabricated_matching_values_with_enrollment(self):
        # Caller-supplied matching strings cannot prove the actual GH env or
        # independent owner approval. This remains a proposal after PASS.
        a = self.check(env=dict(self.env))
        self.assertIn("OFFLINE_ONLY", a.classification)
        self.assertFalse(a.actual_github_environment_setting_verified)
        self.assertFalse(a.owner_key_enrolled_in_trusted_runner)
        self.assertFalse(a.live_command_authorized)


if __name__ == "__main__":
    unittest.main()
