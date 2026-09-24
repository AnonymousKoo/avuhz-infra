from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import development_auth_v32_synthetic_session_cleanup_v2 as executor  # noqa: E402
from avuhz_engineering.development_auth_token_lifecycle import (  # noqa: E402
    IssuedSession,
    RecoveryVerificationCredential,
)


class SecretTrackingEnvironment(dict[str, str]):
    def __init__(self) -> None:
        super().__init__({
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_NUMBER": "1",
            "GITHUB_RUN_ATTEMPT": "1",
            "AVUHZ_CLEANUP_CONFIRMATION": executor.CONFIRMATION,
            "AVUHZ_EXPECTED_PROJECT_REF": executor.PROJECT,
            "AVUHZ_PLAN_ID": executor.PLAN_ID,
            "AVUHZ_PLAN_DIGEST": executor.PLAN_DIGEST,
            "AVUHZ_WINDOW_START": executor.WINDOW_START,
            "AVUHZ_WINDOW_END": executor.WINDOW_END,
        })
        self.secret_reads: list[str] = []

    def get(self, key: str, default=None):
        if key in {executor.ADMIN_ENV, executor.PUBLISHABLE_ENV}:
            self.secret_reads.append(key)
        return super().get(key, default)


class CleanupV2ExecutorSecurityTests(unittest.TestCase):
    def test_local_fake_lifecycle_uses_exact_order_and_clears_material(self) -> None:
        events: list[str] = []
        credential = RecoveryVerificationCredential("non-secret-test-fixture-token-hash")
        session = IssuedSession(
            access_token="non-secret-test-access-fixture",
            refresh_token="non-secret-test-refresh-fixture",
            expires_in=60,
            expires_at=1,
            token_type="bearer",
            user_id="00000000-0000-4000-8000-000000000001",
        )

        def generate(**kwargs):
            events.append("generate")
            self.assertEqual(kwargs["project_ref"], executor.PROJECT)
            self.assertEqual(kwargs["existing_user_email"], executor.TARGET_EMAIL)
            return credential

        def verify(**kwargs):
            events.append("verify")
            self.assertIs(kwargs["credential"], credential)
            return session

        def validate(token: str):
            events.append("validate")
            self.assertEqual(token, "non-secret-test-access-fixture")

        def logout_global(**kwargs):
            events.append("logout")
            self.assertEqual(kwargs["bearer_token"], "non-secret-test-access-fixture")

        result = executor.execute_cleanup(
            admin_secret="admin-test-value",
            publishable_key="publishable-test-value",
            generate=generate,
            verify=verify,
            validate_jwt=validate,
            logout_global=logout_global,
        )
        self.assertEqual(events, ["generate", "verify", "validate", "logout"])
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)
        self.assertEqual(session.user_id, "")
        self.assertEqual(result["classification"], "SESSION_REVOCATION_REQUEST_ACCEPTED")
        self.assertTrue(result["temporary_session_issued"])
        self.assertEqual(result["temporary_session_count"], 1)
        self.assertTrue(result["jwt_validated_before_logout"])
        self.assertTrue(result["global_logout_accepted"])
        self.assertFalse(result["cleanup_verified"])
        self.assertTrue(result["step3_readback_required"])
        self.assertFalse(result["retry_authorized"])
        self.assertFalse(result["credential_material_retained"])
        serialized = json.dumps(result, sort_keys=True)
        for sensitive_fixture in (
            "non-secret-test-fixture-token-hash",
            "non-secret-test-access-fixture",
            "non-secret-test-refresh-fixture",
            executor.TARGET_EMAIL,
            "00000000-0000-4000-8000-000000000001",
        ):
            self.assertNotIn(sensitive_fixture, serialized)
        self.assertEqual(set(result), {
            "classification", "temporary_session_issued", "temporary_session_count",
            "jwt_validated_before_logout", "global_logout_attempted",
            "global_logout_accepted", "cleanup_verified", "step3_readback_required",
            "retry_authorized", "credential_material_retained", "pii_retained",
            "provider_mutation_attempted",
        })

    def test_failure_after_credential_generation_clears_material_without_retry(self) -> None:
        credential = RecoveryVerificationCredential("non-secret-test-fixture-token-hash")
        calls = 0

        def generate(**kwargs):
            nonlocal calls
            calls += 1
            return credential

        def reject(**kwargs):
            raise RuntimeError("sensitive provider body must not escape")

        with self.assertRaises(RuntimeError):
            executor.execute_cleanup(
                admin_secret="admin-test-value",
                publishable_key="publishable-test-value",
                generate=generate,
                verify=reject,
            )
        self.assertEqual(calls, 1)
        self.assertTrue(credential.is_cleared)

    def test_authority_failure_happens_before_any_secret_lookup(self) -> None:
        env = SecretTrackingEnvironment()
        output = io.StringIO()
        with patch.object(executor, "_load_and_authorize", side_effect=executor.AuthorizationPlanStop("SESSION_CLEANUP_V2_AUTHORITY_INVALID")):
            with contextlib.redirect_stdout(output):
                result = executor.main(env)
        self.assertEqual(result, 1)
        self.assertEqual(env.secret_reads, [])
        payload = json.loads(output.getvalue())
        self.assertFalse(payload["provider_mutation_attempted"])
        self.assertFalse(payload["retry_authorized"])

    def test_preflight_confirmation_failure_happens_before_secret_lookup(self) -> None:
        env = SecretTrackingEnvironment()
        env["AVUHZ_CLEANUP_CONFIRMATION"] = "wrong"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = executor.main(env)
        self.assertEqual(result, 1)
        self.assertEqual(env.secret_reads, [])
        self.assertNotIn("wrong", output.getvalue())

    def test_v2_sources_contain_only_secret_references_and_no_v1_fallback(self) -> None:
        executor_source = (ROOT / "scripts/development_auth_v32_synthetic_session_cleanup_v2.py").read_text()
        workflow = (ROOT / ".github/workflows/development-auth-v32-synthetic-session-cleanup-v2.yml").read_text()
        self.assertIn(executor.ADMIN_ENV, executor_source + workflow)
        self.assertNotIn("AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V1_EPHEMERAL", executor_source + workflow)
        self.assertNotRegex(executor_source + workflow, r"sb_secret_[A-Za-z0-9._-]{8,}")
        self.assertNotIn("service_role", executor_source.lower())
        self.assertNotIn("auth.sessions", executor_source)
        self.assertNotIn("auth.refresh_tokens", executor_source)
        self.assertNotIn("cleanup-v1", executor_source.lower())


if __name__ == "__main__":
    unittest.main()
