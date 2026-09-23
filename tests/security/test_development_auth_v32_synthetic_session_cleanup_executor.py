from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path

from avuhz_engineering.development_auth_token_lifecycle import (
    IssuedSession,
    RecoveryVerificationCredential,
    SafeLifecycleStop,
)
from scripts import development_auth_v32_synthetic_session_cleanup_v1 as executor


ROOT = Path(__file__).resolve().parents[2]


def _material(label: str, length: int = 48) -> str:
    return (f"runtime-only-{label}-" + "x" * length)[:length]


class GuardedEnvironment(dict[str, str]):
    def __init__(self) -> None:
        super().__init__({
            "AVUHZ_CLEANUP_CONFIRMATION": executor.CONFIRMATION,
            "AVUHZ_EXPECTED_PROJECT_REF": executor.PROJECT,
        })
        self.secret_read_attempted = False

    def get(self, key: str, default=None):
        if key in {executor.ADMIN_ENV, executor.PUBLISHABLE_ENV}:
            self.secret_read_attempted = True
            raise AssertionError("secret must not be read before authority")
        return super().get(key, default)


class DevelopmentAuthV32SyntheticSessionCleanupExecutorTests(unittest.TestCase):
    def new_credential(self) -> RecoveryVerificationCredential:
        return RecoveryVerificationCredential(
            _material("recovery"),
            user_id="13b7706e-6d90-4696-9e2c-abd377372121",
        )

    def new_session(self) -> IssuedSession:
        return IssuedSession(
            access_token=_material("access", 64),
            refresh_token=_material("refresh", 64),
            expires_in=300,
            expires_at=1800000000,
            token_type="bearer",
            user_id="13b7706e-6d90-4696-9e2c-abd377372121",
        )

    def test_exact_order_one_session_and_global_logout_then_clear(self) -> None:
        credential = self.new_credential()
        session = self.new_session()
        access = session._access_text()
        events: list[str] = []

        def generate(**kwargs):
            events.append("generate")
            self.assertIsNone(kwargs["expected_user_id"])
            self.assertEqual(kwargs["existing_user_email"], executor.TARGET_EMAIL)
            return credential

        def verify(**kwargs):
            events.append("verify")
            self.assertIs(kwargs["credential"], credential)
            self.assertIsNone(kwargs["expected_user_id"])
            return session

        def validate(token: str):
            events.append("validate")
            self.assertEqual(token, access)

        def logout(**kwargs):
            events.append("logout-global")
            self.assertEqual(kwargs["project_ref"], executor.PROJECT)
            self.assertEqual(kwargs["bearer_token"], access)

        result = executor.execute_cleanup(
            admin_secret=_material("admin"),
            publishable_key=_material("publishable"),
            generate=generate,
            verify=verify,
            validate_jwt=validate,
            logout_global=logout,
        )
        self.assertEqual(events, ["generate", "verify", "validate", "logout-global"])
        self.assertEqual(result["classification"], "SESSION_REVOCATION_REQUEST_ACCEPTED")
        self.assertEqual(result["temporary_session_count"], 1)
        self.assertFalse(result["cleanup_verified"])
        self.assertTrue(result["step3_readback_required"])
        self.assertFalse(result["retry_authorized"])
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)

    def test_jwt_failure_prevents_logout_and_clears_every_buffer(self) -> None:
        credential = self.new_credential()
        session = self.new_session()
        calls = {"generate": 0, "verify": 0, "logout": 0}

        def generate(**_kwargs):
            calls["generate"] += 1
            return credential

        def verify(**_kwargs):
            calls["verify"] += 1
            return session

        def reject(_token: str):
            raise SafeLifecycleStop("ACCESS_JWT_VALIDATION_FAILED")

        def logout(**_kwargs):
            calls["logout"] += 1

        with self.assertRaisesRegex(SafeLifecycleStop, "ACCESS_JWT_VALIDATION_FAILED"):
            executor.execute_cleanup(
                admin_secret=_material("admin"),
                publishable_key=_material("publishable"),
                generate=generate,
                verify=verify,
                validate_jwt=reject,
                logout_global=logout,
            )
        self.assertEqual(calls, {"generate": 1, "verify": 1, "logout": 0})
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)

    def test_logout_failure_is_not_retried_and_output_is_redacted(self) -> None:
        credential = self.new_credential()
        session = self.new_session()
        materials = (
            credential._text(),
            session._access_text(),
        )
        calls = 0

        def logout(**_kwargs):
            nonlocal calls
            calls += 1
            raise SafeLifecycleStop("GLOBAL_SESSION_LOGOUT_PROVIDER_REJECTED")

        with self.assertRaises(SafeLifecycleStop) as raised:
            executor.execute_cleanup(
                admin_secret=_material("admin"),
                publishable_key=_material("publishable"),
                generate=lambda **_kwargs: credential,
                verify=lambda **_kwargs: session,
                validate_jwt=lambda _token: None,
                logout_global=logout,
            )
        self.assertEqual(calls, 1)
        rendered = str(raised.exception) + repr(raised.exception)
        self.assertNotIn(executor.TARGET_EMAIL, rendered)
        for material in materials:
            self.assertNotIn(material, rendered)
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)

    def test_confirmation_mismatch_fails_before_secret_resolution(self) -> None:
        environment = GuardedEnvironment()
        environment["AVUHZ_CLEANUP_CONFIRMATION"] = "INVALID_CONFIRMATION"
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = executor.main(environment)
        self.assertEqual(result, 1)
        self.assertFalse(environment.secret_read_attempted)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["classification"], "SESSION_STATE_UNVERIFIED")
        self.assertEqual(payload["safe_error_code"], "SESSION_CLEANUP_CONFIRMATION_MISMATCH")
        self.assertFalse(payload["cleanup_verified"])
        self.assertFalse(payload["retry_authorized"])

    def test_executor_contains_no_sql_readback_or_direct_delete_path(self) -> None:
        source = (
            ROOT / "scripts/development_auth_v32_synthetic_session_cleanup_v1.py"
        ).read_text(encoding="utf-8")
        for prohibited in (
            "/database/query", "auth.sessions", "auth.refresh_tokens",
            "delete from", "request_local_session_logout", "run_recovery_session_lifecycle",
        ):
            self.assertNotIn(prohibited, source.lower())
        self.assertIn("request_global_session_logout", source)
        self.assertIn("validate_development_synthetic_access_jwt", source)


if __name__ == "__main__":
    unittest.main()
