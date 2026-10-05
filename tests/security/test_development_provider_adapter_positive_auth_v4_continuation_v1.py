from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from avuhz_engineering.development_auth_token_lifecycle import (
    IssuedSession,
    JwtValidationResult,
    RecoveryVerificationCredential,
    SafeLifecycleStop,
)
from avuhz_service.development import DEVELOPMENT_AUTH_ISSUER, DEVELOPMENT_SERVICE_AUDIENCE
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY,
)

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "development_provider_adapter_positive_auth_v4_continuation_v1",
    ROOT / "scripts/development_provider_adapter_positive_auth_v4_continuation_v1.py",
)
assert SPEC and SPEC.loader
executor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(executor)


class PositiveAuthV4ContinuationExecutorTests(unittest.TestCase):
    def _credential(self) -> RecoveryVerificationCredential:
        return RecoveryVerificationCredential(
            "recovery-material",
            user_id="33333333-3333-4333-8333-333333333333",
        )

    def _session(self) -> IssuedSession:
        return IssuedSession(
            access_token="access-material-long-enough",
            refresh_token="refresh-material-long-enough",
            expires_in=3600,
            expires_at=1800000000,
            token_type="bearer",
            user_id="33333333-3333-4333-8333-333333333333",
        )

    def _validation(self) -> JwtValidationResult:
        entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
        return JwtValidationResult(
            algorithm="ES256",
            issuer=DEVELOPMENT_AUTH_ISSUER,
            audience=DEVELOPMENT_SERVICE_AUDIENCE,
            subject_digest=entry.subject_digest,
            tenant_id=entry.tenant_id,
            role="authenticated",
            aal="aal1",
            is_anonymous=False,
            caller_type="PROVIDER_ADAPTER",
            capabilities=("implementation_handoff:accept",),
            authority_roles=(),
        )

    def test_success_preserves_exact_order_and_marks_readback_retirement_required(self):
        events: list[str] = []
        credential = self._credential()
        session = self._session()

        def generate(**_kwargs):
            events.append("generate")
            return credential

        def verify(**_kwargs):
            events.append("verify")
            return session

        def validate(_token):
            events.append("validate")
            return self._validation()

        def live_probe(_token):
            events.append("live-probe")

        def logout_global(**_kwargs):
            events.append("logout-global")

        result = executor.execute_positive_auth(
            admin_secret="admin-material",
            publishable_key="publishable-material",
            generate=generate,
            verify=verify,
            validate_jwt=validate,
            live_probe=live_probe,
            logout_global=logout_global,
        )
        self.assertEqual(events, ["generate", "verify", "validate", "live-probe", "logout-global"])
        self.assertEqual(
            result["classification"],
            "PROVIDER_ADAPTER_POSITIVE_AUTH_LIVE_VERIFIED_PENDING_CLEANUP",
        )
        self.assertEqual(result["live_runtime_probe_http"], 400)
        self.assertFalse(result["implementation_handoff_attempted"])
        self.assertTrue(result["step2_readback_required"])
        self.assertFalse(result["retirement_required"])
        self.assertTrue(result["retirement_deferred_until_after_implementation_handoff"])
        self.assertTrue(result["temporary_binding_preserved_for_handoff"])
        self.assertNotIn("step6_readback_required", result)
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)
        self.assertEqual(session.user_id, "")

    def test_failure_after_session_attempts_one_logout_and_still_raises(self):
        events: list[str] = []
        credential = self._credential()
        session = self._session()

        def generate(**_kwargs):
            events.append("generate")
            return credential

        def verify(**_kwargs):
            events.append("verify")
            return session

        def fail_validate(_token):
            events.append("validate")
            raise SafeLifecycleStop("ACCESS_JWT_VALIDATION_FAILED")

        def logout_global(**_kwargs):
            events.append("logout-global")

        with self.assertRaises(SafeLifecycleStop):
            executor.execute_positive_auth(
                admin_secret="admin-material",
                publishable_key="publishable-material",
                generate=generate,
                verify=verify,
                validate_jwt=fail_validate,
                live_probe=lambda _token: events.append("live-probe"),
                logout_global=logout_global,
            )
        self.assertEqual(events, ["generate", "verify", "validate", "logout-global"])
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)

    def test_logout_failure_remains_explicit_unverified_cleanup(self):
        credential = self._credential()
        session = self._session()
        with self.assertRaises(SafeLifecycleStop) as ctx:
            executor.execute_positive_auth(
                admin_secret="admin-material",
                publishable_key="publishable-material",
                generate=lambda **_kwargs: credential,
                verify=lambda **_kwargs: session,
                validate_jwt=lambda _token: (_ for _ in ()).throw(
                    SafeLifecycleStop("ACCESS_JWT_VALIDATION_FAILED")
                ),
                live_probe=lambda _token: None,
                logout_global=lambda **_kwargs: (_ for _ in ()).throw(
                    SafeLifecycleStop("GLOBAL_SESSION_LOGOUT_REQUEST_FAILED")
                ),
            )
        self.assertEqual(ctx.exception.code, "POSITIVE_AUTH_FAILED_LOGOUT_UNVERIFIED")
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)

    def test_redirects_are_rejected(self):
        handler = executor._RejectRedirects()
        self.assertIsNone(handler.redirect_request(None, None, 302, "redirect", {}, "https://example.invalid"))


if __name__ == "__main__":
    unittest.main()
