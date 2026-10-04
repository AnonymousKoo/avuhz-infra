from __future__ import annotations

import base64
import importlib.util
import json
import unittest
from unittest.mock import patch
from pathlib import Path

from avuhz_engineering import development_auth_token_lifecycle as lifecycle
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
    "development_provider_adapter_positive_auth_v1",
    ROOT / "scripts/development_provider_adapter_positive_auth_v1.py",
)
assert SPEC and SPEC.loader
executor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(executor)


def token_with_es256_header() -> str:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "ES256", "typ": "JWT"}, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b"{}").decode().rstrip("=")
    return f"{header}.{payload}.signature-material-long-enough-for-tests"


class FakeVerifier:
    def __init__(self, claims):
        self.claims = claims

    def verify(self, _token):
        return self.claims


class ProviderAdapterJwtValidationTests(unittest.TestCase):
    def claims(self):
        entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
        # The actual subject is never stored in production evidence. This fixed
        # unit-test UUID hashes to the live policy digest only when patched below.
        return {
            "iss": DEVELOPMENT_AUTH_ISSUER,
            "aud": DEVELOPMENT_SERVICE_AUDIENCE,
            "sub": "33333333-3333-4333-8333-333333333333",
            "avuhz_tenant_id": entry.tenant_id,
            "role": "authenticated",
            "aal": "aal1",
            "is_anonymous": False,
            "iat": 1799996000,
            "exp": 1799999600,
            "session_id": "22222222-2222-4222-8222-222222222222",
        }

    def test_provider_adapter_validation_maps_only_handoff_capability(self):
        entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
        claims = self.claims()
        original = entry.subject_digest
        digest = "sha256:" + __import__("hashlib").sha256(
            claims["sub"].encode()
        ).hexdigest()
        patched = type(entry)(
            subject_digest=digest,
            principal_reference=entry.principal_reference,
            tenant_id=entry.tenant_id,
            caller_type=entry.caller_type,
            capabilities=entry.capabilities,
        )
        with patch.object(
            lifecycle,
            "DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY",
            patched,
        ), patch.object(
            lifecycle,
            "DEVELOPMENT_IDENTITY_ALLOWLIST",
            (
                lifecycle.DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST[0],
                patched,
            ),
        ):
            result = lifecycle.validate_development_provider_adapter_access_jwt(
                token_with_es256_header(),
                verifier=FakeVerifier(claims),
            )
        self.assertNotEqual(original, digest)
        self.assertEqual(result.caller_type, "PROVIDER_ADAPTER")
        self.assertEqual(result.capabilities, ("implementation_handoff:accept",))
        self.assertEqual(result.authority_roles, ())
        self.assertEqual(result.tenant_id, entry.tenant_id)

    def test_provider_adapter_validation_rejects_wrong_tenant(self):
        claims = self.claims()
        claims["avuhz_tenant_id"] = "44444444-4444-4444-8444-444444444444"
        with self.assertRaises(SafeLifecycleStop) as ctx:
            lifecycle.validate_development_provider_adapter_access_jwt(
                token_with_es256_header(),
                verifier=FakeVerifier(claims),
            )
        self.assertEqual(ctx.exception.code, "ACCESS_JWT_VALIDATION_FAILED")


class PositiveAuthExecutorTests(unittest.TestCase):
    def test_exact_order_and_cleanup(self):
        events = []
        entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
        credential = RecoveryVerificationCredential(
            "recovery-material",
            user_id="33333333-3333-4333-8333-333333333333",
        )
        session = IssuedSession(
            access_token="access-material-long-enough",
            refresh_token="refresh-material-long-enough",
            expires_in=3600,
            expires_at=1800000000,
            token_type="bearer",
            user_id="33333333-3333-4333-8333-333333333333",
        )

        def generate(**kwargs):
            events.append("generate")
            self.assertEqual(kwargs["expected_subject_digest"], entry.subject_digest)
            return credential

        def verify(**_kwargs):
            events.append("verify")
            return session

        def validate(_token):
            events.append("validate")
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

        def live_probe(_token):
            events.append("live-probe")

        def logout_global(**_kwargs):
            events.append("logout-global")

        result = executor.execute_positive_auth(
            admin_secret="not-returned-admin-material",
            publishable_key="not-returned-publishable-material",
            generate=generate,
            verify=verify,
            validate_jwt=validate,
            live_probe=live_probe,
            logout_global=logout_global,
        )
        self.assertEqual(
            events,
            ["generate", "verify", "validate", "live-probe", "logout-global"],
        )
        self.assertEqual(
            result["classification"],
            "PROVIDER_ADAPTER_POSITIVE_AUTH_LIVE_VERIFIED_PENDING_CLEANUP",
        )
        self.assertEqual(result["live_runtime_probe_http"], 400)
        self.assertFalse(result["implementation_handoff_attempted"])
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)
        self.assertEqual(session.user_id, "")

    def test_failure_after_session_issuance_attempts_global_logout_once(self):
        events = []
        credential = RecoveryVerificationCredential(
            "recovery-material",
            user_id="33333333-3333-4333-8333-333333333333",
        )
        session = IssuedSession(
            access_token="access-material-long-enough",
            refresh_token="refresh-material-long-enough",
            expires_in=3600,
            expires_at=1800000000,
            token_type="bearer",
            user_id="33333333-3333-4333-8333-333333333333",
        )

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
        self.assertEqual(session.user_id, "")

    def test_failure_and_logout_failure_is_explicit_cleanup_unverified_stop(self):
        credential = RecoveryVerificationCredential(
            "recovery-material",
            user_id="33333333-3333-4333-8333-333333333333",
        )
        session = IssuedSession(
            access_token="access-material-long-enough",
            refresh_token="refresh-material-long-enough",
            expires_in=3600,
            expires_at=1800000000,
            token_type="bearer",
            user_id="33333333-3333-4333-8333-333333333333",
        )

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
        self.assertEqual(session.user_id, "")


if __name__ == "__main__":
    unittest.main()
