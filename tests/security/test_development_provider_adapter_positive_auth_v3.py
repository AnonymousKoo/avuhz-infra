from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from avuhz_engineering.authorization_plan import AuthorizationPlanStop
from avuhz_engineering.development_auth_token_lifecycle import (
    IssuedSession,
    JwtValidationResult,
    RecoveryVerificationCredential,
    SafeLifecycleStop,
)
from avuhz_service.development import DEVELOPMENT_AUTH_ISSUER, DEVELOPMENT_SERVICE_AUDIENCE
from avuhz_service.development_supabase_identity import DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "development_provider_adapter_positive_auth_v3",
    ROOT / "scripts/development_provider_adapter_positive_auth_v3.py",
)
assert SPEC and SPEC.loader
executor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(executor)


class PositiveAuthV3SecurityTests(unittest.TestCase):
    def _credential(self) -> RecoveryVerificationCredential:
        return RecoveryVerificationCredential("fixture-recovery-material", user_id="33333333-3333-4333-8333-333333333333")

    def _session(self) -> IssuedSession:
        return IssuedSession(
            access_token="fixture-access-material-long-enough",
            refresh_token="fixture-refresh-material-long-enough",
            expires_in=3600,
            expires_at=1800000000,
            token_type="bearer",
            user_id="33333333-3333-4333-8333-333333333333",
        )

    def _validation(self) -> JwtValidationResult:
        entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
        return JwtValidationResult(
            algorithm="ES256", issuer=DEVELOPMENT_AUTH_ISSUER, audience=DEVELOPMENT_SERVICE_AUDIENCE,
            subject_digest=entry.subject_digest, tenant_id=entry.tenant_id, role="authenticated",
            aal="aal1", is_anonymous=False, caller_type="PROVIDER_ADAPTER",
            capabilities=("implementation_handoff:accept",), authority_roles=(),
        )

    def test_success_order_and_material_clearing(self) -> None:
        events: list[str] = []
        credential, session = self._credential(), self._session()
        result = executor.execute_positive_auth(
            admin_secret="fixture-admin",
            publishable_key="fixture-publishable",
            generate=lambda **_: (events.append("generate") or credential),
            verify=lambda **_: (events.append("verify") or session),
            validate_jwt=lambda _token: (events.append("validate") or self._validation()),
            live_probe=lambda _token: events.append("live-probe"),
            logout_global=lambda **_: events.append("logout-global"),
        )
        self.assertEqual(events, ["generate", "verify", "validate", "live-probe", "logout-global"])
        self.assertEqual(result["classification"], "PROVIDER_ADAPTER_POSITIVE_AUTH_LIVE_VERIFIED_PENDING_CLEANUP")
        self.assertFalse(result["implementation_handoff_attempted"])
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)
        self.assertEqual(session.user_id, "")

    def test_failure_retains_fixed_safe_code_only(self) -> None:
        admin_fixture = "sb_" + "secret_" + "fixture_not_real_value_123456"
        publishable_fixture = "sb_" + "publishable_" + "fixture_not_real_value_123456"
        env = {
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ATTEMPT": "1",
            "AVUHZ_CONFIRMATION": executor.CONFIRMATION,
            executor.ADMIN_ENV: admin_fixture,
            executor.PUBLISHABLE_ENV: publishable_fixture,
        }
        output = io.StringIO()
        with patch.object(executor, "_load_and_authorize", return_value=({}, {})), patch.object(
            executor, "execute_positive_auth", side_effect=SafeLifecycleStop("LIVE_AUTH_PROBE_FAILED")
        ), contextlib.redirect_stdout(output):
            rc = executor.main(env)
        self.assertEqual(rc, 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["safe_error_code"], "LIVE_AUTH_PROBE_FAILED")
        self.assertTrue(payload["provider_mutation_attempted"])
        serialized = json.dumps(payload, sort_keys=True)
        self.assertNotIn(env[executor.ADMIN_ENV], serialized)
        self.assertNotIn(env[executor.PUBLISHABLE_ENV], serialized)
        self.assertNotIn("Traceback", serialized)

    def test_authority_failure_occurs_before_secret_lookup(self) -> None:
        class TrackingEnv(dict):
            reads: list[str]
            def __init__(self):
                super().__init__({"GITHUB_REF":"refs/heads/main","GITHUB_RUN_ATTEMPT":"1","AVUHZ_CONFIRMATION":executor.CONFIRMATION})
                self.reads=[]
            def get(self, key, default=None):
                if key in {executor.ADMIN_ENV, executor.PUBLISHABLE_ENV}: self.reads.append(key)
                return super().get(key, default)
        env=TrackingEnv(); output=io.StringIO()
        with patch.object(executor, "_load_and_authorize", side_effect=AuthorizationPlanStop("AUTHORITY_INVALID")), contextlib.redirect_stdout(output):
            rc=executor.main(env)
        self.assertEqual(rc,1)
        self.assertEqual(env.reads,[])
        self.assertFalse(json.loads(output.getvalue())["provider_mutation_attempted"])

    def test_boundary_uses_distinct_v3_secret_names(self) -> None:
        self.assertEqual(executor.ADMIN_ENV, "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V3_EPHEMERAL")
        self.assertIn("positive-auth-v3", executor.BOUNDARY)
        self.assertNotIn("positive_auth_v1_ephemeral", executor.ADMIN_ENV.lower())


if __name__ == "__main__":
    unittest.main()
