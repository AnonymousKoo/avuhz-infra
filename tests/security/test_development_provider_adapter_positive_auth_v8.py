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
from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_SERVICE_AUDIENCE,
)
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY,
)

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "development_provider_adapter_positive_auth_v8",
    ROOT / "scripts/development_provider_adapter_positive_auth_v8.py",
)
assert SPEC and SPEC.loader
executor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(executor)


class PositiveAuthV8SecurityTests(unittest.TestCase):
    def _credential(self) -> RecoveryVerificationCredential:
        return RecoveryVerificationCredential(
            "fixture-recovery-material",
            user_id="33333333-3333-4333-8333-333333333333",
        )

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

    def test_success_preserves_lifecycle_and_requires_readback_retirement(self) -> None:
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
        self.assertEqual(
            events, ["generate", "verify", "validate", "live-probe", "logout-global"]
        )
        self.assertEqual(
            result["classification"],
            "PROVIDER_ADAPTER_POSITIVE_AUTH_LIVE_VERIFIED_PENDING_CLEANUP",
        )
        self.assertTrue(result["step6_readback_required"])
        self.assertTrue(result["credential_retirement_required"])
        self.assertTrue(result["github_binding_retirement_required"])
        self.assertFalse(result["implementation_handoff_attempted"])
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)
        self.assertEqual(session.user_id, "")

    def test_safe_failure_uses_shared_stage_without_secret_or_provider_payload(self) -> None:
        admin_fixture = "sb_" + "secret_" + "fixture_not_real_value_123456"
        publishable_fixture = (
            "sb_" + "publishable_" + "fixture_not_real_value_123456"
        )
        env = {
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_NUMBER": "1",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": "AnonymousKoo/avuhz-infra",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "AVUHZ_ENVIRONMENT": "development",
            "AVUHZ_CONFIRMATION": executor.CONFIRMATION,
            executor.ADMIN_ENV: admin_fixture,
            executor.PUBLISHABLE_ENV: publishable_fixture,
        }
        output = io.StringIO()
        with patch.object(
            executor, "_load_and_authorize", return_value=({}, {})
        ), patch.object(
            executor,
            "execute_positive_auth",
            side_effect=SafeLifecycleStop("LIVE_AUTH_PROBE_FAILED"),
        ), contextlib.redirect_stdout(output):
            rc = executor.main(env)
        self.assertEqual(rc, 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["safe_error_code"], "LIVE_AUTH_PROBE_FAILED")
        self.assertEqual(payload["failure_stage"], "live_runtime_probe")
        self.assertTrue(payload["provider_mutation_attempted"])
        self.assertTrue(payload["session_state_readback_required"])
        self.assertTrue(payload["credential_retirement_required"])
        self.assertTrue(payload["github_binding_retirement_required"])
        self.assertFalse(payload["provider_payload_retained"])
        serialized = json.dumps(payload, sort_keys=True)
        self.assertNotIn(admin_fixture, serialized)
        self.assertNotIn(publishable_fixture, serialized)
        self.assertNotIn("Traceback", serialized)

    def test_unknown_failure_collapses_to_bounded_authority_code(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = executor._safe_failure(
                "raw provider error token=should-never-escape",
                provider_mutation_attempted=True,
            )
        self.assertEqual(rc, 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["safe_error_code"], "AUTHORITY_INVALID")
        self.assertEqual(payload["failure_stage"], "authorization_preflight")
        self.assertNotIn("raw provider error", json.dumps(payload))

    def test_authority_failure_occurs_before_secret_lookup(self) -> None:
        class TrackingEnv(dict):
            def __init__(self):
                super().__init__(
                    {
                        "GITHUB_REF": "refs/heads/main",
                        "GITHUB_RUN_NUMBER": "1",
                        "GITHUB_RUN_ATTEMPT": "1",
                        "GITHUB_REPOSITORY": "AnonymousKoo/avuhz-infra",
                        "GITHUB_EVENT_NAME": "workflow_dispatch",
                        "AVUHZ_ENVIRONMENT": "development",
                        "AVUHZ_CONFIRMATION": executor.CONFIRMATION,
                    }
                )
                self.reads: list[str] = []

            def get(self, key, default=None):
                if key in {executor.ADMIN_ENV, executor.PUBLISHABLE_ENV}:
                    self.reads.append(key)
                return super().get(key, default)

        env = TrackingEnv()
        output = io.StringIO()
        with patch.object(
            executor,
            "_load_and_authorize",
            side_effect=AuthorizationPlanStop("AUTHORITY_INVALID"),
        ), contextlib.redirect_stdout(output):
            rc = executor.main(env)
        self.assertEqual(rc, 1)
        self.assertEqual(env.reads, [])
        payload = json.loads(output.getvalue())
        self.assertFalse(payload["provider_mutation_attempted"])
        self.assertFalse(payload["session_state_readback_required"])

    def test_redirects_are_rejected(self) -> None:
        handler = executor._RejectRedirects()
        self.assertIsNone(
            handler.redirect_request(
                None, None, 302, "redirect", {}, "https://example.invalid"
            )
        )

    def test_v8_uses_fresh_distinct_secret_namespace(self) -> None:
        self.assertEqual(
            executor.ADMIN_ENV,
            "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V8_EPHEMERAL",
        )
        self.assertEqual(
            executor.BOUNDARY,
            "development-implementation-handoff-provider-adapter-positive-auth-v8",
        )
        self.assertEqual(
            executor.CONFIRMATION,
            "RUN_PROVIDER_ADAPTER_POSITIVE_AUTH_V8_STEP5",
        )

    def test_request_uses_all_prior_step_evidence_digests(self) -> None:
        plan = {
            "plan_id": "plan",
            "plan_version": 7,
            "plan_digest": "sha256:" + "1" * 64,
            "environment": "DEVELOPMENT",
            "target": {
                "provider_reference": "supabase",
                "project_reference": executor.PROJECT,
                "responsibility": "AUTH",
                "issuer_reference": "issuer",
                "audience_reference": "audience",
            },
            "steps": [
                {}, {}, {}, {},
                {
                    "step_id": executor.STEP_ID,
                    "resource": {
                        "resource_reference": "resource",
                        "exact_version": "provider-adapter-positive-auth.v8",
                        "exact_digest": "sha256:" + "2" * 64,
                    },
                    "operation": "provider.auth-session.provider-adapter-recover-validate-live-probe-and-logout-global",
                    "execution_class": "PROVIDER_MUTATION",
                    "required_evidence": [
                        {
                            "evidence_type": "step4",
                            "source_step_id": "step4",
                            "binding_state": "DERIVED_FROM_SOURCE_STEP",
                            "exact_digest": None,
                        }
                    ],
                },
            ],
        }
        progress = {
            "step_states": [
                {"step_id": "step1", "evidence": [{"evidence_type": "a", "evidence_digest": "sha256:" + "a" * 64}]},
                {"step_id": "step2", "evidence": [{"evidence_type": "b", "evidence_digest": "sha256:" + "b" * 64}]},
                {"step_id": "step3", "evidence": [{"evidence_type": "c", "evidence_digest": "sha256:" + "c" * 64}]},
                {"step_id": "step4", "evidence": [{"evidence_type": "step4", "evidence_digest": "sha256:" + "d" * 64}]},
            ]
        }
        request = executor._request_for(plan, progress)
        self.assertEqual(
            request["prior_evidence_digests"],
            [
                "sha256:" + "a" * 64,
                "sha256:" + "b" * 64,
                "sha256:" + "c" * 64,
                "sha256:" + "d" * 64,
            ],
        )


if __name__ == "__main__":
    unittest.main()
