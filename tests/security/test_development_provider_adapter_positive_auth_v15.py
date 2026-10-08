"""Offline safety and cleanup tests for the gated DEVELOPMENT v15 executor."""
from __future__ import annotations

import contextlib
import io
import json
import unittest
from unittest.mock import patch

from avuhz_engineering.authorization_plan import AuthorizationPlanStop
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
from scripts import development_provider_adapter_positive_auth_v15 as candidate


def good_invocation() -> dict[str, str]:
    return {
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_NUMBER": "1",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REPOSITORY": "AnonymousKoo/avuhz-infra",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "AVUHZ_ENVIRONMENT": "development",
        "AVUHZ_CONFIRMATION": candidate.CONFIRMATION,
    }


class PositiveAuthV15CandidateTests(unittest.TestCase):
    def test_invocation_is_exact_and_first_run_only(self):
        candidate._check_invocation(good_invocation())
        for field in good_invocation():
            invalid = good_invocation()
            invalid[field] = "unexpected"
            with self.subTest(field=field), self.assertRaises(AuthorizationPlanStop):
                candidate._check_invocation(invalid)

    def test_missing_future_plan_fails_closed_before_any_secret_lookup(self):
        class TrackingEnvironment(dict):
            def __init__(self):
                super().__init__(good_invocation())
                self.secret_reads = []

            def get(self, field, default=None):
                if field in (candidate.ADMIN_ENV, candidate.PUBLISHABLE_ENV):
                    self.secret_reads.append(field)
                return super().get(field, default)

        env = TrackingEnvironment()
        output = io.StringIO()
        with patch.object(
            candidate, "_load_and_authorize",
            side_effect=AuthorizationPlanStop("PLAN_NOT_READY"),
        ), contextlib.redirect_stdout(output):
            result = candidate.main(env)
        self.assertEqual(result, 1)
        self.assertEqual(env.secret_reads, [])
        data = json.loads(output.getvalue())
        self.assertEqual(data["safe_error_code"], "PLAN_NOT_READY")
        self.assertFalse(data["provider_mutation_attempted"])
        self.assertFalse(data["session_state_readback_required"])
        self.assertTrue(data["credential_retirement_required"])
        self.assertTrue(data["github_binding_retirement_required"])

    def test_fallback_cleanup_is_mandatory_before_secret_resolution(self):
        with patch.object(candidate, "_load", side_effect=AuthorizationPlanStop("PLAN_NOT_READY")):
            with self.assertRaises(AuthorizationPlanStop) as caught:
                candidate._check_fallback({}, "2026-10-08T15:00:00Z")
        self.assertEqual(str(caught.exception), "CLEANUP_FALLBACK_UNAVAILABLE")

    def test_safe_error_taxonomy_is_preserved_without_sensitive_payloads(self):
        for code in (
            "LIVE_PROBE_IDENTITY_REJECTED",
            "LIVE_PROBE_AUTHORIZATION_DENIED",
            "LIVE_PROBE_SERVICE_UNAVAILABLE",
            "LIVE_PROBE_NETWORK_TIMEOUT",
            "LIVE_PROBE_RESPONSE_SHAPE_INVALID",
            "LIVE_PROBE_REDIRECT_REJECTED",
            "LIVE_PROBE_DNS_FAILURE",
            "POSITIVE_AUTH_FAILED_LOGOUT_UNVERIFIED",
        ):
            with self.subTest(code=code):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    rc = candidate._safe_failure(code, attempted=True)
                self.assertEqual(rc, 1)
                data = json.loads(output.getvalue())
                self.assertEqual(data["safe_error_code"], code)
                self.assertTrue(data["session_state_readback_required"])
                self.assertTrue(data["credential_retirement_required"])
                self.assertTrue(data["github_binding_retirement_required"])
                self.assertFalse(data["cleanup_verified"])
                self.assertFalse(data["retry_authorized"])
                self.assertFalse(data["implementation_handoff_attempted"])

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            candidate._safe_failure("SENSITIVE_SESSION_OR_PROVIDER_ERROR_TEXT", attempted=True)
        self.assertEqual(json.loads(output.getvalue())["safe_error_code"], "AUTHORITY_INVALID")

    def test_new_v15_probe_injected_into_shared_lifecycle(self):
        entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
        credential = RecoveryVerificationCredential(
            "offline-recovery-fixture-material-123456",
            user_id="33333333-3333-4333-8333-333333333333",
        )
        session = IssuedSession(
            access_token="offline-access-fixture-material-1234567890",
            refresh_token="offline-refresh-fixture-material-1234567890",
            expires_in=3600,
            expires_at=1800000000,
            token_type="bearer",
            user_id="33333333-3333-4333-8333-333333333333",
        )
        checked_jwt = JwtValidationResult(
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
        events = []
        with patch.object(candidate, "authenticated_live_identity_probe") as exact_probe:
            result = candidate.execute_positive_auth(
                admin_secret="offline-admin-fixture",
                publishable_key="offline-publishable-fixture",
                generate=lambda **_: (events.append("generate") or credential),
                verify=lambda **_: (events.append("verify") or session),
                validate_jwt=lambda _: (events.append("validate") or checked_jwt),
                live_probe=lambda token: (
                    events.append("live") or exact_probe(token)
                ),
                logout_global=lambda **_: events.append("logout"),
            )
        self.assertEqual(events, ["generate", "verify", "validate", "live", "logout"])
        exact_probe.assert_called_once()
        self.assertTrue(result["session_state_readback_required"])
        self.assertTrue(result["credential_retirement_required"])
        self.assertTrue(result["github_binding_retirement_required"])
        self.assertFalse(result["cleanup_verified"])
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)

    def test_failure_in_new_probe_still_logs_out_and_clears_session(self):
        entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
        credential = RecoveryVerificationCredential(
            "offline-recovery-fixture-material-123456",
            user_id="33333333-3333-4333-8333-333333333333",
        )
        session = IssuedSession(
            access_token="offline-access-fixture-material-1234567890",
            refresh_token="offline-refresh-fixture-material-1234567890",
            expires_in=3600,
            expires_at=1800000000,
            token_type="bearer",
            user_id="33333333-3333-4333-8333-333333333333",
        )
        checked_jwt = JwtValidationResult(
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
        events = []

        def failed_probe(_token):
            events.append("live")
            raise SafeLifecycleStop("LIVE_PROBE_NETWORK_TIMEOUT")

        with self.assertRaises(SafeLifecycleStop) as caught:
            candidate.execute_positive_auth(
                admin_secret="offline-admin-fixture",
                publishable_key="offline-publishable-fixture",
                generate=lambda **_: (events.append("generate") or credential),
                verify=lambda **_: (events.append("verify") or session),
                validate_jwt=lambda _: (events.append("validate") or checked_jwt),
                live_probe=failed_probe,
                logout_global=lambda **_: events.append("logout"),
            )
        self.assertEqual(caught.exception.code, "LIVE_PROBE_NETWORK_TIMEOUT")
        self.assertEqual(events, ["generate", "verify", "validate", "live", "logout"])
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)

    def test_prior_evidence_digests_are_all_bound(self):
        step0, step1, step2 = "first", "second", "third"
        plan = {
            "plan_id": "v15-test",
            "plan_version": 15,
            "plan_digest": "not-a-real-digest",
            "environment": "DEVELOPMENT",
            "target": {
                "provider_reference": "supabase", "project_reference": candidate.PROJECT,
                "responsibility": "AUTH", "issuer_reference": "issuer", "audience_reference": "audience",
            },
            "steps": [
                {"step_id": step0}, {"step_id": step1}, {"step_id": step2},
                {
                    "step_id": candidate.STEP_ID,
                    "resource": {"resource_reference": "test", "exact_version": "v15",
                                 "exact_digest": "fixture"},
                    "operation": candidate.OPERATION,
                    "execution_class": "PROVIDER_MUTATION",
                    "required_evidence": [
                        {"source_step_id": step0, "evidence_type": "first.done", "exact_digest": None},
                        {"source_step_id": None, "evidence_type": "preflight", "exact_digest": "bound"},
                    ],
                }
            ],
        }
        progress = {"step_states": [
            {"step_id": step0, "evidence": [{"evidence_type": "first.done", "evidence_digest": "digest-one"}]},
            {"step_id": step1, "evidence": [{"evidence_type": "second.done", "evidence_digest": "digest-two"}]},
            {"step_id": step2, "evidence": [{"evidence_type": "third.done", "evidence_digest": "digest-three"}]},
            {"step_id": candidate.STEP_ID, "evidence": []},
        ]}
        request = candidate._request_for(plan, progress)
        self.assertEqual(request["prior_evidence_digests"], ["digest-one", "digest-two", "digest-three"])
        self.assertEqual(request["required_evidence"], [
            {"evidence_type": "first.done", "evidence_digest": "digest-one"},
            {"evidence_type": "preflight", "evidence_digest": "bound"},
        ])


if __name__ == "__main__":
    unittest.main()
