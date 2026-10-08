"""No-network tests for source-bound, single-session DEVELOPMENT handoff."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/service")]

from test_development_synthetic_handoff_offline_certification import (
    SAMPLE_HANDOFF_ID, fictional_envelope,
)
from test_development_synthetic_handoff_preflight import CLOCK

from avuhz_engineering.development_auth_token_lifecycle import (
    IssuedSession, JwtValidationResult, RecoveryVerificationCredential,
)
from avuhz_engineering.development_source_bound_handoff_lifecycle import (
    COMMAND_URL, REPOSITORY,
    DevelopmentHandoffSource, preflight_source_bound_handoff,
    execute_source_bound_handoff,
)
from avuhz_engineering.development_synthetic_handoff_preflight import (
    SyntheticCommandPreflightStop, certify_synthetic_command,
)
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF,
)
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY,
)

MAIN = "c860f4ff22da60cfaac9c5dc8be778cb1d512f8c"
# Offline placeholders, never authenticated or transmitted.
ADMIN = "sb_secret_" + "fictional_local_only_no_provider_access"
PUBLISHABLE = "sb_publishable_" + "fictional_local_only_no_provider_access"
EMAIL = "fictional-provider-adapter@example.invalid"


def source_for(request):
    return DevelopmentHandoffSource(
        repository=REPOSITORY,
        canonical_main_sha=MAIN,
        authorization_plan_digest="sha256:" + "a" * 64,
        command_digest=certify_synthetic_command(request, at_utc=CLOCK).command_digest,
        auth_project_ref=DEVELOPMENT_AUTH_PROJECT_REF,
        data_project_ref=DEVELOPMENT_DATA_PROJECT_REF,
        command_url=COMMAND_URL,
        tenant_id=DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY.tenant_id,
    )


def fixture_credentials():
    credential = RecoveryVerificationCredential("fictional-recovery-local-only-0123456789")
    session = IssuedSession(
        access_token="synthetic-not-a-jwt-" + "x" * 64,
        refresh_token="fictional-refresh-local-only",
        expires_in=600,
        expires_at=None,
        token_type="bearer",
        user_id="a6b00000-0000-4000-8000-000000000010",
    )
    return credential, session


def valid_jwt_proof():
    entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
    return JwtValidationResult(
        algorithm="ES256",
        issuer="https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        audience="audience.avuhz.command-service.development",
        subject_digest=entry.subject_digest,
        tenant_id=entry.tenant_id,
        role="authenticated",
        aal="aal1",
        is_anonymous=False,
        caller_type="PROVIDER_ADAPTER",
        capabilities=("implementation_handoff:accept",),
        authority_roles=(),
    )


def callbacks(events, *, failed_stage=None, bad_validation=False,
              transport_failure=False, logout_failure=False, verify_failure=False):
    credential, session = fixture_credentials()

    def authorize(stage, project_ref, source):
        events.append(("approval", stage, project_ref))
        return stage != failed_stage

    def generate(**kwargs):
        events.append(("generate", kwargs["project_ref"]))
        assert kwargs["expected_subject_digest"] == DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY.subject_digest
        return credential

    def verify(**kwargs):
        events.append(("verify", kwargs["project_ref"]))
        if verify_failure:
            raise RuntimeError("fictional-provider-PII-must-not-appear")
        return session

    def validate(_token):
        events.append(("validate",))
        if bad_validation:
            value = valid_jwt_proof()
            return type("BadProof", (), {"algorithm": value.algorithm, "subject_digest": "sha256:" + "0" * 64})()
        return valid_jwt_proof()

    def sender(envelope, token):
        events.append(("send", envelope["subject_id"]))
        assert len(token) > 32
        if transport_failure:
            raise RuntimeError("fictional-provider-PII-must-not-appear")
        return 202, json.dumps({
            "result": "ACCEPTED",
            "reason_code": "COMMAND_ACCEPTED",
            "authoritative_record_reference": SAMPLE_HANDOFF_ID,
        }).encode()

    def logout(**kwargs):
        events.append(("logout", kwargs["project_ref"]))
        if logout_failure:
            raise RuntimeError("fictional-provider-PII-must-not-appear")

    options = dict(
        authorize_stage=authorize,
        admin_secret_supplier=lambda: (events.append(("resolve", "admin")) or ADMIN),
        publishable_key_supplier=lambda: (events.append(("resolve", "publishable")) or PUBLISHABLE),
        existing_user_email_supplier=lambda: (events.append(("resolve", "email")) or EMAIL),
        generate=generate, verify=verify, validate_jwt=validate,
        send_once=sender, logout_global=logout,
    )
    return options, credential, session


class SourceBoundDevelopmentHandoffLifecycleTests(unittest.TestCase):
    def execute(self, request, options, source=None):
        binding = source_for(request) if source is None else source
        return execute_source_bound_handoff(
            request, source=binding, observed_main_sha=MAIN, at_utc=CLOCK, **options
        )

    def test_success_exact_auth_data_scope_one_send_and_global_logout(self):
        request = fictional_envelope()
        events = []
        opts, credential, session = callbacks(events)
        with patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")):
            result = self.execute(request, opts)
        self.assertEqual(result.classification, "SYNTHETIC_COMMAND_ACCEPTED_PENDING_DATA_VERIFICATION")
        self.assertEqual(result.handoff_id, SAMPLE_HANDOFF_ID)
        self.assertTrue(result.generated_attempted)
        self.assertTrue(result.verification_attempted)
        self.assertTrue(result.command_attempted)
        self.assertTrue(result.global_logout_attempted)
        self.assertTrue(result.global_logout_accepted)
        self.assertTrue(result.data_readback_required)
        self.assertTrue(result.session_state_readback_required)
        self.assertTrue(result.credential_retirement_required)
        self.assertFalse(result.cleanup_verified)
        self.assertFalse(result.retry_authorized)
        self.assertFalse(result.token_material_retained)
        self.assertFalse(result.pii_retained)
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)
        self.assertEqual(session.user_id, "")
        self.assertEqual([event[0] for event in events], [
            "approval", "approval", "approval", "approval",
            "resolve", "resolve", "resolve",
            "generate", "verify", "validate", "send", "logout",
        ])
        self.assertEqual(
            [event[2] for event in events[:4]],
            [DEVELOPMENT_AUTH_PROJECT_REF] * 3 + [DEVELOPMENT_DATA_PROJECT_REF],
        )

    def test_source_sha_and_auth_data_project_drift_stop_before_any_resource_action(self):
        request = fictional_envelope()
        binding = source_for(request)
        for name, modified in (
            ("wrong-sha", {**binding.__dict__, "canonical_main_sha": "0" * 40}),
            ("AUTH-is-DATA", {**binding.__dict__, "auth_project_ref": DEVELOPMENT_DATA_PROJECT_REF}),
            ("DATA-is-AUTH", {**binding.__dict__, "data_project_ref": DEVELOPMENT_AUTH_PROJECT_REF}),
            ("wrong-host", {**binding.__dict__, "command_url": "https://example.invalid/v1/commands"}),
            ("wrong-command-digest", {**binding.__dict__, "command_digest": "sha256:" + "b" * 64}),
            ("missing-plan-digest", {**binding.__dict__, "authorization_plan_digest": ""}),
        ):
            with self.subTest(name=name):
                events = []
                options, _, _ = callbacks(events)
                with self.assertRaises(SyntheticCommandPreflightStop):
                    self.execute(request, options, DevelopmentHandoffSource(**modified))
                self.assertEqual(events, [])

    def test_missing_stage_authority_never_resolves_secrets(self):
        request = fictional_envelope()
        for stage in ("AUTH_GLOBAL_LOGOUT", "AUTH_GENERATE", "AUTH_VERIFY", "DATA_COMMAND"):
            with self.subTest(stage=stage):
                events = []
                options, _, _ = callbacks(events, failed_stage=stage)
                with self.assertRaises(SyntheticCommandPreflightStop):
                    self.execute(request, options)
                self.assertNotIn("resolve", [e[0] for e in events])
                self.assertNotIn("generate", [e[0] for e in events])
                self.assertNotIn("send", [e[0] for e in events])

    def test_invalid_jwt_prevents_command_but_logs_out_and_clears(self):
        events = []
        opts, credential, session = callbacks(events, bad_validation=True)
        result = self.execute(fictional_envelope(), opts)
        self.assertEqual(result.classification, "SYNTHETIC_HANDOFF_UNVERIFIED")
        self.assertFalse(result.command_attempted)
        self.assertTrue(result.global_logout_accepted)
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)
        self.assertNotIn("send", [e[0] for e in events])

    def test_ambiguous_send_does_not_retry_and_mandates_readback(self):
        events = []
        opts, credential, session = callbacks(events, transport_failure=True)
        result = self.execute(fictional_envelope(), opts)
        self.assertEqual([e[0] for e in events].count("send"), 1)
        self.assertEqual(result.classification, "SYNTHETIC_COMMAND_OUTCOME_UNVERIFIED")
        self.assertTrue(result.data_readback_required)
        self.assertFalse(result.retry_authorized)
        self.assertTrue(result.global_logout_accepted)
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)
        self.assertNotIn("fictional-provider-PII-must-not-appear", repr(result))

    def test_logout_failure_is_not_mislabeled_clean(self):
        events = []
        opts, credential, session = callbacks(events, logout_failure=True)
        result = self.execute(fictional_envelope(), opts)
        self.assertEqual(result.classification, "SYNTHETIC_HANDOFF_CLEANUP_UNVERIFIED")
        self.assertTrue(result.global_logout_attempted)
        self.assertFalse(result.global_logout_accepted)
        self.assertFalse(result.cleanup_verified)
        self.assertTrue(result.session_state_readback_required)
        self.assertEqual(result.safe_error_code, "HANDOFF_GLOBAL_LOGOUT_UNVERIFIED")
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)

    def test_verify_failure_marks_session_state_unknown_and_never_sends(self):
        events = []
        opts, credential, session = callbacks(events, verify_failure=True)
        result = self.execute(fictional_envelope(), opts)
        self.assertTrue(result.verification_attempted)
        self.assertTrue(result.session_state_readback_required)
        self.assertFalse(result.command_attempted)
        self.assertFalse(result.global_logout_accepted)
        self.assertTrue(credential.is_cleared)
        self.assertNotIn("send", [e[0] for e in events])
        self.assertNotIn("fictional-provider-PII-must-not-appear", repr(result))

    def test_mutated_envelope_stops_before_authority_and_credentials(self):
        original = fictional_envelope()
        request = copy.deepcopy(original)
        request["tenant_id"] = "a6b00000-0000-4000-8000-000000000099"
        events = []
        opts, _, _ = callbacks(events)
        with self.assertRaises(SyntheticCommandPreflightStop):
            self.execute(request, opts, source_for(original))
        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
