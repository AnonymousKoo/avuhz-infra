from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import urllib.error
import unittest
from pathlib import Path
from unittest.mock import patch

from avuhz_engineering import development_auth_token_lifecycle as lifecycle
from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_SERVICE_AUDIENCE,
)
from avuhz_service.development_supabase_identity import (
    DevelopmentIdentityAllowlistEntry,
)


ROOT = Path(__file__).resolve().parents[2]
GENERATE_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures/development_auth_generate_link_response.json"
)
VERIFY_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures/development_auth_verify_recovery_response.json"
)


class FakeResponse:
    def __init__(self, status: int, body: bytes = b"") -> None:
        self.status = status
        self._body = body

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self, limit: int = -1) -> bytes:
        return self._body if limit < 0 else self._body[:limit]


def _memory_secret(label: str, minimum: int = 40) -> str:
    value = "-".join(("runtime", "only", label, "material"))
    return (value + "x" * minimum)[:minimum]


def _subject_digest(user_id: str) -> str:
    return "sha256:" + hashlib.sha256(user_id.encode("utf-8")).hexdigest()


def _jwt_with_es256_header() -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(b'{"sub":"fixture"}').rstrip(b"=")
    signature = base64.urlsafe_b64encode(b"synthetic-signature").rstrip(b"=")
    return b".".join((header, payload, signature)).decode("ascii")


class FakeVerifier:
    def __init__(self, claims: dict[str, object]) -> None:
        self.claims = claims

    def verify(self, _token: str) -> dict[str, object]:
        return dict(self.claims)


class DevelopmentAuthDirectRecoveryLifecycleTests(unittest.TestCase):
    def generate_fixture(self) -> dict:
        value = json.loads(GENERATE_FIXTURE.read_text(encoding="utf-8"))
        self.assertIsInstance(value, dict)
        return value

    def verify_fixture(self) -> dict:
        value = json.loads(VERIFY_FIXTURE.read_text(encoding="utf-8"))
        self.assertIsInstance(value, dict)
        return value

    def recovery_credential(
        self, payload: dict
    ) -> lifecycle.RecoveryVerificationCredential:
        return lifecycle.extract_recovery_verification_credential(
            payload,
            expected_user_id=payload["id"],
            expected_subject_digest=_subject_digest(payload["id"]),
        )

    def issued_session(self, payload: dict) -> lifecycle.IssuedSession:
        return lifecycle.parse_recovery_verification_response(
            payload,
            expected_user_id=payload["user"]["id"],
        )

    def valid_session_payload(self) -> dict:
        payload = self.verify_fixture()
        payload["access_token"] = _memory_secret("access")
        payload["refresh_token"] = _memory_secret("refresh")
        return payload

    def assert_safe_stop(
        self,
        expected: str,
        callback,
        *,
        session_state: lifecycle.SessionState | None = None,
        cleanup_state: lifecycle.SessionState | None = None,
    ) -> lifecycle.SafeLifecycleStop:
        with self.assertRaises(lifecycle.SafeLifecycleStop) as raised:
            callback()
        self.assertEqual(raised.exception.code, expected)
        self.assertEqual(raised.exception.session_state, session_state)
        self.assertEqual(raised.exception.cleanup_state, cleanup_state)
        return raised.exception

    def test_raw_generate_link_wire_shape_extracts_hashed_token_only_in_memory(self) -> None:
        payload = self.generate_fixture()
        credential_value = _memory_secret("recovery-credential")
        payload["hashed_token"] = credential_value
        credential = lifecycle.extract_recovery_verification_credential(
            payload,
            expected_user_id=payload["id"],
            expected_subject_digest=_subject_digest(payload["id"]),
        )
        try:
            self.assertEqual(credential._text(), credential_value)
            self.assertEqual(payload["verification_type"], "recovery")
            self.assertIsNone(payload["hashed_token"])
            self.assertIsNone(payload["action_link"])
            self.assertIsNone(payload["email_otp"])
            self.assertNotIn("properties", payload)
            self.assertNotIn("user", payload)
        finally:
            credential.clear()
        self.assertTrue(credential.is_cleared)

    def test_direct_recovery_verification_uses_exact_wire_contract(self) -> None:
        captured: list[object] = []
        recovery_token_hash = _memory_secret("direct-verification")
        credential = lifecycle.RecoveryVerificationCredential(recovery_token_hash)
        response_payload = self.verify_fixture()
        response_payload["access_token"] = _memory_secret("access")
        response_payload["refresh_token"] = _memory_secret("refresh")
        parsed_payloads: list[dict] = []
        parse_response = lifecycle.parse_recovery_verification_response

        def capture_parse(payload, *, expected_user_id):
            parsed_payloads.append(payload)
            return parse_response(payload, expected_user_id=expected_user_id)

        def urlopen(request, timeout):
            captured.extend((request, timeout, bytes(request.data)))
            return FakeResponse(200, json.dumps(response_payload).encode("utf-8"))

        try:
            with patch.object(
                lifecycle,
                "parse_recovery_verification_response",
                side_effect=capture_parse,
            ):
                result = lifecycle.request_direct_recovery_verification(
                    project_ref=DEVELOPMENT_AUTH_PROJECT_REF,
                    publishable_key=_memory_secret("publishable"),
                    credential=credential,
                    expected_user_id=response_payload["user"]["id"],
                    urlopen=urlopen,
                )
        finally:
            credential.clear()

        request = captured[0]
        self.assertEqual(request.full_url, f"{DEVELOPMENT_AUTH_ISSUER}/verify")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(captured[1], 30)
        body = json.loads(captured[2])
        self.assertEqual(set(body), {"type", "token_hash"})
        self.assertEqual(body["type"], "recovery")
        self.assertEqual(body["token_hash"], recovery_token_hash)
        self.assertEqual(result.token_type, "bearer")
        self.assertIsNotNone(request.get_header("Apikey"))
        self.assertTrue(request.get_header("Authorization").startswith("Bearer "))
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(request.get_header("Accept"), "application/json")
        self.assertEqual(request.data, bytearray())
        self.assertIsNone(parsed_payloads[0]["access_token"])
        self.assertIsNone(parsed_payloads[0]["refresh_token"])
        result.clear()
        self.assertTrue(result.is_cleared)

    def test_generate_recovery_uses_existing_user_only_wire_contract(self) -> None:
        captured: list[object] = []
        response_payload = self.generate_fixture()

        def urlopen(request, timeout):
            captured.extend((request, timeout, bytes(request.data)))
            return FakeResponse(200, json.dumps(response_payload).encode("utf-8"))

        result = lifecycle.request_generate_recovery_credential(
            project_ref=DEVELOPMENT_AUTH_PROJECT_REF,
            admin_secret=_memory_secret("admin"),
            existing_user_email="synthetic-fixture@example.invalid",
            expected_user_id=response_payload["id"],
            expected_subject_digest=_subject_digest(response_payload["id"]),
            urlopen=urlopen,
        )
        request = captured[0]
        self.assertEqual(
            request.full_url,
            (
                f"https://{DEVELOPMENT_AUTH_PROJECT_REF}.supabase.co"
                "/auth/v1/admin/generate_link"
            ),
        )
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(
            json.loads(captured[2]),
            {
                "type": "recovery",
                "email": "synthetic-fixture@example.invalid",
            },
        )
        self.assertNotIn("password", json.loads(captured[2]))
        self.assertEqual(request.data, bytearray())
        self.assertFalse(result.is_cleared)
        result.clear()
        self.assertTrue(result.is_cleared)

    def test_exact_raw_session_response_is_parsed(self) -> None:
        payload = self.valid_session_payload()
        session = lifecycle.parse_recovery_verification_response(
            payload,
            expected_user_id=payload["user"]["id"],
        )
        try:
            self.assertTrue(session.has_access_token)
            self.assertTrue(session.has_refresh_token)
            self.assertEqual(session.token_type, "bearer")
            self.assertEqual(session.expires_in, 3600)
            self.assertEqual(session.expires_at, 1799999999)
        finally:
            session.clear()
        self.assertTrue(session.is_cleared)
        self.assertNotIn(_memory_secret("access"), repr(session))

    def test_missing_expires_at_is_accepted_without_synthesis(self) -> None:
        payload = self.valid_session_payload()
        payload.pop("expires_at")
        session = lifecycle.parse_recovery_verification_response(
            payload, expected_user_id=payload["user"]["id"]
        )
        try:
            self.assertIsNone(session.expires_at)
        finally:
            session.clear()

    def test_null_expires_at_is_accepted(self) -> None:
        payload = self.valid_session_payload()
        payload["expires_at"] = None
        session = lifecycle.parse_recovery_verification_response(
            payload, expected_user_id=payload["user"]["id"]
        )
        try:
            self.assertIsNone(session.expires_at)
        finally:
            session.clear()

    def test_expires_in_above_previous_cap_is_accepted(self) -> None:
        payload = self.valid_session_payload()
        payload["expires_in"] = 7200
        session = lifecycle.parse_recovery_verification_response(
            payload, expected_user_id=payload["user"]["id"]
        )
        try:
            self.assertEqual(session.expires_in, 7200)
        finally:
            session.clear()

    def test_top_level_user_id_is_accepted_when_nested_user_is_absent(self) -> None:
        payload = self.valid_session_payload()
        user_id = payload["user"].pop("id")
        payload.pop("user")
        payload["id"] = user_id
        session = lifecycle.parse_recovery_verification_response(
            payload, expected_user_id=user_id
        )
        try:
            self.assertEqual(session.user_id, user_id)
        finally:
            session.clear()

    def test_matching_nested_and_top_level_ids_are_accepted(self) -> None:
        payload = self.valid_session_payload()
        user_id = payload["user"]["id"]
        payload["id"] = user_id
        session = lifecycle.parse_recovery_verification_response(
            payload, expected_user_id=user_id
        )
        try:
            self.assertEqual(session.user_id, user_id)
        finally:
            session.clear()

    def test_conflicting_nested_and_top_level_ids_fail_closed(self) -> None:
        payload = self.valid_session_payload()
        payload["id"] = "22222222-2222-4222-8222-222222222222"
        self.assert_safe_stop(
            "RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID",
            lambda: lifecycle.parse_recovery_verification_response(
                payload,
                expected_user_id=payload["user"]["id"],
            ),
        )

    def test_missing_both_identity_shapes_fails_closed(self) -> None:
        payload = self.valid_session_payload()
        payload.pop("user")
        self.assert_safe_stop(
            "RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID",
            lambda: lifecycle.parse_recovery_verification_response(
                payload, expected_user_id="11111111-1111-4111-8111-111111111111"
            ),
        )

    def test_malformed_nested_identity_fails_closed_even_with_top_level_id(self) -> None:
        payload = self.valid_session_payload()
        payload["user"]["id"] = "not-a-uuid"
        payload["id"] = "11111111-1111-4111-8111-111111111111"
        self.assert_safe_stop(
            "RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID",
            lambda: lifecycle.parse_recovery_verification_response(
                payload, expected_user_id="11111111-1111-4111-8111-111111111111"
            ),
        )

    def test_expected_user_mismatch_fails_closed(self) -> None:
        payload = self.valid_session_payload()
        self.assert_safe_stop(
            "RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID",
            lambda: lifecycle.parse_recovery_verification_response(
                payload, expected_user_id="22222222-2222-4222-8222-222222222222"
            ),
        )

    def test_invalid_session_fields_fail_closed(self) -> None:
        cases = (
            ("missing access", lambda p: p.pop("access_token")),
            ("missing refresh", lambda p: p.pop("refresh_token")),
            ("non-bearer", lambda p: p.__setitem__("token_type", "mac")),
            ("zero expiry", lambda p: p.__setitem__("expires_in", 0)),
            ("negative expiry", lambda p: p.__setitem__("expires_in", -1)),
            ("boolean expiry", lambda p: p.__setitem__("expires_in", True)),
            ("string expiry", lambda p: p.__setitem__("expires_in", "3600")),
            ("malformed expires_at", lambda p: p.__setitem__("expires_at", "later")),
            ("zero expires_at", lambda p: p.__setitem__("expires_at", 0)),
            ("boolean expires_at", lambda p: p.__setitem__("expires_at", True)),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                payload = self.valid_session_payload()
                mutate(payload)
                self.assert_safe_stop(
                    "RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID",
                    lambda payload=payload: lifecycle.parse_recovery_verification_response(
                        payload,
                        expected_user_id="11111111-1111-4111-8111-111111111111",
                    ),
                )

    def test_parser_does_not_make_provider_or_network_calls(self) -> None:
        payload = self.valid_session_payload()
        with patch.object(
            lifecycle.urllib.request,
            "urlopen",
            side_effect=AssertionError("parser must remain local"),
        ):
            session = lifecycle.parse_recovery_verification_response(
                payload, expected_user_id=payload["user"]["id"]
            )
        session.clear()

    def test_verification_provider_rejection_does_not_read_response_body(self) -> None:
        error_body = io.BytesIO(_memory_secret("provider-body").encode("utf-8"))
        rejection = urllib.error.HTTPError(
            "https://example.invalid", 400, "rejected", {}, error_body
        )
        credential = lifecycle.RecoveryVerificationCredential(
            _memory_secret("rejected-credential")
        )
        try:
            self.assert_safe_stop(
                "RECOVERY_VERIFICATION_PROVIDER_REJECTED",
                lambda: lifecycle.request_direct_recovery_verification(
                    project_ref=DEVELOPMENT_AUTH_PROJECT_REF,
                    publishable_key=_memory_secret("publishable"),
                    credential=credential,
                    expected_user_id=self.generate_fixture()["id"],
                    urlopen=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                        rejection
                    ),
                ),
            )
        finally:
            credential.clear()
        self.assertEqual(error_body.tell(), 0)

    def test_one_issued_session_is_logged_out_then_read_back_zero(self) -> None:
        generate = self.generate_fixture()
        generate["hashed_token"] = _memory_secret("lifecycle-credential")
        verify = self.verify_fixture()
        access_token = _memory_secret("lifecycle-access")
        verify["access_token"] = access_token
        verify["refresh_token"] = _memory_secret("lifecycle-refresh")
        states = iter(
            (
                {"session_count": 1, "refresh_token_count": 1},
                {"session_count": 0, "refresh_token_count": 0},
            )
        )
        events: list[str] = []

        result = lifecycle.run_recovery_session_lifecycle(
            generate_recovery=lambda _user_id, _digest: self.recovery_credential(
                generate
            ),
            verify_recovery=lambda _credential, _user_id: self.issued_session(
                verify
            ),
            read_session_state=lambda: next(states),
            logout_local=lambda token: events.append(
                "logout" if token == access_token else "wrong-token"
            ),
            validate_access_jwt=lambda token: events.append(
                "validate" if token == access_token else "wrong-token"
            ),
            expected_user_id=generate["id"],
            expected_subject_digest=_subject_digest(generate["id"]),
        )

        self.assertEqual(events, ["logout", "validate"])
        self.assertEqual(result.session_count_after_issue, 1)
        self.assertEqual(result.refresh_token_count_after_issue, 1)
        self.assertEqual(result.session_count_after_cleanup, 0)
        self.assertEqual(result.refresh_token_count_after_cleanup, 0)
        self.assertEqual(
            result.cleanup_state, lifecycle.SessionState.SESSION_CLEANUP_VERIFIED
        )

    def test_local_logout_uses_exact_session_endpoint_and_bearer(self) -> None:
        captured: list[object] = []
        access_token = _memory_secret("logout-access")

        def urlopen(request, timeout):
            captured.extend((request, timeout, bytes(request.data)))
            return FakeResponse(204)

        lifecycle.request_local_session_logout(
            project_ref=DEVELOPMENT_AUTH_PROJECT_REF,
            publishable_key=_memory_secret("publishable"),
            access_token=access_token,
            urlopen=urlopen,
        )
        request = captured[0]
        self.assertEqual(
            request.full_url,
            (
                f"https://{DEVELOPMENT_AUTH_PROJECT_REF}.supabase.co"
                "/auth/v1/logout?scope=local"
            ),
        )
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(json.loads(captured[2]), {})
        self.assertEqual(request.data, bytearray())
        self.assertEqual(request.get_header("Authorization"), f"Bearer {access_token}")

    def test_global_logout_uses_exact_scope_and_accepts_only_empty_204(self) -> None:
        captured: list[object] = []
        access_token = _memory_secret("global-logout-access")

        def urlopen(request, timeout):
            captured.extend((request, timeout, bytes(request.data)))
            return FakeResponse(204)

        lifecycle.request_global_session_logout(
            project_ref=DEVELOPMENT_AUTH_PROJECT_REF,
            publishable_key=_memory_secret("publishable"),
            bearer_token=access_token,
            urlopen=urlopen,
        )
        request = captured[0]
        self.assertEqual(
            request.full_url,
            (
                f"https://{DEVELOPMENT_AUTH_PROJECT_REF}.supabase.co"
                "/auth/v1/logout?scope=global"
            ),
        )
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(json.loads(captured[2]), {})
        self.assertEqual(request.data, bytearray())
        self.assertEqual(request.get_header("Authorization"), f"Bearer {access_token}")
        self.assertEqual(len(captured), 3)

    def test_subject_digest_binds_generated_id_for_direct_verification(self) -> None:
        generated = self.generate_fixture()
        generated["hashed_token"] = _memory_secret("subject-bound-recovery")
        verified = self.verify_fixture()
        verified["access_token"] = _memory_secret("subject-bound-access")
        verified["refresh_token"] = _memory_secret("subject-bound-refresh")
        credential = lifecycle.extract_recovery_verification_credential(
            generated,
            expected_user_id=None,
            expected_subject_digest=_subject_digest(generated["id"]),
        )

        def urlopen(_request, timeout):
            self.assertEqual(timeout, 30)
            return FakeResponse(200, json.dumps(verified).encode("utf-8"))

        try:
            session = lifecycle.request_direct_recovery_verification(
                project_ref=DEVELOPMENT_AUTH_PROJECT_REF,
                publishable_key=_memory_secret("publishable"),
                credential=credential,
                expected_user_id=None,
                urlopen=urlopen,
            )
            session.clear()
        finally:
            credential.clear()
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)

    def test_uncaptured_access_token_with_session_has_no_invented_cleanup(self) -> None:
        generate = self.generate_fixture()
        generate["hashed_token"] = _memory_secret("uncaptured-credential")
        malformed = self.verify_fixture()
        malformed.pop("access_token")
        logout_calls: list[str] = []

        self.assert_safe_stop(
            "RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID",
            lambda: lifecycle.run_recovery_session_lifecycle(
                generate_recovery=lambda _user_id, _digest: self.recovery_credential(
                    generate
                ),
                verify_recovery=lambda _credential, _user_id: self.issued_session(
                    malformed
                ),
                read_session_state=lambda: {
                    "session_count": 1,
                    "refresh_token_count": 1,
                },
                logout_local=logout_calls.append,
                validate_access_jwt=lambda _token: None,
                expected_user_id=generate["id"],
                expected_subject_digest=_subject_digest(generate["id"]),
            ),
            session_state=lifecycle.SessionState.SESSION_PRESENT,
            cleanup_state=lifecycle.SessionState.SESSION_CLEANUP_UNAVAILABLE,
        )
        self.assertEqual(logout_calls, [])

    def test_provider_rejection_still_reads_back_zero_independently(self) -> None:
        generate = self.generate_fixture()
        generate["hashed_token"] = _memory_secret("rejected-lifecycle")
        readbacks: list[str] = []

        def reject(_credential, _user_id):
            raise lifecycle.SafeLifecycleStop(
                "RECOVERY_VERIFICATION_PROVIDER_REJECTED"
            )

        def readback():
            readbacks.append("read")
            return {"session_count": 0, "refresh_token_count": 0}

        self.assert_safe_stop(
            "RECOVERY_VERIFICATION_PROVIDER_REJECTED",
            lambda: lifecycle.run_recovery_session_lifecycle(
                generate_recovery=lambda _user_id, _digest: self.recovery_credential(
                    generate
                ),
                verify_recovery=reject,
                read_session_state=readback,
                logout_local=lambda _token: self.fail("logout must not run"),
                validate_access_jwt=lambda _token: None,
                expected_user_id=generate["id"],
                expected_subject_digest=_subject_digest(generate["id"]),
            ),
            session_state=lifecycle.SessionState.NO_SESSION_OBSERVED,
            cleanup_state=lifecycle.SessionState.NO_SESSION_OBSERVED,
        )
        self.assertEqual(readbacks, ["read"])

    def test_readback_failure_is_explicitly_unverified(self) -> None:
        generate = self.generate_fixture()
        generate["hashed_token"] = _memory_secret("unverified-credential")

        self.assert_safe_stop(
            "RECOVERY_VERIFICATION_REQUEST_FAILED",
            lambda: lifecycle.run_recovery_session_lifecycle(
                generate_recovery=lambda _user_id, _digest: self.recovery_credential(
                    generate
                ),
                verify_recovery=lambda _credential, _user_id: (_ for _ in ()).throw(
                    OSError("sanitized transport failure")
                ),
                read_session_state=lambda: (_ for _ in ()).throw(
                    OSError("sanitized readback failure")
                ),
                logout_local=lambda _token: self.fail("logout must not run"),
                validate_access_jwt=lambda _token: None,
                expected_user_id=generate["id"],
                expected_subject_digest=_subject_digest(generate["id"]),
            ),
            session_state=lifecycle.SessionState.SESSION_STATE_UNVERIFIED,
            cleanup_state=lifecycle.SessionState.SESSION_STATE_UNVERIFIED,
        )

    def test_nonzero_post_logout_state_fails_closed_as_session_present(self) -> None:
        generate = self.generate_fixture()
        generate["hashed_token"] = _memory_secret("residual-credential")
        verify = self.verify_fixture()
        verify["access_token"] = _memory_secret("residual-access")
        verify["refresh_token"] = _memory_secret("residual-refresh")
        states = iter(
            (
                {"session_count": 1, "refresh_token_count": 1},
                {"session_count": 1, "refresh_token_count": 1},
            )
        )

        self.assert_safe_stop(
            "SESSION_CLEANUP_NOT_VERIFIED",
            lambda: lifecycle.run_recovery_session_lifecycle(
                generate_recovery=lambda _user_id, _digest: self.recovery_credential(
                    generate
                ),
                verify_recovery=lambda _credential, _user_id: self.issued_session(
                    verify
                ),
                read_session_state=lambda: next(states),
                logout_local=lambda _token: None,
                validate_access_jwt=lambda _token: None,
                expected_user_id=generate["id"],
                expected_subject_digest=_subject_digest(generate["id"]),
            ),
            session_state=lifecycle.SessionState.SESSION_PRESENT,
            cleanup_state=lifecycle.SessionState.SESSION_PRESENT,
        )

    def test_exact_development_jwt_policy_is_preserved(self) -> None:
        provider_subject = "13b7706e-6d90-4696-9e2c-abd377372121"
        tenant_id = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
        allowlist = (
            DevelopmentIdentityAllowlistEntry(
                subject_digest=_subject_digest(provider_subject),
                principal_reference="subject.development-synthetic-user",
                tenant_id=tenant_id,
            ),
        )
        claims = {
            "iss": DEVELOPMENT_AUTH_ISSUER,
            "aud": DEVELOPMENT_SERVICE_AUDIENCE,
            "sub": provider_subject,
            "avuhz_tenant_id": tenant_id,
            "role": "authenticated",
            "aal": "aal1",
            "is_anonymous": False,
            "iat": 1799996000,
            "exp": 1799999600,
            "session_id": "22222222-2222-4222-8222-222222222222",
        }
        with patch.object(
            lifecycle, "DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST", allowlist
        ):
            result = lifecycle.validate_development_synthetic_access_jwt(
                _jwt_with_es256_header(),
                verifier=FakeVerifier(claims),
            )
        self.assertEqual(result.algorithm, "ES256")
        self.assertEqual(result.issuer, DEVELOPMENT_AUTH_ISSUER)
        self.assertEqual(result.audience, DEVELOPMENT_SERVICE_AUDIENCE)
        self.assertEqual(result.tenant_id, tenant_id)
        self.assertEqual(result.subject_digest, allowlist[0].subject_digest)
        self.assertEqual(result.role, "authenticated")
        self.assertEqual(result.aal, "aal1")
        self.assertFalse(result.is_anonymous)
        self.assertEqual(result.caller_type, "HUMAN")
        self.assertEqual(result.capabilities, ("engagement:read",))
        self.assertEqual(result.authority_roles, ())

    def test_sensitive_material_never_appears_in_errors_or_output(self) -> None:
        generate = self.generate_fixture()
        recovery_material = _memory_secret("no-log-recovery")
        access_material = _memory_secret("no-log-access")
        refresh_material = _memory_secret("no-log-refresh")
        generate["hashed_token"] = recovery_material
        malformed = self.verify_fixture()
        malformed["access_token"] = access_material
        malformed["refresh_token"] = refresh_material
        malformed["expires_at"] = "invalid-expiry"
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            error = self.assert_safe_stop(
                "RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID",
                lambda: lifecycle.run_recovery_session_lifecycle(
                    generate_recovery=lambda _user_id, _digest: self.recovery_credential(
                        generate
                    ),
                    verify_recovery=lambda _credential, _user_id: self.issued_session(
                        malformed
                    ),
                    read_session_state=lambda: {
                        "session_count": 1,
                        "refresh_token_count": 1,
                    },
                    logout_local=lambda _token: None,
                    validate_access_jwt=lambda _token: None,
                    expected_user_id=generate["id"],
                    expected_subject_digest=_subject_digest(generate["id"]),
                ),
                session_state=lifecycle.SessionState.SESSION_PRESENT,
                cleanup_state=lifecycle.SessionState.SESSION_CLEANUP_UNAVAILABLE,
            )
        rendered = output.getvalue() + str(error) + repr(error)
        for material in (recovery_material, access_material, refresh_material):
            self.assertNotIn(material, rendered)

    def test_corrected_lifecycle_has_no_browser_redirect_fragment_dependency(self) -> None:
        source = (
            ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("get_redirect_without_following(", source)
        self.assertNotIn("parse_session_redirect(", source)
        self.assertNotIn("urllib.parse", source)
        self.assertNotIn("HTTPRedirectHandler", source)
        self.assertIn('VERIFY_METHOD = "POST"', source)
        self.assertIn(
            'body={"type": VERIFY_TYPE, "token_hash": credential._text()}',
            source,
        )


if __name__ == "__main__":
    unittest.main()
