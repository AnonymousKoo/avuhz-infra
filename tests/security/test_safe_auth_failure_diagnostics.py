import unittest

from avuhz_engineering.safe_auth_failure_diagnostics import sanitized_positive_auth_failure


class SafeAuthFailureDiagnosticsTests(unittest.TestCase):
    def test_known_code_retains_only_safe_code_and_stage(self):
        payload = sanitized_positive_auth_failure(
            "LIVE_AUTH_PROBE_FAILED", provider_mutation_attempted=True
        )
        self.assertEqual(payload["safe_error_code"], "LIVE_AUTH_PROBE_FAILED")
        self.assertEqual(payload["failure_stage"], "live_runtime_probe")
        self.assertTrue(payload["provider_mutation_attempted"])
        self.assertFalse(payload["retry_authorized"])
        self.assertFalse(payload["credential_material_retained"])
        self.assertFalse(payload["token_material_retained"])
        self.assertFalse(payload["provider_payload_retained"])
        self.assertFalse(payload["pii_retained"])

    def test_logout_codes_identify_logout_without_provider_detail(self):
        for code in (
            "GLOBAL_SESSION_LOGOUT_PROVIDER_REJECTED",
            "GLOBAL_SESSION_LOGOUT_REQUEST_FAILED",
            "GLOBAL_SESSION_LOGOUT_RESPONSE_INVALID",
        ):
            with self.subTest(code=code):
                payload = sanitized_positive_auth_failure(code, provider_mutation_attempted=True)
                self.assertEqual(payload["safe_error_code"], code)
                self.assertEqual(payload["failure_stage"], "global_logout")

    def test_unknown_value_collapses_fail_closed(self):
        payload = sanitized_positive_auth_failure(
            "raw provider error: token=secret", provider_mutation_attempted=True
        )
        self.assertEqual(payload["safe_error_code"], "AUTHORITY_INVALID")
        self.assertEqual(payload["failure_stage"], "authorization_preflight")
        rendered = repr(payload)
        self.assertNotIn("raw provider error", rendered)
        self.assertNotIn("token=secret", rendered)

    def test_none_collapses_fail_closed(self):
        payload = sanitized_positive_auth_failure(None, provider_mutation_attempted=False)
        self.assertEqual(payload["safe_error_code"], "AUTHORITY_INVALID")
        self.assertFalse(payload["provider_mutation_attempted"])


if __name__ == "__main__":
    unittest.main()
