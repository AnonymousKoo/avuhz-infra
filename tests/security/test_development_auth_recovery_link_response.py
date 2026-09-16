from __future__ import annotations

import importlib.util
import io
import json
import urllib.error
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
EXECUTOR_PATH = ROOT / "scripts/development_auth_v30_token_executor.py"
FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures/development_auth_generate_link_response.json"

spec = importlib.util.spec_from_file_location("development_auth_v30_token_executor", EXECUTOR_PATH)
assert spec is not None and spec.loader is not None
executor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(executor)


class FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class DevelopmentAuthRecoveryLinkResponseTests(unittest.TestCase):
    def fixture(self) -> dict:
        value = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        self.assertIsInstance(value, dict)
        return value

    def assert_safe_stop(self, expected: str, callback) -> None:
        with self.assertRaises(executor.SafeStop) as raised:
            callback()
        self.assertEqual(str(raised.exception), expected)

    def test_raw_direct_http_response_is_parsed_from_top_level_fields(self) -> None:
        payload = self.fixture()
        subject_digest = "sha256:" + executor.hashlib.sha256(payload["id"].encode("utf-8")).hexdigest()
        with patch.object(executor, "SUBJECT_DIGEST", subject_digest):
            result = executor.parse_generate_recovery_link_response(payload, payload["id"])
        self.assertEqual(result, "<synthetic-redacted-action-link>")
        self.assertNotIn("properties", payload)
        self.assertNotIn("user", payload)

    def test_sdk_transformed_shape_fails_closed(self) -> None:
        payload = self.fixture()
        transformed = {
            "properties": {
                "action_link": payload["action_link"],
                "verification_type": payload["verification_type"],
            },
            "user": {"id": payload["id"]},
        }
        self.assert_safe_stop(
            "V30_RECOVERY_LINK_RESPONSE_SHAPE_INVALID",
            lambda: executor.parse_generate_recovery_link_response(transformed, payload["id"]),
        )

    def test_http_rejection_has_sanitized_classification_without_reading_body(self) -> None:
        error_body = io.BytesIO(b"body-must-not-be-read")
        rejection = urllib.error.HTTPError(
            "https://example.invalid",
            400,
            "rejected",
            {},
            error_body,
        )
        with patch.object(executor.urllib.request, "urlopen", side_effect=rejection):
            self.assert_safe_stop(
                "V30_RECOVERY_LINK_PROVIDER_REJECTED",
                lambda: executor.request_generate_recovery_link("synthetic-redacted"),
            )
        self.assertEqual(error_body.tell(), 0)

    def test_invalid_non_json_response_has_sanitized_classification(self) -> None:
        response = FakeResponse(200, b"not-json")
        with patch.object(executor.urllib.request, "urlopen", return_value=response):
            self.assert_safe_stop(
                "V30_RECOVERY_LINK_RESPONSE_INVALID",
                lambda: executor.request_generate_recovery_link("synthetic-redacted"),
            )

    def test_success_with_unexpected_shape_has_sanitized_classification(self) -> None:
        response = FakeResponse(200, b'{"verification_type":"recovery"}')
        with patch.object(executor.urllib.request, "urlopen", return_value=response):
            payload = executor.request_generate_recovery_link("synthetic-redacted")
        self.assert_safe_stop(
            "V30_RECOVERY_LINK_RESPONSE_SHAPE_INVALID",
            lambda: executor.parse_generate_recovery_link_response(payload, self.fixture()["id"]),
        )

    def test_non_object_json_has_unexpected_shape_classification(self) -> None:
        response = FakeResponse(200, b"[]")
        with patch.object(executor.urllib.request, "urlopen", return_value=response):
            self.assert_safe_stop(
                "V30_RECOVERY_LINK_RESPONSE_SHAPE_INVALID",
                lambda: executor.request_generate_recovery_link("synthetic-redacted"),
            )

    def test_transport_failure_has_distinct_sanitized_classification(self) -> None:
        with patch.object(
            executor.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("synthetic transport failure"),
        ):
            self.assert_safe_stop(
                "V30_RECOVERY_LINK_REQUEST_FAILED",
                lambda: executor.request_generate_recovery_link("synthetic-redacted"),
            )


if __name__ == "__main__":
    unittest.main()
