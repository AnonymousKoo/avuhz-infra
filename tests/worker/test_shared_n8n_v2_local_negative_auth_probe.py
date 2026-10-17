"""Offline-only negative-auth proof; no real n8n traffic or credential reads."""
from __future__ import annotations

import contextlib
import io
import json
import os
import unittest
from unittest.mock import Mock, patch

from scripts import prepare_shared_n8n_v2_local_negative_auth_probe as probe
from scripts import prepare_shared_n8n_v2_local_first_event_qa as qa

ENV = {"CI": "", "GITHUB_ACTIONS": "", "AVUHZ_ENVIRONMENT": "LOCAL"}
COMMIT = "a" * 40


def evidence(*, count=1, executions=0):
    runtime = qa.QaReadback(
        probe.replay.RECEIPT_ENDPOINT, 19999, count, 6, 1, 0, executions
    )
    return probe.replay.Evidence(runtime, (
        ("synthetic-inbound-id", "httpHeaderAuth", "metadata-only"),
        ("synthetic-receipt-id", "httpHeaderAuth", "metadata-only"),
    ), probe.replay.FIXTURE_DIGEST)


class NativeHeaderNegativeAuthTests(unittest.TestCase):
    def setUp(self):
        self.default = ["--target", probe.TARGET]
        self.approved = self.default + [
            "--send-one-denied", "--ui-listener-ready",
            "--approved-receiver-id", probe.first.RECEIVER_ID,
            "--approved-test-url", probe.first.TEST_URL,
            "--approved-receipt-endpoint", probe.replay.RECEIPT_ENDPOINT,
            "--approved-source-sha256", probe.replay.EXPECTED_SOURCE_SHA256,
            "--approved-source-commit", COMMIT,
            "--approved-event-digest", "sha256:" + probe.replay.FIXTURE_DIGEST,
        ]

    def output(self, args):
        with contextlib.redirect_stdout(io.StringIO()) as sink:
            code = probe.run(args)
        return code, sink.getvalue()

    def test_default_is_readonly_and_never_sends(self):
        with (
            patch.dict(os.environ, ENV),
            patch.object(probe, "_preflight", return_value=evidence()) as gate,
            patch.object(probe, "_post_invalid_one") as post,
        ):
            code, text = self.output(self.default)
        self.assertEqual(code, 0)
        gate.assert_called_once()
        post.assert_not_called()
        self.assertIn("read-only", text)

    def test_readonly_rejects_mutation_flags(self):
        with (
            patch.dict(os.environ, ENV),
            patch.object(probe, "_preflight") as gate,
            patch.object(probe, "_post_invalid_one") as post,
        ):
            for flag in (
                ["--ui-listener-ready"],
                ["--approved-source-commit", COMMIT],
                ["--approved-test-url", probe.first.TEST_URL],
                ["--approved-event-digest", "sha256:" + probe.replay.FIXTURE_DIGEST],
            ):
                with self.subTest(flag=flag):
                    self.assertEqual(self.output(self.default + flag)[0], 2)
        gate.assert_not_called()
        post.assert_not_called()

    def test_wrong_environments_block_before_any_preflight(self):
        with (
            patch.object(probe, "_preflight") as gate,
            patch.object(probe, "_post_invalid_one") as post,
        ):
            for delta in (
                {"AVUHZ_ENVIRONMENT": "TEST"},
                {"AVUHZ_ENVIRONMENT": "DEVELOPMENT"},
                {"AVUHZ_ENVIRONMENT": "PRODUCTION"},
                {"CI": "true"},
                {"GITHUB_ACTIONS": "true"},
            ):
                with self.subTest(delta=delta), patch.dict(os.environ, {**ENV, **delta}):
                    self.assertEqual(self.output(self.approved)[0], 2)
            with patch.dict(os.environ, ENV):
                self.assertEqual(self.output(["--target", "WRONG"])[0], 2)
        gate.assert_not_called()
        post.assert_not_called()

    def test_exact_source_url_receipt_and_listener_approval_required(self):
        with (
            patch.dict(os.environ, ENV),
            patch.object(probe, "_preflight", return_value=evidence()),
            patch.object(probe.first, "_pinned_source_commit", return_value=COMMIT),
            patch.object(probe, "_post_invalid_one") as post,
        ):
            for name, bad in (
                ("--approved-receiver-id", "different"),
                ("--approved-test-url", "http://127.0.0.1:5678/webhook/avuhz-events"),
                ("--approved-receipt-endpoint", "http://172.17.0.1:37892/"),
                ("--approved-source-sha256", "sha256:" + "0" * 64),
                ("--approved-source-commit", "b" * 40),
                ("--approved-event-digest", "sha256:" + "0" * 64),
            ):
                args = self.approved.copy()
                args[args.index(name) + 1] = bad
                with self.subTest(name=name):
                    self.assertEqual(self.output(args)[0], 2)
            args = [value for value in self.approved if value != "--ui-listener-ready"]
            self.assertEqual(self.output(args)[0], 2)
        post.assert_not_called()

    def test_missing_original_receipt_and_saved_execution_block(self):
        for count, executions in ((0, 0), (2, 0), (1, 1)):
            with (
                self.subTest(count=count, executions=executions),
                patch.dict(os.environ, ENV),
                patch.object(
                    probe.replay, "_preflight", return_value=evidence(
                        count=count, executions=executions
                    ),
                ),
                patch.object(probe, "_post_invalid_one") as post,
            ):
                self.assertEqual(self.output(self.approved)[0], 2)
                post.assert_not_called()

    def test_random_wrong_header_single_native_webhook_post(self):
        conn = Mock()
        response = Mock(status=403)
        conn.getresponse.return_value = response
        with (
            patch.object(probe.http.client, "HTTPConnection", return_value=conn) as make,
            patch.object(probe.secrets, "token_urlsafe", return_value="synthetic-invalid-" + "z" * 48) as fake,
        ):
            self.assertEqual(probe._post_invalid_one(), 403)
        make.assert_called_once_with("127.0.0.1", 5678, timeout=8)
        fake.assert_called_once_with(48)
        conn.request.assert_called_once()
        method, url = conn.request.call_args.args[:2]
        self.assertEqual((method, url), ("POST", "/webhook-test/avuhz-events"))
        headers = conn.request.call_args.kwargs["headers"]
        self.assertEqual(headers[probe.inbound.HEADER_NAME], "synthetic-invalid-" + "z" * 48)
        self.assertEqual(json.loads(conn.request.call_args.kwargs["body"]), qa.fictional_event())
        response.read.assert_not_called()
        response.getheader.assert_not_called()
        conn.close.assert_called_once()

    def test_one_403_does_not_create_receipt_or_execution(self):
        before = evidence()
        with (
            patch.dict(os.environ, ENV),
            patch.object(probe, "_preflight", return_value=before) as pre,
            patch.object(probe.first, "_pinned_source_commit", return_value=COMMIT),
            patch.object(probe, "_post_invalid_one", return_value=403) as post,
        ):
            code, text = self.output(self.approved)
        self.assertEqual(code, 0)
        self.assertEqual(pre.call_count, 3)
        post.assert_called_once()
        self.assertIn("HTTP 403", text)
        self.assertIn("zero new executions", text)

    def test_non_denial_http_status_or_metadata_drift_fails_closed(self):
        for status in (200, 202, 400, 401, 404, 500):
            with (
                self.subTest(status=status),
                patch.dict(os.environ, ENV),
                patch.object(probe, "_preflight", return_value=evidence()),
                patch.object(probe.first, "_pinned_source_commit", return_value=COMMIT),
                patch.object(probe, "_post_invalid_one", return_value=status) as post,
            ):
                code, text = self.output(self.approved)
            self.assertEqual(code, 2)
            post.assert_called_once()
            self.assertNotIn("PASS", text)
        with (
            patch.dict(os.environ, ENV),
            patch.object(probe, "_preflight", side_effect=[evidence(), evidence(), evidence(executions=1)]),
            patch.object(probe.first, "_pinned_source_commit", return_value=COMMIT),
            patch.object(probe, "_post_invalid_one", return_value=403) as post,
        ):
            self.assertEqual(self.output(self.approved)[0], 2)
        post.assert_called_once()

    def test_runtime_drift_before_post_and_ambiguous_transport_never_retry(self):
        with (
            patch.dict(os.environ, ENV),
            patch.object(probe, "_preflight", side_effect=[evidence(), evidence(executions=1)]),
            patch.object(probe.first, "_pinned_source_commit", return_value=COMMIT),
            patch.object(probe, "_post_invalid_one") as post,
        ):
            self.assertEqual(self.output(self.approved)[0], 2)
        post.assert_not_called()
        with (
            patch.dict(os.environ, ENV),
            patch.object(probe, "_preflight", return_value=evidence()),
            patch.object(probe.first, "_pinned_source_commit", return_value=COMMIT),
            patch.object(probe, "_post_invalid_one", side_effect=probe.NegativeAuthDenied("ambiguous_transport_no_retry")) as post,
        ):
            code, text = self.output(self.approved)
        self.assertEqual(code, 2)
        post.assert_called_once()
        self.assertNotIn("ambiguous_transport_no_retry", text)

    def test_transport_error_never_reads_body_or_retries(self):
        conn = Mock()
        conn.getresponse.side_effect = TimeoutError("fictional time-out, no retry")
        with (
            patch.object(probe.http.client, "HTTPConnection", return_value=conn),
        ):
            with self.assertRaises(probe.NegativeAuthDenied):
                probe._post_invalid_one()
        conn.request.assert_called_once()
        conn.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
