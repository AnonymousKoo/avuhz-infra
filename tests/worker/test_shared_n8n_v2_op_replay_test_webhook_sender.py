"""Offline-only tests for the bounded LOCAL native n8n receipt replay probe."""
from __future__ import annotations

import contextlib
import io
import os
import unittest
from unittest.mock import patch

from scripts import prepare_shared_n8n_v2_op_replay_test_webhook_sender as replay
from scripts import prepare_shared_n8n_v2_local_first_event_qa as qa

FAKE_REF = "op://fictional-vault/fictional-inbound-item/password"
FAKE_TOKEN = "synthetic-private-token-" + "f" * 38
FAKE_COMMIT = "a" * 40
ENV = {"CI": "", "GITHUB_ACTIONS": "", "AVUHZ_ENVIRONMENT": "LOCAL"}


def evidence(*, receipts=1, executions=0, pid=19731):
    state = qa.QaReadback(replay.RECEIPT_ENDPOINT, pid, receipts, 6, 1, 0, executions)
    return replay.Evidence(state, (
        (replay.INBOUND_ID, "synthetic-inbound-name", "httpHeaderAuth", "old", "fixed", 144),
        (replay.RECEIPT_ID, "synthetic-receipt-name", "httpHeaderAuth", "old", "fixed", 144),
    ), replay.FIXTURE_DIGEST)


class OneLocalReplayTests(unittest.TestCase):
    def setUp(self):
        self.default = ["--target", replay.TARGET]
        self.approved = self.default + [
            "--send-one-replay",
            "--ui-listener-ready",
            "--approved-receiver-id", replay.first.RECEIVER_ID,
            "--approved-test-url", replay.first.TEST_URL,
            "--approved-receipt-endpoint", replay.RECEIPT_ENDPOINT,
            "--approved-source-sha256", replay.EXPECTED_SOURCE_SHA256,
            "--approved-source-commit", FAKE_COMMIT,
            "--approved-event-digest", "sha256:" + replay.FIXTURE_DIGEST,
            "--approved-secret-reference", FAKE_REF,
        ]

    def run_silent(self, arguments):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = replay.run(arguments)
        return result, output.getvalue()

    def test_readonly_one_receipt_never_reaches_secret_or_sender(self):
        with (
            patch.dict(os.environ, ENV),
            patch.object(replay, "_preflight", return_value=evidence()) as pre,
            patch.object(replay, "LocalN8nOnePasswordCredential") as provider,
            patch.object(replay.first, "_post_one") as sender,
        ):
            result, output = self.run_silent(self.default)
        self.assertEqual(result, 0)
        self.assertIn("read-only", output)
        pre.assert_called_once()
        provider.assert_not_called()
        sender.assert_not_called()

    def test_readonly_refuses_send_related_flags(self):
        with (
            patch.dict(os.environ, ENV),
            patch.object(replay, "LocalN8nOnePasswordCredential") as provider,
            patch.object(replay.first, "_post_one") as sender,
        ):
            for flags in (["--ui-listener-ready"],
                          ["--approved-secret-reference", FAKE_REF],
                          ["--approved-event-digest", "sha256:" + replay.FIXTURE_DIGEST]):
                self.assertEqual(self.run_silent(self.default + flags)[0], 2)
        provider.assert_not_called()
        sender.assert_not_called()

    def test_wrong_scope_never_reads_credential_or_posts(self):
        with (
            patch.object(replay, "_preflight") as pre,
            patch.object(replay, "LocalN8nOnePasswordCredential") as provider,
            patch.object(replay.first, "_post_one") as sender,
        ):
            for change in ({"AVUHZ_ENVIRONMENT": "DEVELOPMENT"},
                           {"AVUHZ_ENVIRONMENT": "PRODUCTION"},
                           {"AVUHZ_ENVIRONMENT": "TEST"},
                           {"CI": "true"}, {"GITHUB_ACTIONS": "true"}):
                with patch.dict(os.environ, {**ENV, **change}):
                    self.assertEqual(self.run_silent(self.approved)[0], 2)
            with patch.dict(os.environ, ENV):
                self.assertEqual(self.run_silent(["--target", "OTHER"])[0], 2)
        pre.assert_not_called()
        provider.assert_not_called()
        sender.assert_not_called()

    def test_any_wrong_approval_denied_before_issuer(self):
        with (
            patch.dict(os.environ, ENV),
            patch.object(replay, "_preflight", return_value=evidence()),
            patch.object(replay.first, "_pinned_source_commit", return_value=FAKE_COMMIT),
            patch.object(replay, "LocalN8nOnePasswordCredential") as provider,
            patch.object(replay.first, "_post_one") as sender,
        ):
            for flag, bad in (
                ("--approved-receiver-id", "wrong"),
                ("--approved-test-url", "http://127.0.0.1:5678/webhook/avuhz-events"),
                ("--approved-receipt-endpoint", "http://127.0.0.1:37891/"),
                ("--approved-source-sha256", "sha256:" + "0" * 64),
                ("--approved-source-commit", "b" * 40),
                ("--approved-event-digest", "sha256:" + "0" * 64),
            ):
                args = self.approved.copy()
                args[args.index(flag) + 1] = bad
                with self.subTest(flag=flag):
                    self.assertEqual(self.run_silent(args)[0], 2)
            without_listener = [v for v in self.approved if v != "--ui-listener-ready"]
            self.assertEqual(self.run_silent(without_listener)[0], 2)
        provider.assert_not_called()
        sender.assert_not_called()

    def test_zero_prior_receipts_and_retained_execution_block_before_secret(self):
        for receipts, executions in ((0, 0), (2, 0), (1, 1)):
            state = qa.QaReadback(replay.RECEIPT_ENDPOINT, 19731, receipts, 6, 1, 0, executions)
            with (
                self.subTest(receipts=receipts, executions=executions),
                patch.dict(os.environ, ENV),
                patch.object(replay.qa, "preflight", return_value=state),
                patch.object(replay, "LocalN8nOnePasswordCredential") as provider,
                patch.object(replay.first, "_post_one") as sender,
            ):
                self.assertEqual(self.run_silent(self.approved)[0], 2)
                provider.assert_not_called()
                sender.assert_not_called()

    def test_invalid_secret_reference_denied_before_token_read(self):
        args = self.approved.copy()
        args[args.index("--approved-secret-reference") + 1] = "https://invalid.example"
        with (
            patch.dict(os.environ, ENV),
            patch.object(replay, "_preflight", return_value=evidence()),
            patch.object(replay.first, "_pinned_source_commit", return_value=FAKE_COMMIT),
            patch.object(replay.first, "_post_one") as sender,
        ):
            self.assertEqual(self.run_silent(args)[0], 2)
        sender.assert_not_called()

    def test_exactly_one_private_read_one_send_postcheck(self):
        sent = []
        def one_send(*, event, token):
            self.assertEqual(token, FAKE_TOKEN)
            self.assertEqual(qa._digest(event), replay.FIXTURE_DIGEST)
            sent.append(1)
            return True
        after = evidence(executions=1)
        with (
            patch.dict(os.environ, ENV),
            patch.object(replay, "_preflight", return_value=evidence()) as pre,
            patch.object(replay, "_preflight_post_send", return_value=after) as post,
            patch.object(replay.first, "_pinned_source_commit", return_value=FAKE_COMMIT),
            patch.object(replay, "LocalN8nOnePasswordCredential", return_value=lambda: FAKE_TOKEN) as provider,
            patch.object(replay.first, "_post_one", side_effect=one_send) as sender,
        ):
            result, output = self.run_silent(self.approved)
        self.assertEqual(result, 0)
        self.assertEqual(sent, [1])
        self.assertEqual(pre.call_count, 3)
        post.assert_called_once()
        provider.assert_called_once_with(environment="LOCAL", approved_secret_reference=FAKE_REF)
        sender.assert_called_once()
        self.assertNotIn(FAKE_TOKEN, output)
        self.assertNotIn(FAKE_REF, output)
        self.assertIn("count remains one", output)

    def test_post_token_runtime_drift_stops_before_post(self):
        with (
            patch.dict(os.environ, ENV),
            patch.object(replay, "_preflight", side_effect=[
                evidence(), evidence(), evidence(executions=1),
            ]),
            patch.object(replay.first, "_pinned_source_commit", return_value=FAKE_COMMIT),
            patch.object(replay, "LocalN8nOnePasswordCredential", return_value=lambda: FAKE_TOKEN) as provider,
            patch.object(replay.first, "_post_one") as sender,
        ):
            result, output = self.run_silent(self.approved)
        self.assertEqual(result, 2)
        provider.assert_called_once()
        sender.assert_not_called()
        self.assertNotIn(FAKE_TOKEN, output)

    def test_unverified_postcondition_never_retries(self):
        for changed in (evidence(receipts=2, executions=1), evidence(pid=9999, executions=1)):
            with (
                self.subTest(changed=changed.runtime),
                patch.dict(os.environ, ENV),
                patch.object(replay, "_preflight", return_value=evidence()),
                patch.object(replay, "_preflight_post_send", return_value=changed),
                patch.object(replay.first, "_pinned_source_commit", return_value=FAKE_COMMIT),
                patch.object(replay, "LocalN8nOnePasswordCredential", return_value=lambda: FAKE_TOKEN),
                patch.object(replay.first, "_post_one", return_value=True) as sender,
            ):
                result, output = self.run_silent(self.approved)
            self.assertEqual(result, 2)
            sender.assert_called_once()
            self.assertNotIn(FAKE_TOKEN, output)

    def test_failure_or_transport_ambiguity_never_retries_or_leaks(self):
        for exception in (replay.first.TestWebhookHttpOutcome("HTTP_401"),
                          replay.first.TestWebhookHttpOutcome("TRANSPORT_AMBIGUOUS")):
            with (
                self.subTest(reason=str(type(exception))),
                patch.dict(os.environ, ENV),
                patch.object(replay, "_preflight", return_value=evidence()),
                patch.object(replay.first, "_pinned_source_commit", return_value=FAKE_COMMIT),
                patch.object(replay, "LocalN8nOnePasswordCredential", return_value=lambda: FAKE_TOKEN),
                patch.object(replay.first, "_post_one", side_effect=exception) as sender,
            ):
                result, output = self.run_silent(self.approved)
            self.assertEqual(result, 2)
            sender.assert_called_once()
            self.assertNotIn(FAKE_TOKEN, output)
            self.assertNotIn(FAKE_REF, output)


if __name__ == "__main__":
    unittest.main()
