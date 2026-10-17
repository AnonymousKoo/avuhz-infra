"""Synthetic offline safety tests for an opt-in 1Password -> n8n test send."""
from __future__ import annotations

import contextlib
import io
import os
import unittest
from unittest.mock import patch

from scripts import prepare_shared_n8n_v2_op_test_webhook_sender as bridge
from scripts import prepare_shared_n8n_v2_local_test_webhook_sender as sender
from scripts import prepare_shared_n8n_v2_local_first_event_qa as qa

FAKE_REF = "op://fictional-local-vault/fictional-approved-item/password"
FAKE_COMMIT = "a"*40
FAKE_SECRET = "synthetic-inbound-credential-only-" + "a"*34
ENV = {"CI": "", "GITHUB_ACTIONS": "", "AVUHZ_ENVIRONMENT": "LOCAL"}


class OnePrivateSendTests(unittest.TestCase):
    def setUp(self):
        self.event = qa.fictional_event()
        self.digest = qa._digest(self.event)
        self.state = qa.QaReadback(
            "http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts",
            19999, 0, 6, 1, 0, 0,
        )
        self.default = ["--target", sender.TARGET]
        self.write = self.default + [
            "--send-one",
            "--approved-receiver-id", sender.RECEIVER_ID,
            "--approved-test-url", sender.TEST_URL,
            "--approved-receipt-endpoint", self.state.endpoint,
            "--approved-source-sha256", sender.SOURCE_SHA256,
            "--approved-source-commit", FAKE_COMMIT,
            "--approved-event-digest", "sha256:" + self.digest,
            "--approved-secret-reference", FAKE_REF,
            "--ui-listener-ready",
        ]

    def _preflight(self):
        return self.state, self.event, self.digest

    def test_read_only_uses_no_1password_and_no_send(self):
        with (
            patch.dict(os.environ,ENV),
            patch.object(bridge.sender,"_one_readonly_preflight",return_value=self._preflight()),
            patch.object(bridge,"LocalN8nOnePasswordCredential") as provider,
            patch.object(bridge.sender,"run") as send,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(bridge.run(self.default),0)
        provider.assert_not_called()
        send.assert_not_called()
        self.assertIn("no 1Password call",output.getvalue())

    def test_readonly_refuses_all_mutation_flags(self):
        for arg in (
            ["--send-one"],
            ["--approved-secret-reference",FAKE_REF],
            ["--ui-listener-ready"],
        ):
            with (
                self.subTest(arg=arg),
                patch.dict(os.environ,ENV),
                patch.object(bridge,"LocalN8nOnePasswordCredential") as provider,
                patch.object(bridge.sender,"run") as send,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(bridge.run(self.default+arg),2)
                provider.assert_not_called()
                send.assert_not_called()

    def test_wrong_environment_or_target_blocks_before_preflight(self):
        cases=[
            (self.default,{"AVUHZ_ENVIRONMENT":"PRODUCTION"}),
            (self.default,{"AVUHZ_ENVIRONMENT":"TEST"}),
            (self.default,{"AVUHZ_ENVIRONMENT":"DEVELOPMENT"}),
            (self.default,{"CI":"1"}),
            (self.default,{"GITHUB_ACTIONS":"true"}),
            (["--target","OTHER"],{}),
        ]
        for args,env in cases:
            with (
                self.subTest(env=env),
                patch.dict(os.environ,{**ENV,**env}),
                patch.object(bridge.sender,"_one_readonly_preflight") as pre,
                patch.object(bridge,"LocalN8nOnePasswordCredential") as op,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(bridge.run(args),2)
                pre.assert_not_called()
                op.assert_not_called()

    def test_missing_exact_approval_fails_before_secret_access(self):
        for flag,val in (
            ("--approved-receiver-id","WRONG"),
            ("--approved-test-url","http://127.0.0.1:5678/webhook/avuhz-events"),
            ("--approved-receipt-endpoint","http://172.17.0.1:19999/v1/avuhz/local-n8n-receipts"),
            ("--approved-source-sha256","sha256:"+"0"*64),
            ("--approved-event-digest","sha256:"+"0"*64),
            ("--approved-source-commit","b"*40),
        ):
            args=self.write[:]
            args[args.index(flag)+1]=val
            with (
                self.subTest(flag=flag),
                patch.dict(os.environ,ENV),
                patch.object(bridge.sender,"_one_readonly_preflight",return_value=self._preflight()),
                patch.object(bridge.sender,"_pinned_source_commit",return_value=FAKE_COMMIT),
                patch.object(bridge,"LocalN8nOnePasswordCredential") as provider,
                patch.object(bridge.sender,"run") as send,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(bridge.run(args),2)
                provider.assert_not_called()
                send.assert_not_called()

    def test_missing_ui_listener_acknowledgement_blocks(self):
        args=[a for a in self.write if a!="--ui-listener-ready"]
        with (
            patch.dict(os.environ,ENV),
            patch.object(bridge,"LocalN8nOnePasswordCredential") as op,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(bridge.run(args),2)
        op.assert_not_called()

    def test_private_reference_bad_shape_fails_without_op_read(self):
        args=self.write[:]
        args[args.index("--approved-secret-reference")+1]="https://not-1password.invalid"
        with (
            patch.dict(os.environ,ENV),
            patch.object(bridge.sender,"_one_readonly_preflight",return_value=self._preflight()),
            patch.object(bridge.sender,"_pinned_source_commit",return_value=FAKE_COMMIT),
            patch.object(bridge.sender,"run") as send,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(bridge.run(args),2)
        send.assert_not_called()

    def test_exact_one_issuer_read_one_fd_bridge_one_send(self):
        from_holder=[]
        def fake_send(args):
            self.assertEqual(args[:3],["--target",sender.TARGET,"--send-one"])
            fd=int(args[args.index("--token-fd")+1])
            observed=os.read(fd,512).decode("ascii")
            from_holder.append(observed)
            self.assertNotIn(observed,str(args))
            self.assertNotIn(FAKE_REF,str(args))
            return 0
        with (
            patch.dict(os.environ,ENV),
            patch.object(bridge.sender,"_one_readonly_preflight",return_value=self._preflight()) as pre,
            patch.object(bridge.sender,"_pinned_source_commit",return_value=FAKE_COMMIT),
            patch.object(bridge,"LocalN8nOnePasswordCredential",return_value=lambda:FAKE_SECRET) as op,
            patch.object(bridge.sender,"run",side_effect=fake_send) as send,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(bridge.run(self.write),0)
        self.assertEqual(from_holder,[FAKE_SECRET])
        self.assertEqual(pre.call_count,2)
        op.assert_called_once_with(environment="LOCAL",approved_secret_reference=FAKE_REF)
        send.assert_called_once()
        self.assertNotIn(FAKE_SECRET,output.getvalue())
        self.assertNotIn(FAKE_REF,output.getvalue())

    def test_issuer_unavailable_stops_before_sending(self):
        from avuhz_worker.local_n8n_onepassword_credential import LocalN8nSecretUnavailable
        with (
            patch.dict(os.environ,ENV),
            patch.object(bridge.sender,"_one_readonly_preflight",return_value=self._preflight()),
            patch.object(bridge.sender,"_pinned_source_commit",return_value=FAKE_COMMIT),
            patch.object(bridge,"LocalN8nOnePasswordCredential",
                         return_value=lambda: (_ for _ in ()).throw(LocalN8nSecretUnavailable("do_not_expose"))),
            patch.object(bridge.sender,"run") as send,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(bridge.run(self.write),2)
        send.assert_not_called()
        self.assertNotIn("do_not_expose",output.getvalue())

    def test_sender_rejection_means_no_retry(self):
        for code in (2,1):
            with (
                self.subTest(code=code),
                patch.dict(os.environ,ENV),
                patch.object(bridge.sender,"_one_readonly_preflight",return_value=self._preflight()),
                patch.object(bridge.sender,"_pinned_source_commit",return_value=FAKE_COMMIT),
                patch.object(bridge,"LocalN8nOnePasswordCredential",return_value=lambda:FAKE_SECRET),
                patch.object(bridge.sender,"run",return_value=code) as send,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(bridge.run(self.write),2)
                send.assert_called_once()
                self.assertNotIn(FAKE_SECRET,output.getvalue())

    def test_runtime_drift_on_second_preflight_blocks_before_issuer(self):
        different=qa.QaReadback(
            "http://172.17.0.1:57777/v1/avuhz/local-n8n-receipts",
            20000, 0, 6, 1, 0, 0,
        )
        with (
            patch.dict(os.environ,ENV),
            patch.object(bridge.sender,"_one_readonly_preflight",side_effect=[
                self._preflight(),(different,self.event,self.digest),
            ]),
            patch.object(bridge.sender,"_pinned_source_commit",return_value=FAKE_COMMIT),
            patch.object(bridge,"LocalN8nOnePasswordCredential") as op,
            patch.object(bridge.sender,"run") as send,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(bridge.run(self.write),2)
        op.assert_called_once()
        op.return_value.assert_not_called()
        send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
