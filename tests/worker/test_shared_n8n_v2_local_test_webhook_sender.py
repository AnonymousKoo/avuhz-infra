"""Offline safety proof for one private-FD LOCAL native test-webhook delivery."""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import unittest
from unittest.mock import Mock, patch

from scripts import prepare_shared_n8n_v2_local_test_webhook_sender as sender
from scripts import prepare_shared_n8n_v2_local_first_event_qa as qa

LOCAL = {"CI": "", "GITHUB_ACTIONS": "", "AVUHZ_ENVIRONMENT": "LOCAL"}
COMMIT = "a"*40


class OneNativeTestWebhookSendTests(unittest.TestCase):
    def setUp(self):
        self.event = qa.fictional_event()
        self.digest = qa._digest(self.event)
        self.before = qa.QaReadback(
            "http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts",
            1939646, 0, 6, 1, 0, 0,
        )
        self.after = qa.QaReadback(
            self.before.endpoint, self.before.listener_pid, 1, 6, 1, 0, 0,
        )
        self.defaults = ["--target", sender.TARGET]
        self.approved = self.defaults + [
            "--send-one",
            "--approved-receiver-id", sender.RECEIVER_ID,
            "--approved-test-url", sender.TEST_URL,
            "--approved-receipt-endpoint", self.before.endpoint,
            "--approved-source-sha256", sender.SOURCE_SHA256,
            "--approved-source-commit", COMMIT,
            "--approved-event-digest", "sha256:"+self.digest,
            "--token-fd", "7",
        ]

    def _preflight(self):
        return (self.before, self.event, self.digest)

    def _test_args(self, *, token_fd=7):
        args=self.approved[:]
        args[args.index("--token-fd")+1]=str(token_fd)
        return args

    def _pipe(self):
        rd,wr=os.pipe()
        os.write(wr,b"test-only-synthetic-authorized-inbound-token-12345678")
        os.close(wr)
        self.addCleanup(lambda: os.close(rd) if rd in _open_fd_set() else None)
        return rd

    def test_default_read_only_no_secret_or_http(self):
        with (
            patch.dict(os.environ,LOCAL),
            patch.object(sender,"_one_readonly_preflight",return_value=self._preflight()),
            patch.object(sender,"_read_inbound_from_fd") as rd,
            patch.object(sender,"_post_one") as post,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(sender.run(self.defaults),0)
        rd.assert_not_called()
        post.assert_not_called()
        self.assertIn("no credential access",out.getvalue())

    def test_default_refuses_approval_flags_and_never_reads_token(self):
        with (
            patch.dict(os.environ,LOCAL),
            patch.object(sender,"_read_inbound_from_fd") as rd,
            patch.object(sender,"_post_one") as post,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(sender.run(self.defaults+["--token-fd","7"]),2)
        rd.assert_not_called()
        post.assert_not_called()
        self.assertIn("BLOCKED",out.getvalue())

    def test_ci_production_test_wrong_target_rejected_before_preflight(self):
        cases = [
            (self.defaults,{"AVUHZ_ENVIRONMENT":"PRODUCTION"}),
            (self.defaults,{"AVUHZ_ENVIRONMENT":"DEVELOPMENT"}),
            (self.defaults,{"AVUHZ_ENVIRONMENT":"TEST"}),
            (self.defaults,{"CI":"true"}),
            (self.defaults,{"GITHUB_ACTIONS":"true"}),
            (["--target","PRODUCTION"],{}),
        ]
        for args,env in cases:
            with (
                self.subTest(env=env),
                patch.dict(os.environ,{**LOCAL,**env}),
                patch.object(sender,"_one_readonly_preflight") as pre,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(sender.run(args),2)
                pre.assert_not_called()

    def test_exact_approval_required_before_issuer_fd_read(self):
        for flag,wrong in [
            ("--approved-receiver-id","bad"),
            ("--approved-test-url","http://127.0.0.1:5678/webhook/avuhz-events"),
            ("--approved-test-url","http://example.com/webhook-test/avuhz-events"),
            ("--approved-receipt-endpoint","http://172.17.0.1:9999/v1/avuhz/local-n8n-receipts"),
            ("--approved-source-sha256","sha256:"+"0"*64),
            ("--approved-event-digest","sha256:"+"0"*64),
        ]:
            args=self.approved[:]
            args[args.index(flag)+1]=wrong
            with (
                self.subTest(flag=flag),
                patch.dict(os.environ,LOCAL),
                patch.object(sender,"_one_readonly_preflight",return_value=self._preflight()),
                patch.object(sender,"_read_inbound_from_fd") as rd,
                patch.object(sender,"_post_one") as post,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(sender.run(args),2)
                rd.assert_not_called()
                post.assert_not_called()

    def test_source_commit_mismatch_rejects_before_secret(self):
        with (
            patch.dict(os.environ,LOCAL),
            patch.object(sender,"_one_readonly_preflight",return_value=self._preflight()),
            patch.object(sender,"_pinned_source_commit",return_value="b"*40),
            patch.object(sender,"_read_inbound_from_fd") as rd,
            patch.object(sender,"_post_one") as post,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(sender.run(self.approved),2)
        rd.assert_not_called()
        post.assert_not_called()

    def test_service_change_between_preflights_denies_before_secret(self):
        changed=(qa.QaReadback(
            "http://172.17.0.1:50011/v1/avuhz/local-n8n-receipts",
            25001,0,6,1,0,0,
        ),self.event,self.digest)
        with (
            patch.dict(os.environ,LOCAL),
            patch.object(sender,"_one_readonly_preflight",side_effect=[self._preflight(),changed]),
            patch.object(sender,"_pinned_source_commit",return_value=COMMIT),
            patch.object(sender,"_read_inbound_from_fd") as rd,
            patch.object(sender,"_post_one") as post,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(sender.run(self.approved),2)
        rd.assert_not_called()
        post.assert_not_called()

    def test_exact_approval_consumes_one_fd_and_calls_one_post(self):
        token="only-in-memory-test-secret-abcdefghijklmnopqrstuvwxyz"
        with (
            patch.dict(os.environ,LOCAL),
            patch.object(sender,"_one_readonly_preflight",return_value=self._preflight()) as pre,
            patch.object(sender,"_pinned_source_commit",return_value=COMMIT),
            patch.object(sender,"_read_inbound_from_fd",return_value=token) as rd,
            patch.object(sender,"_post_one",return_value=True) as post,
            patch.object(sender.qa,"preflight",return_value=self.after) as verify,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(sender.run(self.approved),0)
        self.assertEqual(pre.call_count,2)
        rd.assert_called_once_with(7)
        post.assert_called_once_with(event=self.event,token=token)
        verify.assert_called_once_with(expect_one=True)
        self.assertNotIn(token,out.getvalue())
        self.assertIn("NOT CERTIFIED",out.getvalue())

    def test_post_approval_denial_never_retries(self):
        for result in (False,sender.TestWebhookSendDenied("ambiguous")):
            with (
                self.subTest(result=repr(result)),
                patch.dict(os.environ,LOCAL),
                patch.object(sender,"_one_readonly_preflight",return_value=self._preflight()),
                patch.object(sender,"_pinned_source_commit",return_value=COMMIT),
                patch.object(sender,"_read_inbound_from_fd",return_value="test-private-token-1234567890123456789"),
                patch.object(sender,"_post_one",side_effect=[result] if isinstance(result,Exception) else None,
                             return_value=result if not isinstance(result,Exception) else None) as post,
                patch.object(sender.qa,"preflight") as verify,
                contextlib.redirect_stdout(io.StringIO()) as out,
            ):
                self.assertEqual(sender.run(self.approved),2)
            post.assert_called_once()
            verify.assert_not_called()
            self.assertNotIn("test-private-token",out.getvalue())

    def test_ambiguous_postcondition_after_send_never_retries(self):
        with (
            patch.dict(os.environ,LOCAL),
            patch.object(sender,"_one_readonly_preflight",return_value=self._preflight()),
            patch.object(sender,"_pinned_source_commit",return_value=COMMIT),
            patch.object(sender,"_read_inbound_from_fd",return_value="test-private-token-1234567890123456789"),
            patch.object(sender,"_post_one",return_value=True) as post,
            patch.object(sender.qa,"preflight",side_effect=qa.FirstEventQaDenied("not_proven")),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(sender.run(self.approved),2)
        post.assert_called_once()

    def test_fd_requires_private_anonymous_secret(self):
        rd,wr=os.pipe()
        try:
            os.write(wr,b"x"*31)
            os.close(wr);wr=-1
            with self.assertRaises(sender.TestWebhookSendDenied):
                sender._read_inbound_from_fd(rd)
            rd=-1
        finally:
            if rd>=0:os.close(rd)
            if wr>=0:os.close(wr)
        rd,wr=os.pipe()
        try:
            secret="example-only-private-FD-token-1234567890123456789"
            os.write(wr,secret.encode("ascii"))
            os.close(wr);wr=-1
            self.assertEqual(sender._read_inbound_from_fd(rd),secret)
            rd=-1
        finally:
            if rd>=0:os.close(rd)
            if wr>=0:os.close(wr)

    def test_raw_http_posts_once_to_exact_loopback_test_url(self):
        token="one-time-synthetic-token-123456789012345678901"
        conn=Mock()
        resp=Mock()
        resp.status=202
        resp.getheader.return_value="17"
        resp.read.return_value=b'{"accepted":true}'
        conn.getresponse.return_value=resp
        with patch.object(sender.http.client,"HTTPConnection",return_value=conn) as cls:
            self.assertTrue(sender._post_one(event=self.event,token=token))
        cls.assert_called_once_with("127.0.0.1",5678,timeout=8)
        conn.request.assert_called_once()
        method,url=conn.request.call_args.args[:2]
        data=conn.request.call_args.kwargs["body"]
        headers=conn.request.call_args.kwargs["headers"]
        self.assertEqual((method,url),("POST","/webhook-test/avuhz-events"))
        self.assertEqual(json.loads(data),self.event)
        self.assertEqual(headers[sender.inbound.HEADER_NAME],token)
        self.assertEqual(headers["X-Avuhz-Delivery-Key"],qa.QA_DELIVERY_KEY)
        conn.close.assert_called_once()

    def test_wrong_status_or_response_cannot_prove_commit(self):
        for code,data in (
            (404,b'{"accepted":true}'),
            (401,b'{"accepted":true}'),
            (202,b'{"accepted":false}'),
            (202,b'{"accepted":true,"extra":1}'),
            (202,b'garbage'),
        ):
            response=Mock(status=code)
            response.getheader.return_value=None
            response.read.return_value=data
            conn=Mock()
            conn.getresponse.return_value=response
            with (
                self.subTest(code=code),
                patch.object(sender.http.client,"HTTPConnection",return_value=conn),
            ):
                self.assertFalse(sender._post_one(
                    event=self.event,token="one-time-synthetic-token-123456789012345678901"
                ))
            conn.request.assert_called_once()

    def test_http_timeout_ambiguous_and_no_second_request(self):
        conn=Mock()
        conn.request.side_effect=OSError("sensitive_network_data")
        with patch.object(sender.http.client,"HTTPConnection",return_value=conn):
            with self.assertRaises(sender.TestWebhookSendDenied) as e:
                sender._post_one(event=self.event,token="only-in-memory-token-123456789012345")
        self.assertNotIn("sensitive_network_data",str(e.exception))
        conn.request.assert_called_once()


if __name__ == "__main__":
    unittest.main()
