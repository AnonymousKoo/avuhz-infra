"""No credential or network mutations: file-descriptor-only gate safety tests."""
from __future__ import annotations

import contextlib
import io
import os
import pathlib
import secrets
import subprocess
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from scripts import prepare_shared_n8n_receiver_v2_header_credential_local as gate

TEST_TOKEN=secrets.token_urlsafe(40)  # generated only in-process per test run


def synthetic_snapshot(**replacements):
    baseline=gate.Snapshot(
        project_id="test-personal-project",
        workflow_digest="0"*64,
        workflow_count=3,
        credential_count=2,
        shared_credential_count=2,
        receiver_id="1234567890abcdef",
        receiver_credential_count=0,
        active_workflow_count=0,
        execution_count=0,
    )
    return replace(baseline,**replacements)


class HeaderCredentialGateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="avuhz-credential-test-")
        self.addCleanup(self.temp.cleanup)
        self.path=pathlib.Path(self.temp.name)/"fake-n8n.sqlite"
        self.baseline=synthetic_snapshot()
        self.env={"CI":"","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"LOCAL"}
        self.allowed=[
            "--target",gate.TARGET,
            "--import-one",
            "--approved-source-sha256","sha256:"+gate.SOURCE_SHA256,
            "--token-fd","43",
        ]

    def test_preflight_passed_against_real_local_n8n_without_secret(self):
        # This test only runs when a genuine machine has the approved LOCAL
        # n8n and installed receiver; on CI use independent mocked tests.
        with patch.object(gate,"preflight",return_value=(self.path,self.baseline)):
            with patch.object(gate,"import_once") as send,patch.dict(os.environ,self.env):
                with contextlib.redirect_stdout(io.StringIO()) as stdout:
                    status=gate.run(["--target",gate.TARGET])
        self.assertEqual(status,0)
        send.assert_not_called()
        self.assertIn("no resource changes",stdout.getvalue())
        self.assertNotIn(TEST_TOKEN,stdout.getvalue())
        self.assertNotIn(self.baseline.project_id,stdout.getvalue())

    def test_protected_context_denied_without_touching_source(self):
        for environment in (
            {"CI":"true","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"LOCAL"},
            {"CI":"","GITHUB_ACTIONS":"true","AVUHZ_ENVIRONMENT":"LOCAL"},
            {"CI":"","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"PRODUCTION"},
        ):
            with (
                self.subTest(environment=environment),
                patch.dict(os.environ,environment),
                patch.object(gate,"preflight") as before,
                patch.object(gate,"import_once") as import_one,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(gate.run(self.allowed),2)
                before.assert_not_called()
                import_one.assert_not_called()

    def test_source_digest_and_token_fd_required_before_preflight(self):
        for args in (
            ["--target",gate.TARGET,"--import-one","--token-fd","43"],
            ["--target",gate.TARGET,"--import-one",
             "--approved-source-sha256","sha256:"+gate.SOURCE_SHA256],
            ["--target",gate.TARGET,"--import-one",
             "--approved-source-sha256","sha256:"+"f"*64,"--token-fd","43"],
            ["--target",gate.TARGET,"--token-fd","43"],
            ["--target",gate.TARGET,
             "--approved-source-sha256","sha256:"+gate.SOURCE_SHA256],
            ["--target","PRODUCTION"],
        ):
            with (
                self.subTest(args=args),patch.dict(os.environ,self.env),
                patch.object(gate,"preflight") as before,
                patch.object(gate,"import_once") as send,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(gate.run(args),2)
                before.assert_not_called()
                send.assert_not_called()

    def test_secret_loaded_only_from_closed_private_fd(self):
        test_token=TEST_TOKEN.encode("ascii")
        read,write=os.pipe()
        os.write(write,test_token)
        os.close(write)
        self.assertEqual(gate.load_private_token(read),TEST_TOKEN)
        with self.assertRaises(gate.CredentialGateDenied):
            gate.load_private_token(read) # descriptor was closed

    def test_private_fd_chunked_reads_are_complete_and_never_log(self):
        # A private secrets provider may write the approved ASCII token in
        # several chunks. Do not accept only an initial prefix as the secret.
        parts=[TEST_TOKEN[:33].encode(),TEST_TOKEN[33:].encode(),b""]
        with patch.object(gate.os,"read",side_effect=parts) as read:
            with patch.object(gate.os,"close") as closed:
                self.assertEqual(gate.load_private_token(43),TEST_TOKEN)
        self.assertEqual(read.call_count,3)
        closed.assert_called_once_with(43)

    def test_bad_fds_and_unsafe_secret_are_denied(self):
        for fd in (-1,0,1,2,True,None,"3"):
            with self.subTest(fd=fd),self.assertRaises(gate.CredentialGateDenied):
                gate.load_private_token(fd)
        for invalid in (b"short",b"a"*31,b"a"*513,b"a"*40+b"\n",b"b"*30+b"\x00\x00"):
            rd,wr=os.pipe()
            os.write(wr,invalid)
            os.close(wr)
            with self.subTest(length=len(invalid)),self.assertRaises(gate.CredentialGateDenied):
                gate.load_private_token(rd)

    def test_single_encrypted_import_command_and_no_workflow_edits(self):
        captured=[]
        def only_cli(cmd,**kwargs):
            captured.append((cmd,kwargs))
            return subprocess.CompletedProcess(cmd,0,b"",b"")
        with patch.object(gate.subprocess,"run",side_effect=only_cli):
            gate.import_once("test-personal-project",TEST_TOKEN,"credential-uuid-local-only")
        self.assertEqual(len(captured),1)
        args,opts=captured[0]
        self.assertEqual(args,[
            "docker","exec","-i","n8n","n8n","import:credentials",
            "--input=/dev/stdin","--projectId=test-personal-project",
        ])
        import json
        document=json.loads(opts["input"])
        self.assertEqual(len(document),1)
        entry=document[0]
        self.assertEqual(entry["type"],"httpHeaderAuth")
        self.assertEqual(entry["name"],gate.CREDENTIAL_NAME)
        self.assertEqual(entry["data"]["name"],"X-Avuhz-Webhook-Token")
        self.assertEqual(entry["data"]["value"],TEST_TOKEN)
        self.assertNotIn("workflow",str(document))
        self.assertEqual(opts["timeout"],60)

    def test_provider_failures_no_retry_and_no_secret_in_error(self):
        for outcome in (
            subprocess.CompletedProcess([],1,b"SECRET",b"SECRET"),
        ):
            with patch.object(gate.subprocess,"run",return_value=outcome) as run:
                with self.assertRaisesRegex(gate.CredentialGateDenied,
                      "^single_encrypted_credential_import_unverified$") as ex:
                    gate.import_once("test-personal-project",TEST_TOKEN,"test-only-credential")
                self.assertNotIn(TEST_TOKEN,str(ex.exception))
                self.assertEqual(run.call_count,1)

    def test_exact_opt_in_validates_full_postcondition_and_one_import(self):
        cid="61e70000-0000-4000-8000-000000000001"
        after=synthetic_snapshot(
            credential_count=3,shared_credential_count=3,
            receiver_credential_count=1,
        )
        with (
            patch.dict(os.environ,self.env),
            patch.object(gate,"preflight",return_value=(self.path,self.baseline)),
            patch.object(gate,"load_private_token",return_value=TEST_TOKEN) as token,
            patch.object(gate.uuid,"uuid4",return_value=cid),
            patch.object(gate,"import_once") as do_import,
            patch.object(gate,"read_only_snapshot",return_value=after) as postcheck,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            status=gate.run(self.allowed)
        self.assertEqual(status,0)
        token.assert_called_once_with(43)
        do_import.assert_called_once_with("test-personal-project",TEST_TOKEN,cid)
        postcheck.assert_called_once_with(self.path,require_credential=True,expected_id=cid)
        self.assertNotIn(TEST_TOKEN,out.getvalue())
        self.assertNotIn(cid,out.getvalue())
        self.assertIn("credential NOT bound",out.getvalue())

    def test_drift_after_import_denied_without_retry(self):
        for changes in (
            {"workflow_digest":"1"*64},
            {"workflow_count":4},
            {"receiver_id":"different"},
            {"credential_count":4},
            {"shared_credential_count":4},
            {"receiver_credential_count":0},
            {"active_workflow_count":1},
            {"execution_count":1},
        ):
            after=synthetic_snapshot(
                credential_count=3,shared_credential_count=3,
                receiver_credential_count=1,**{
                    key:value for key,value in changes.items()
                    if key not in ("credential_count","shared_credential_count",
                                   "receiver_credential_count")
                }
            )
            # explicit overrides for potentially repeated kwargs
            after=replace(after,**changes)
            with (
                self.subTest(changes=changes),
                patch.dict(os.environ,self.env),
                patch.object(gate,"preflight",
                             return_value=(self.path,self.baseline)),
                patch.object(gate,"load_private_token",return_value=TEST_TOKEN),
                patch.object(gate,"import_once") as do_import,
                patch.object(gate,"read_only_snapshot",return_value=after),
                contextlib.redirect_stdout(io.StringIO()) as out,
            ):
                status=gate.run(self.allowed)
                self.assertEqual(status,2)
                self.assertEqual(do_import.call_count,1)
                self.assertIn("BLOCKED single_credential_postcondition_denied",
                              out.getvalue())
                self.assertNotIn(TEST_TOKEN,out.getvalue())


if __name__=="__main__":
    unittest.main()
