"""Synthetic safety tests for the source-only LOCAL receipt service wrapper."""
from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import secrets
import subprocess
import unittest
from unittest.mock import patch

from scripts import prepare_local_n8n_receipt_op_service_launcher as gate

TOKEN = secrets.token_urlsafe(45)
REF = "op://synthetic-vault/synthetic-item/password"
QA = "a4730000-0000-4000-8000-000000000001"
GATE_ID = "154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2"


def fixture_state():
    return gate.Preflight(
        tenant_id=QA, db_path=Path("/tmp/nonexistent-private-receipt-test.sqlite"),
        gateway="172.17.0.1", client="172.17.0.3",
        network_cidr="172.17.0.0/16",
        receiver_id="0068feb4c96bdb5f",
        receipt_credential_id=GATE_ID,
    )


class FakeServiceChild:
    def __init__(self, argv, **kw):
        self.argv = argv
        self.kw = kw
        self.saved_token = None
        self.returncode = None
        self.read_secret_fd = os.dup(kw["pass_fds"][0])
        reader, writer = os.pipe()
        self.stdout = os.fdopen(reader, "rb", buffering=0)
        os.write(writer, b"LOCAL_DEVELOPMENT_RECEIPT_BOUND_PRIVATE http://172.17.0.1:45901\n")
        os.close(writer)

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        data = []
        while True:
            chunk = os.read(self.read_secret_fd, 512)
            if not chunk:
                break
            data.append(chunk)
        os.close(self.read_secret_fd)
        self.saved_token = b"".join(data)
        self.returncode = 0
        return 0

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = -9


class LocalReceiptServiceLaunchTests(unittest.TestCase):
    def setUp(self):
        self.env = {"CI": "", "GITHUB_ACTIONS": "", "AVUHZ_ENVIRONMENT": "LOCAL"}
        self.default = ["--target",gate.TARGET]
        self.serve = self.default + [
            "--serve-one", "--approved-qa-tenant-id",QA,
            "--approved-receipt-credential-id",GATE_ID,
            "--approved-runner-sha256","sha256:"+gate.RUNNER_SHA256,
            "--approved-secret-reference", REF,
        ]

    def test_pinned_qa_fixture_is_fictional_not_real_owner_authority(self):
        self.assertEqual(gate._check_fictional_qa_fixture(), QA)
        with patch.object(gate,"_digest",return_value="badsha"):
            with self.assertRaises(ValueError):
                gate._check_fictional_qa_fixture()

    def test_default_never_reads_1password_or_starts_child(self):
        with (
            patch.dict(os.environ,self.env),
            patch.object(gate,"preflight",return_value=fixture_state()) as pf,
            patch.object(gate,"LocalN8nOnePasswordCredential") as provider,
            patch.object(gate,"start_once") as start,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(gate.run(self.default),0)
        pf.assert_called_once()
        provider.assert_not_called()
        start.assert_not_called()
        self.assertIn("read-only",out.getvalue())

    def test_live_preflight_uses_private_candidate_and_exact_qa_identity(self):
        from avuhz_worker.local_n8n_receipt_dev_runner import PrivateDockerBoundary
        with (
            patch.object(gate,"_digest",side_effect=[
                gate.RUNNER_SHA256,gate.FIXTURE_SHA256
            ]),
            patch.object(gate,"validate_storage_path") as paths,
            patch.object(gate,"inspect_private_local_n8n",return_value=PrivateDockerBoundary(
                "172.17.0.1","172.17.0.3","172.17.0.0/16"
            )) as network,
            patch.object(gate,"_check_receipt_n8n_metadata") as meta,
        ):
            result=gate.preflight()
        self.assertEqual(result.tenant_id,QA)
        self.assertEqual(result.db_path,Path.home()/gate.QA_DB_RELATIVE)
        self.assertEqual(result.receipt_credential_id,GATE_ID)
        paths.assert_called_once()
        network.assert_called_once()
        meta.assert_called_once()

    def test_wrong_environment_and_missing_approvals_block_provider(self):
        bad = [
            self.default + ["--serve-one"],
            self.default + ["--approved-qa-tenant-id", QA],
            self.default + ["--serve-one","--approved-qa-tenant-id",QA],
            ["--target","PRODUCTION"],
        ]
        for args in bad:
            with (
                self.subTest(args=args),
                patch.dict(os.environ,self.env),
                patch.object(gate,"preflight") as pf,
                patch.object(gate,"LocalN8nOnePasswordCredential") as provider,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(gate.run(args),2)
                pf.assert_not_called()
                provider.assert_not_called()
        for env_key, value in (
            ("CI","1"),("GITHUB_ACTIONS","true"),
            ("AVUHZ_ENVIRONMENT","PRODUCTION"),
            ("AVUHZ_ENVIRONMENT","TEST"),
        ):
            with (
                self.subTest(env_key=env_key),
                patch.dict(os.environ,{**self.env,env_key:value}),
                patch.object(gate,"preflight") as pf,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(gate.run(self.serve),2)
                pf.assert_not_called()

    def test_wrong_exact_approval_parameters_block_before_credential_read(self):
        for key,wrong in (
            ("--approved-qa-tenant-id","a4730000-0000-4000-8000-000000000099"),
            ("--approved-receipt-credential-id","made-up-id"),
            ("--approved-runner-sha256","sha256:"+"0"*64),
        ):
            args=self.serve[:]
            args[args.index(key)+1]=wrong
            with (
                self.subTest(key=key),
                patch.dict(os.environ,self.env),
                patch.object(gate,"preflight") as pf,
                patch.object(gate,"LocalN8nOnePasswordCredential") as provider,
                patch.object(gate,"start_once") as start,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(gate.run(args),2)
                pf.assert_not_called()
                start.assert_not_called()
                # Bad reference is rejected in the constructor if other
                # exact approvals match; never calls the issuer or server.
                provider.return_value.assert_not_called()

    def test_invalid_secret_reference_rejected_by_real_private_provider(self):
        args=self.serve[:]
        args[args.index("--approved-secret-reference")+1]="no/invalid/reference"
        with (
            patch.dict(os.environ,self.env),
            patch.object(gate,"preflight") as pf,
            patch.object(gate,"start_once") as start,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(gate.run(args),2)
        pf.assert_not_called()
        start.assert_not_called()
        self.assertNotIn("no/invalid/reference",out.getvalue())

    def test_preflight_drift_after_one_private_issuer_read_blocks_start(self):
        from dataclasses import replace
        original=fixture_state()
        modified=replace(original,client="172.17.0.44")
        with (
            patch.dict(os.environ,self.env),
            patch.object(gate,"preflight",side_effect=[original,modified]) as pf,
            patch.object(gate,"LocalN8nOnePasswordCredential") as provider,
            patch.object(gate,"start_once") as start,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            provider.return_value.return_value=TOKEN
            self.assertEqual(gate.run(self.serve),2)
        self.assertEqual(pf.call_count,2)
        provider.return_value.assert_called_once()
        start.assert_not_called()
        self.assertNotIn(TOKEN,out.getvalue())

    def test_approved_one_service_uses_one_private_secret_and_exact_state(self):
        state=fixture_state()
        with (
            patch.dict(os.environ,self.env),
            patch.object(gate,"preflight",return_value=state) as pf,
            patch.object(gate,"LocalN8nOnePasswordCredential") as provider,
            patch.object(gate,"start_once",return_value=0) as start,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            provider.return_value.return_value=TOKEN
            self.assertEqual(gate.run(self.serve),0)
        self.assertEqual(pf.call_count,2)
        provider.return_value.assert_called_once()
        start.assert_called_once_with(TOKEN,state)
        self.assertNotIn(TOKEN,out.getvalue())
        self.assertNotIn(REF,out.getvalue())

    def test_real_pipe_child_gets_exact_secret_fd_not_argument_or_env(self):
        created=[]
        def launch(args, **kw):
            child=FakeServiceChild(args,**kw)
            created.append(child)
            return child
        with (
            patch.object(gate.subprocess,"Popen",side_effect=launch),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(gate.start_once(TOKEN,fixture_state()),0)
        self.assertEqual(len(created),1)
        child=created[0]
        self.assertEqual(child.saved_token,TOKEN.encode("ascii"))
        self.assertEqual(child.kw["pass_fds"],(int(child.argv[-1]),))
        self.assertEqual(child.argv[-2],"--token-fd")
        self.assertEqual(child.kw["stdin"],subprocess.DEVNULL)
        self.assertEqual(child.kw["stderr"],subprocess.DEVNULL)
        self.assertEqual(child.kw["cwd"],str(gate.ROOT))
        self.assertEqual(child.kw["env"]["AVUHZ_ENVIRONMENT"],"LOCAL")
        self.assertNotIn(TOKEN,str(child.kw["env"]))
        self.assertNotIn(TOKEN,str(child.argv))
        self.assertNotIn("OP_SESSION",child.kw["env"])
        self.assertNotIn(TOKEN,out.getvalue())
        self.assertIn("172.17.0.1:45901",out.getvalue())

    def test_unexpected_child_startup_stops_that_child_without_retry(self):
        children=[]
        def bad_launch(args,**kw):
            child=FakeServiceChild(args,**kw)
            child.stdout.close()
            reader,writer=os.pipe()
            os.write(writer,b"UNTRUSTED STARTUP DETAIL\n")
            os.close(writer)
            child.stdout=os.fdopen(reader,"rb",buffering=0)
            children.append(child)
            return child
        with (
            patch.object(gate.subprocess,"Popen",side_effect=bad_launch) as launcher,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            with self.assertRaises(gate.LocalReceiptLaunchDenied):
                gate.start_once(TOKEN,fixture_state())
        self.assertEqual(launcher.call_count,1)
        self.assertEqual(children[0].returncode,0)
        self.assertEqual(children[0].saved_token,TOKEN.encode("ascii"))
        self.assertNotIn("UNTRUSTED",out.getvalue())
        self.assertNotIn(TOKEN,out.getvalue())

    def test_bad_secret_never_spawns_child(self):
        for token in ("short", "x"*513,"x"*36+"\n"):
            with (
                self.subTest(size=len(token)),
                patch.object(gate.subprocess,"Popen") as spawn,
            ):
                with self.assertRaises(gate.LocalReceiptLaunchDenied):
                    gate.start_once(token,fixture_state())
                spawn.assert_not_called()

    def test_untrusted_start_banner_fails_closed_without_echo(self):
        from unittest.mock import MagicMock
        for data in (
            b"Authorization: secret-value\n",
            b"LOCAL_DEVELOPMENT_RECEIPT_BOUND_PRIVATE http://0.0.0.0:45901\n",
            b"LOCAL_DEVELOPMENT_RECEIPT_BOUND_PRIVATE http://172.17.0.1:0\n",
            b"LOCAL_DEVELOPMENT_RECEIPT_BOUND_PRIVATE http://172.17.0.1:45901\nextra",
        ):
            reader,writer=os.pipe()
            try:
                os.write(writer,data)
                os.close(writer)
                writer=None
                child=MagicMock()
                child.stdout=os.fdopen(reader,"rb",buffering=0)
                reader=None
                child.poll.return_value=None
                with self.subTest(data=data[:20]):
                    with self.assertRaises(gate.LocalReceiptLaunchDenied):
                        gate._read_start_banner(child,"172.17.0.1")
            finally:
                if reader is not None: os.close(reader)
                if writer is not None: os.close(writer)
                child.stdout.close()


if __name__=="__main__":
    unittest.main()
