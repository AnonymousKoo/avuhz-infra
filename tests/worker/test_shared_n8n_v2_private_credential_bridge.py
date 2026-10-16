"""Exact private-FD-only LOCAL secret-to-encrypted-importer tests.

No real 1Password access, no n8n installation or secret value in source.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import unittest
from unittest.mock import patch

from scripts import prepare_shared_n8n_v2_op_to_encrypted_credential_local as bridge

DUMMY_REFERENCE="op://fixturevault/fixtureitem/fixturefield"
DUMMY_TOKEN=secrets.token_urlsafe(40)
SHA="sha256:"+bridge.gate.SOURCE_SHA256


class FakeImporter:
    """Take custody of exactly the FD inherited by a single subprocess."""
    def __init__(self, args, **kwargs):
        self.args=args
        self.kwargs=kwargs
        self.reader=os.dup(kwargs["pass_fds"][0])
        self.returncode=None
        self.received=None

    def communicate(self, timeout=None):
        chunks=[]
        while True:
            chunk=os.read(self.reader,1024)
            if not chunk:break
            chunks.append(chunk)
        os.close(self.reader)
        self.received=b"".join(chunks)
        self.returncode=0
        return (
            b"PASS exactly one n8n-encrypted LOCAL shared receiver header credential imported\n"
            b"PASS all workflows unchanged, inactive, zero executions; credential NOT bound\n",
            b"",
        )

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode=-9


class PrivateCredentialBridgeTests(unittest.TestCase):
    def setUp(self):
        self.env={"CI":"","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"LOCAL"}
        self.safe=["--target",bridge.gate.TARGET]
        self.write=self.safe+[
            "--import-one","--approved-source-sha256",SHA,
            "--approved-secret-reference",DUMMY_REFERENCE,
        ]

    def test_default_preflight_performs_no_provider_calls(self):
        with (
            patch.dict(os.environ,self.env),
            patch.object(bridge.gate,"preflight",return_value=(Path("/tmp/unused"),object()))
            as before,
            patch.object(bridge,"LocalN8nOnePasswordCredential") as provider,
            patch.object(bridge,"import_private_fd_once") as importer,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(bridge.run(self.safe),0)
        before.assert_called_once()
        provider.assert_not_called()
        importer.assert_not_called()
        self.assertIn("no 1Password secret read",output.getvalue())

    def test_missing_approval_and_production_or_ci_never_read(self):
        options=(
            self.safe+["--import-one"],
            self.safe+["--import-one","--approved-secret-reference",DUMMY_REFERENCE],
            self.safe+["--import-one","--approved-source-sha256",SHA],
            self.safe+["--approved-secret-reference",DUMMY_REFERENCE],
            self.safe+["--approved-source-sha256",SHA],
            ["--target","PRODUCTION"],
            self.safe+["--import-one","--approved-source-sha256","sha256:"+"a"*64,
                       "--approved-secret-reference",DUMMY_REFERENCE],
            self.safe+["--import-one","--approved-source-sha256",SHA,
                       "--approved-secret-reference","op://vault/item/field;evil"],
        )
        for args in options:
            with (
                self.subTest(args=args),
                patch.dict(os.environ,self.env),
                patch.object(bridge.gate,"preflight") as before,
                patch.object(bridge,"import_private_fd_once") as importer,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(bridge.run(args),2)
                before.assert_not_called()
                importer.assert_not_called()
        for var,val in (
            ("CI","true"),("GITHUB_ACTIONS","true"),
            ("AVUHZ_ENVIRONMENT","PRODUCTION"),
        ):
            with (
                self.subTest(env=var),
                patch.dict(os.environ,{**self.env,var:val}),
                patch.object(bridge.gate,"preflight") as before,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(bridge.run(self.write),2)
                before.assert_not_called()

    def test_one_private_pipe_one_subprocess_never_token_in_argv(self):
        imports=[]
        def launch(args,**kwargs):
            obj=FakeImporter(args,**kwargs)
            imports.append(obj)
            return obj
        with patch.object(bridge.subprocess,"Popen",side_effect=launch):
            bridge.import_private_fd_once(DUMMY_TOKEN,source_sha256=SHA)
        self.assertEqual(len(imports),1)
        p=imports[0]
        self.assertEqual(p.received,DUMMY_TOKEN.encode("ascii"))
        self.assertEqual(p.args[0],__import__("sys").executable)
        self.assertEqual(p.args[1],str(bridge.IMPORTER))
        self.assertIn("--import-one",p.args)
        self.assertIn("--token-fd",p.args)
        self.assertEqual(p.kwargs["cwd"],str(bridge.ROOT))
        self.assertEqual(p.kwargs["stdin"],subprocess.DEVNULL)
        self.assertEqual(p.kwargs["stdout"],subprocess.PIPE)
        self.assertEqual(p.kwargs["stderr"],subprocess.DEVNULL)
        self.assertNotIn(DUMMY_TOKEN,str(p.args))
        self.assertNotIn(DUMMY_TOKEN,str(p.kwargs))
        self.assertEqual(len(p.kwargs["pass_fds"]),1)

    def test_invalid_secret_or_source_never_creates_a_pipe(self):
        for bad,sha in (
            ("short",SHA),("x"*513,SHA),
            ("z"*31,SHA),("z"*35+"\n",SHA),
            (DUMMY_TOKEN,"sha256:"+"0"*64),
        ):
            with (
                self.subTest(length=len(bad),sha=sha),
                patch.object(bridge.os,"pipe") as pipe,
                self.assertRaisesRegex(bridge.BridgeDenied,
                                       "^private_import_boundary_denied$"),
            ):
                bridge.import_private_fd_once(bad,source_sha256=sha)
            pipe.assert_not_called()

    def test_importer_failure_does_not_retry_or_echo_private_data(self):
        class FailingImporter(FakeImporter):
            def communicate(self, timeout=None):
                super().communicate(timeout=timeout)
                self.returncode=2
                return (b"hidden sensitive diagnostic",b"")
        created=[]
        def launch(args,**kwargs):
            p=FailingImporter(args,**kwargs)
            created.append(p)
            return p
        with patch.object(bridge.subprocess,"Popen",side_effect=launch):
            with self.assertRaisesRegex(
                bridge.BridgeDenied,"^single_importer_postcondition_unverified$",
            ) as context:
                bridge.import_private_fd_once(DUMMY_TOKEN,source_sha256=SHA)
        self.assertEqual(len(created),1)
        self.assertEqual(created[0].received,DUMMY_TOKEN.encode("ascii"))
        self.assertNotIn(DUMMY_TOKEN,str(context.exception))
        self.assertNotIn("hidden",str(context.exception))

    def test_one_approved_run_reads_issuer_once_and_invokes_one_import(self):
        with (
            patch.dict(os.environ,self.env),
            patch.object(bridge.gate,"preflight",
                         return_value=(Path("/tmp/unused"),object())),
            patch.object(bridge,"LocalN8nOnePasswordCredential") as provider,
            patch.object(bridge,"import_private_fd_once") as importer,
            patch.object(bridge,"postcheck_exact_increment",return_value=True)
            as postcheck,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            provider.return_value.return_value=DUMMY_TOKEN
            self.assertEqual(bridge.run(self.write),0)
        provider.assert_called_once_with(
            environment="LOCAL",approved_secret_reference=DUMMY_REFERENCE,
        )
        provider.return_value.assert_called_once_with()
        importer.assert_called_once_with(DUMMY_TOKEN,source_sha256=SHA)
        postcheck.assert_called_once()
        self.assertIn("one encrypted LOCAL n8n credential",output.getvalue())
        self.assertNotIn(DUMMY_TOKEN,output.getvalue())
        self.assertNotIn(DUMMY_REFERENCE,output.getvalue())

    def test_secret_unavailable_stops_before_import(self):
        with (
            patch.dict(os.environ,self.env),
            patch.object(bridge.gate,"preflight",
                         return_value=(Path("/tmp/unused"),object())),
            patch.object(bridge,"LocalN8nOnePasswordCredential") as provider,
            patch.object(bridge,"import_private_fd_once") as importer,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            provider.return_value.side_effect=bridge.LocalN8nSecretUnavailable(
                "some private credential error",
            )
            self.assertEqual(bridge.run(self.write),2)
        importer.assert_not_called()
        self.assertNotIn("private credential",output.getvalue())

    def test_importer_failure_or_postcheck_drift_denied_without_retry(self):
        for failure in ("import","postcheck"):
            with (
                self.subTest(failure=failure),
                patch.dict(os.environ,self.env),
                patch.object(bridge.gate,"preflight",
                             return_value=(Path("/tmp/unused"),object())),
                patch.object(bridge,"LocalN8nOnePasswordCredential") as provider,
                patch.object(bridge,"import_private_fd_once") as importer,
                patch.object(bridge,"postcheck_exact_increment",
                             return_value=False) as postcheck,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                provider.return_value.return_value=DUMMY_TOKEN
                if failure=="import":
                    importer.side_effect=bridge.BridgeDenied("private failure")
                self.assertEqual(bridge.run(self.write),2)
                importer.assert_called_once()
                if failure=="import":postcheck.assert_not_called()
                self.assertNotIn(DUMMY_TOKEN,output.getvalue())


if __name__=="__main__":
    unittest.main()
