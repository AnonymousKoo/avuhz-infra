"""Offline safety tests for source-only LOCAL n8n credential-reference binding."""
from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import sqlite3
import subprocess
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from scripts import prepare_shared_n8n_receiver_v2_header_binding_local as binding


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="avuhz-binding-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.dbfile = pathlib.Path(self.temp.name) / "synthetic.sqlite"
        self.source = binding.receiver_source._source()
        self.receiver = "abc123def456gh78"
        self.credential = "fake-credential-id"
        self.project = "synthetic-personal-project"
        source_nodes = json.dumps(self.source["nodes"], sort_keys=True)
        source_edges = json.dumps(self.source["connections"], sort_keys=True)
        source_settings = json.dumps(self.source["settings"], sort_keys=True)
        self.receiver_row = (
            self.receiver, self.source["name"], 0, source_nodes,
            source_edges, source_settings, None, None,
        )
        self.other_row = (
            "other-id", "Other inactive workflow", 0, "[]", "{}",
            "{}", None, None,
        )
        self.rows = tuple(sorted([self.receiver_row, self.other_row]))
        self.sharing = ((self.receiver, self.project, "workflow:owner"),)
        self.state = binding.State(
            self.dbfile, self.receiver, self.credential, self.project,
            self.rows, 1, 1, 0, 0, self.sharing,
        )
        self.default_args = ["--target", binding.TARGET]
        self.write_args = self.default_args + [
            "--bind-one", "--approved-source-sha256",
            binding.EXPECTED_SOURCE_DIGEST,
            "--approved-receiver-id", self.receiver,
            "--approved-credential-id", self.credential,
        ]
        self.local_env = {
            "AVUHZ_ENVIRONMENT": "LOCAL", "CI": "", "GITHUB_ACTIONS": ""
        }

    def test_safe_default_does_not_import_or_modify(self):
        with (
            patch.dict(os.environ, self.local_env),
            patch.object(binding, "preflight", return_value=(self.state, self.source)),
            patch.object(binding, "bind_once") as bind,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            result = binding.run(self.default_args)
        self.assertEqual(result, 0)
        bind.assert_not_called()
        self.assertIn("read-only", output.getvalue())

    def test_disallow_production_ci_and_wrong_namespace_before_preflight(self):
        for env in ("PRODUCTION", "DEVELOPMENT"):
            with (
                patch.dict(os.environ, {**self.local_env, "AVUHZ_ENVIRONMENT": env}),
                patch.object(binding, "preflight") as preflight,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(binding.run(self.write_args), 2)
                preflight.assert_not_called()
        for flag in ("CI", "GITHUB_ACTIONS"):
            with (
                patch.dict(os.environ, {**self.local_env, flag: "true"}),
                patch.object(binding, "preflight") as preflight,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(binding.run(self.write_args), 2)
                preflight.assert_not_called()
        with (
            patch.dict(os.environ, self.local_env),
            patch.object(binding, "preflight") as preflight,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(binding.run(["--target", "PRODUCTION"]), 2)
            preflight.assert_not_called()

    def test_separate_exact_id_and_source_approval_required(self):
        bad = [
            self.default_args + ["--bind-one"],
            self.default_args + ["--approved-credential-id", self.credential],
            self.write_args[:-2],
            self.write_args[:-4] + ["--approved-source-sha256", "sha256:" + "0"*64],
        ]
        for args in bad:
            with (
                self.subTest(args=args),
                patch.dict(os.environ, self.local_env),
                patch.object(binding, "preflight") as preflight,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(binding.run(args), 2)
                preflight.assert_not_called()

    def test_exact_identity_mismatch_prevents_import(self):
        for flag, value in (
            ("--approved-receiver-id", "different-receiver"),
            ("--approved-credential-id", "different-credential"),
        ):
            args = self.write_args[:]
            args[args.index(flag) + 1] = value
            with (
                patch.dict(os.environ, self.local_env),
                patch.object(binding, "preflight", return_value=(self.state, self.source)),
                patch.object(binding, "bind_once") as importer,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(binding.run(args), 2)
                importer.assert_not_called()

    def test_binding_payload_touches_only_webhook_credential_reference(self):
        doc = binding.binding_document(self.state, self.source)
        self.assertEqual(doc["id"], self.receiver)
        self.assertIs(doc["active"], False)
        self.assertEqual(doc["nodes"][0]["credentials"], {
            "httpHeaderAuth": {
                "id": self.credential,
                "name": binding.credential_gate.CREDENTIAL_NAME,
            }
        })
        self.assertEqual(doc["nodes"][1:], self.source["nodes"][1:])
        self.assertEqual(doc["connections"], self.source["connections"])
        self.assertEqual(doc["settings"], self.source["settings"])
        self.assertNotIn("credentials", self.source["nodes"][0])

    def test_single_import_uses_native_cli_with_no_secret(self):
        captured = []
        def fake_run(command, **kwargs):
            captured.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, b"", b"")
        with patch.object(binding.subprocess, "run", side_effect=fake_run):
            binding.bind_once(self.state, self.source)
        self.assertEqual(len(captured), 1)
        cmd, kwargs = captured[0]
        self.assertEqual(cmd, [
            "docker", "exec", "-i", "n8n", "n8n", "import:workflow",
            "--input=/dev/stdin", "--projectId=" + self.project,
        ])
        self.assertNotIn("op://", str(cmd))
        self.assertNotIn("password", str(cmd).lower())
        doc = json.loads(kwargs["input"])
        self.assertEqual(len(doc), 1)
        self.assertEqual(doc[0], binding.binding_document(self.state, self.source))
        self.assertEqual(kwargs["timeout"], 60)

    def test_one_attempt_on_import_failure_with_sanitized_error(self):
        with patch.object(binding.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 1, b"secret-like content", b"secret-like content"
        )) as run:
            with self.assertRaises(binding.BindingDenied) as error:
                binding.bind_once(self.state, self.source)
        self.assertEqual(run.call_count, 1)
        self.assertNotIn("secret-like content", str(error.exception))

    def test_write_path_exactly_one_import_two_preflights_and_postcheck(self):
        with (
            patch.dict(os.environ, self.local_env),
            patch.object(binding, "preflight", return_value=(self.state, self.source)) as preflight,
            patch.object(binding, "bind_once") as import_once,
            patch.object(binding, "postcondition", return_value=True) as verify,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(binding.run(self.write_args), 0)
        self.assertEqual(preflight.call_count, 2)
        import_once.assert_called_once_with(self.state, self.source)
        verify.assert_called_once_with(self.state, self.source)
        self.assertIn("inactive", output.getvalue())
        self.assertNotIn(self.credential, output.getvalue())

    def test_ambiguous_postcondition_no_retry_or_rollback(self):
        with (
            patch.dict(os.environ, self.local_env),
            patch.object(binding, "preflight", return_value=(self.state, self.source)),
            patch.object(binding, "bind_once") as importer,
            patch.object(binding, "postcondition", return_value=False),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(binding.run(self.write_args), 2)
        importer.assert_called_once()
        self.assertIn("no retry", output.getvalue())

    def _sqlite(self, *, bound: bool, drift: bool = False, active: bool = False):
        source_nodes = binding.binding_document(self.state, self.source)["nodes"] if bound else self.source["nodes"]
        receiver = list(self.receiver_row)
        receiver[3] = json.dumps(source_nodes)
        receiver[2] = 1 if active else 0
        other = list(self.other_row)
        if drift:
            other[3] = json.dumps([{"unauthorized": True}])
        with sqlite3.connect(self.dbfile) as db:
            db.executescript("""
                CREATE TABLE workflow_entity(id TEXT, name TEXT, active INTEGER, nodes TEXT,
                  connections TEXT, settings TEXT, staticData TEXT, pinData TEXT);
                CREATE TABLE credentials_entity(id TEXT,name TEXT,type TEXT);
                CREATE TABLE shared_credentials(credentialsId TEXT,projectId TEXT);
                CREATE TABLE webhook_entity(id TEXT);
                CREATE TABLE execution_entity(id TEXT);
                CREATE TABLE shared_workflow(workflowId TEXT,projectId TEXT,role TEXT);
            """)
            db.executemany("INSERT INTO workflow_entity VALUES(?,?,?,?,?,?,?,?)", [receiver, other])
            db.execute("INSERT INTO credentials_entity VALUES(?,?,?)", (
                self.credential, binding.credential_gate.CREDENTIAL_NAME,
                binding.credential_gate.CREDENTIAL_TYPE,
            ))
            db.execute("INSERT INTO shared_credentials VALUES(?,?)", (
                self.credential, self.project,
            ))
            db.execute("INSERT INTO shared_workflow VALUES(?,?,?)", self.sharing[0])

    def test_independent_read_only_postcondition_accepts_only_one_binding(self):
        self._sqlite(bound=True)
        self.assertTrue(binding.postcondition(self.state, self.source))

    def test_independent_postcondition_denies_no_binding(self):
        self._sqlite(bound=False)
        self.assertFalse(binding.postcondition(self.state, self.source))

    def test_independent_postcondition_denies_other_workflow_drift(self):
        self._sqlite(bound=True, drift=True)
        self.assertFalse(binding.postcondition(self.state, self.source))

    def test_independent_postcondition_denies_activation(self):
        self._sqlite(bound=True, active=True)
        self.assertFalse(binding.postcondition(self.state, self.source))


if __name__ == "__main__":
    unittest.main()
