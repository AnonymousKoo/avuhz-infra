"""Offline fail-closed tests for one inactive LOCAL n8n receipt HTTP node binding."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from scripts import prepare_shared_n8n_v2_local_receipt_node_binding as gate

RECEIVER = gate.RECEIVER_ID
RECEIPT_ID = gate.RECEIPT_ID
SOURCE_DIGEST = "sha256:" + gate.source_gate.SOURCE_SHA256
ENDPOINT = "http://172.17.0.1:37891" + gate.RECEIPT_ROUTE
ENV = {"CI": "", "GITHUB_ACTIONS": "", "AVUHZ_ENVIRONMENT": "LOCAL"}


class LocalReceiptBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="avuhz-synthetic-receipt-node-")
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "n8n.sqlite"
        self.storage = Path(self.temp.name) / "receipts.sqlite"
        self.source = gate.source_gate._source()
        self.project = "fictional-personal-project"
        inbound_id = "synthetic-inbound-credential"
        nodes = copy.deepcopy(self.source["nodes"])
        nodes[0]["credentials"] = {
            gate.inbound_gate.CREDENTIAL_TYPE: {
                "id": inbound_id, "name": gate.inbound_gate.CREDENTIAL_NAME
            }
        }
        self.inbound = inbound_id
        self.rows = tuple(sorted((
            ("another-01", "Other inactive workflow", 0, "[]", "{}", "{}", None, None),
            (RECEIVER, self.source["name"], 0, json.dumps(nodes),
             json.dumps(self.source["connections"]), json.dumps(self.source["settings"]), None, None),
        )))
        self.creds = tuple(sorted((
            (inbound_id, gate.inbound_gate.CREDENTIAL_NAME, "httpHeaderAuth", 200, "a"),
            (RECEIPT_ID, gate.RECEIPT_NAME, "httpHeaderAuth", 200, "b"),
        )))
        self.cred_shares = tuple(sorted((
            (inbound_id, self.project, "credential:owner"),
            (RECEIPT_ID, self.project, "credential:owner"),
        )))
        self.wf_shares = ((RECEIVER, self.project, "workflow:owner"),)
        self.state = gate.Snapshot(
            self.db, RECEIVER, self.project, ENDPOINT, 1234, self.storage,
            self.rows, self.creds, self.cred_shares, self.wf_shares, 0, 0,
        )
        self.default = ["--target", gate.TARGET]
        self.write = self.default + [
            "--bind-one", "--approved-receiver-id", RECEIVER,
            "--approved-receipt-credential-id", RECEIPT_ID,
            "--approved-source-sha256", SOURCE_DIGEST,
            "--approved-endpoint", ENDPOINT,
        ]

    def test_document_changes_only_receipt_node_two_fields(self):
        doc = gate.binding_document(self.state, self.source)
        old = json.loads(next(row[3] for row in self.rows if row[0] == RECEIVER))
        self.assertEqual(doc["id"], RECEIVER)
        self.assertIs(doc["active"], False)
        self.assertEqual(doc["nodes"][0], old[0])
        self.assertEqual(doc["nodes"][1], old[1])
        self.assertEqual(doc["nodes"][3:], old[3:])
        new = doc["nodes"][2]
        self.assertEqual(new["parameters"]["url"], ENDPOINT)
        self.assertEqual(new["credentials"], {
            "httpHeaderAuth": {"id": RECEIPT_ID, "name": gate.RECEIPT_NAME}
        })
        old_except_url = copy.deepcopy(old[2])
        old_except_url["parameters"]["url"] = ENDPOINT
        old_except_url["credentials"] = new["credentials"]
        self.assertEqual(new, old_except_url)
        self.assertEqual(doc["connections"], self.source["connections"])
        self.assertEqual(doc["settings"], self.source["settings"])
        self.assertNotIn("credentials", self.source["nodes"][2])

    def test_default_only_preflight_never_imports(self):
        with (
            patch.dict(os.environ, ENV),
            patch.object(gate, "preflight", return_value=(self.state, self.source)) as pre,
            patch.object(gate, "bind_once") as modify,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(gate.run(self.default), 0)
        pre.assert_called_once()
        modify.assert_not_called()
        self.assertIn("read-only", output.getvalue())

    def test_wrong_namespace_ci_and_production_denied_before_any_snapshot(self):
        for key, value in (
            ("CI", "true"), ("GITHUB_ACTIONS", "true"),
            ("AVUHZ_ENVIRONMENT", "PRODUCTION"),
            ("AVUHZ_ENVIRONMENT", "DEVELOPMENT"),
            ("AVUHZ_ENVIRONMENT", "TEST"),
        ):
            with (
                self.subTest(key=key),
                patch.dict(os.environ, {**ENV, key: value}),
                patch.object(gate, "preflight") as pre,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(gate.run(self.write), 2)
                pre.assert_not_called()
        with (
            patch.dict(os.environ, ENV),
            patch.object(gate, "preflight") as pre,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(gate.run(["--target", "PRODUCTION"]), 2)
            pre.assert_not_called()

    def test_exact_new_authorization_required(self):
        bad = [
            self.default + ["--bind-one"],
            self.default + ["--approved-endpoint", ENDPOINT],
            self.write[:-2],
        ]
        for key, value in (
            ("--approved-receiver-id", "other-receiver"),
            ("--approved-receipt-credential-id", "other-credential"),
            ("--approved-source-sha256", "sha256:" + "0"*64),
            ("--approved-endpoint", "http://172.17.0.1:5678" + gate.RECEIPT_ROUTE),
            ("--approved-endpoint", "https://example.com" + gate.RECEIPT_ROUTE),
            ("--approved-endpoint", "http://127.0.0.1:37891" + gate.RECEIPT_ROUTE),
        ):
            args = self.write[:]
            args[args.index(key) + 1] = value
            bad.append(args)
        for args in bad:
            with (
                self.subTest(args=args),
                patch.dict(os.environ, ENV),
                patch.object(gate, "preflight") as pre,
                patch.object(gate, "bind_once") as modify,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                # A different private port still has to be checked against
                # observed endpoint, never accepted as authority.
                self.assertEqual(gate.run(args), 2)
                modify.assert_not_called()

    def test_single_native_workflow_import_omits_secret(self):
        captured = []
        def fake_run(command, **kwargs):
            captured.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, b"one workflow imported\n", b"")
        with patch.object(gate.subprocess, "run", side_effect=fake_run):
            gate.bind_once(self.state, self.source)
        self.assertEqual(len(captured), 1)
        cmd, kw = captured[0]
        self.assertEqual(cmd, [
            "docker", "exec", "-i", "n8n", "n8n", "import:workflow",
            "--input=/dev/stdin", "--projectId=" + self.project,
        ])
        self.assertEqual(kw["timeout"], 60)
        self.assertEqual(kw["stderr"], subprocess.DEVNULL)
        payload = json.loads(kw["input"])
        self.assertEqual(payload, [gate.binding_document(self.state, self.source)])
        self.assertNotIn("op://", str(cmd) + str(kw["input"]))
        self.assertNotIn("password", str(cmd) + str(kw["input"]).lower())

    def test_import_failure_sanitized_no_retry(self):
        with patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 1, b"private-secret", b"private-secret"
        )) as process:
            with self.assertRaises(gate.ReceiptBindingDenied) as failure:
                gate.bind_once(self.state, self.source)
        self.assertEqual(process.call_count, 1)
        self.assertNotIn("private-secret", str(failure.exception))

    def test_preflight_rechecked_before_single_import(self):
        with (
            patch.dict(os.environ, ENV),
            patch.object(gate, "preflight", return_value=(self.state, self.source)) as pre,
            patch.object(gate, "bind_once") as modify,
            patch.object(gate, "postcondition", return_value=True) as verify,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(gate.run(self.write), 0)
        self.assertEqual(pre.call_count, 2)
        modify.assert_called_once_with(self.state, self.source)
        verify.assert_called_once_with(self.state, self.source)
        self.assertNotIn(RECEIPT_ID, output.getvalue())

    def test_endpoint_process_drift_blocks_before_import(self):
        changed = replace(
            self.state, endpoint="http://172.17.0.1:50001" + gate.RECEIPT_ROUTE
        )
        with (
            patch.dict(os.environ, ENV),
            patch.object(gate, "preflight", side_effect=[
                (self.state, self.source), (changed, self.source)
            ]),
            patch.object(gate, "bind_once") as modify,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(gate.run(self.write), 2)
        modify.assert_not_called()

    def test_postcondition_failure_never_retries_or_rolls_back(self):
        with (
            patch.dict(os.environ, ENV),
            patch.object(gate, "preflight", return_value=(self.state, self.source)),
            patch.object(gate, "bind_once") as modify,
            patch.object(gate, "postcondition", return_value=False),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(gate.run(self.write), 2)
        modify.assert_called_once()
        self.assertIn("no retry", output.getvalue())

    def _make_synthetic_sqlite(self, *, bound: bool, drift_other: bool=False,
                               active: bool=False, extra_execution: bool=False):
        with sqlite3.connect(self.db) as db:
            db.executescript("""
                CREATE TABLE workflow_entity(id TEXT,name TEXT,active INTEGER,nodes TEXT,
                  connections TEXT,settings TEXT,staticData TEXT,pinData TEXT);
                CREATE TABLE credentials_entity(id TEXT,name TEXT,type TEXT,data TEXT);
                CREATE TABLE shared_credentials(credentialsId TEXT,projectId TEXT,role TEXT);
                CREATE TABLE shared_workflow(workflowId TEXT,projectId TEXT,role TEXT);
                CREATE TABLE webhook_entity(id TEXT);
                CREATE TABLE execution_entity(id TEXT);
                CREATE TABLE project(id TEXT,type TEXT);
            """)
            db.execute("INSERT INTO project VALUES(?,?)",(self.project,"personal"))
            rows = list(self.rows)
            if bound:
                ix = next(i for i, row in enumerate(rows) if row[0] == RECEIVER)
                rx = list(rows[ix])
                rx[3] = json.dumps(gate.binding_document(self.state,self.source)["nodes"])
                rx[2] = int(active)
                rows[ix] = tuple(rx)
            if drift_other:
                ix = next(i for i, row in enumerate(rows) if row[0] != RECEIVER)
                other = list(rows[ix])
                other[3] = json.dumps([{"unexpected": True}])
                rows[ix] = tuple(other)
            db.executemany("INSERT INTO workflow_entity VALUES(?,?,?,?,?,?,?,?)",rows)
            db.executemany("INSERT INTO credentials_entity VALUES(?,?,?,?)",[
                (self.inbound,gate.inbound_gate.CREDENTIAL_NAME,"httpHeaderAuth","a"*200),
                (RECEIPT_ID,gate.RECEIPT_NAME,"httpHeaderAuth","b"*200),
            ])
            db.executemany("INSERT INTO shared_credentials VALUES(?,?,?)",self.cred_shares)
            db.executemany("INSERT INTO shared_workflow VALUES(?,?,?)",self.wf_shares)
            if extra_execution:
                db.execute("INSERT INTO execution_entity VALUES(?)",("unexpected",))
        with sqlite3.connect(self.storage) as db:
            db.execute("CREATE TABLE local_n8n_receipts(id TEXT)")

    def _postcondition(self):
        with (
            patch.object(gate.service_gate,"inspect_private_local_n8n") as bridge,
            patch.object(gate,"_service_listener",return_value=(ENDPOINT,1234)),
        ):
            bridge.return_value.gateway="172.17.0.1"
            # Fake type needs no endpoint or auth methods.
            return gate.postcondition(self.state,self.source)

    def test_independent_postcondition_accepts_exact_receipt_binding(self):
        self._make_synthetic_sqlite(bound=True)
        self.assertTrue(self._postcondition())

    def test_postcondition_rejects_no_binding(self):
        self._make_synthetic_sqlite(bound=False)
        self.assertFalse(self._postcondition())

    def test_postcondition_rejects_other_workflow_drift(self):
        self._make_synthetic_sqlite(bound=True,drift_other=True)
        self.assertFalse(self._postcondition())

    def test_postcondition_rejects_activation_or_execution(self):
        for active, execution in ((True,False),(False,True)):
            with self.subTest(active=active,execution=execution):
                if self.db.exists():self.db.unlink()
                if self.storage.exists():self.storage.unlink()
                self._make_synthetic_sqlite(bound=True,active=active,extra_execution=execution)
                self.assertFalse(self._postcondition())


if __name__=="__main__":
    unittest.main()
