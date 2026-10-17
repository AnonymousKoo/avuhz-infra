"""LOCAL/TEST receipt credential import gate: synthetic, no provider operations."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_shared_n8n_v2_op_receipt_credential_local as gate

TOKEN = secrets.token_urlsafe(40)
REFERENCE = "op://syntheticvault/syntheticitem/password"
NEW_ID = "f047927a-d1bf-4e79-bf2b-909910110bad"


class ReceiptCredentialGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="avuhz-receipt-gate-")
        self.addCleanup(self.temp.cleanup)
        self.dbfile = Path(self.temp.name) / "test.sqlite"
        self.source = gate.receiver._source()
        self.receiver_id = "0068feb4c96bdb5f"
        self.inbound_id = "synthetic-inbound-credential"
        self.project = "synthetic-personal"
        self.env = {"CI": "", "GITHUB_ACTIONS": "", "AVUHZ_ENVIRONMENT": "LOCAL"}
        self.default = ["--target", gate.TARGET]
        self.approved = self.default + [
            "--import-one", "--approved-source-sha256", gate.SOURCE_DIGEST,
            "--approved-receiver-id", self.receiver_id,
            "--approved-secret-reference", REFERENCE,
        ]
        self._create_db()

    def _create_db(self):
        nodes = json.loads(json.dumps(self.source["nodes"]))
        nodes[0]["credentials"] = {
            gate.inbound.CREDENTIAL_TYPE: {
                "id": self.inbound_id,
                "name": gate.inbound.CREDENTIAL_NAME,
            },
        }
        self.workflows = [
            (
                self.receiver_id, self.source["name"], 0, json.dumps(nodes),
                json.dumps(self.source["connections"]),
                json.dumps(self.source["settings"]),
            ),
            ("other-inactive-workflow", "Synthetic unrelated inactive", 0,
             "[]", "{}", "{}"),
        ]
        with sqlite3.connect(self.dbfile) as db:
            db.executescript("""
                CREATE TABLE project(id TEXT,type TEXT);
                CREATE TABLE workflow_entity(
                    id TEXT,name TEXT,active INTEGER,nodes TEXT,connections TEXT,settings TEXT
                );
                CREATE TABLE credentials_entity(id TEXT,name TEXT,type TEXT,data TEXT);
                CREATE TABLE shared_credentials(credentialsId TEXT,projectId TEXT,role TEXT);
                CREATE TABLE shared_workflow(workflowId TEXT,projectId TEXT,role TEXT);
                CREATE TABLE webhook_entity(id TEXT);
                CREATE TABLE execution_entity(id TEXT);
            """)
            db.execute("INSERT INTO project VALUES(?,?)", (self.project, "personal"))
            db.executemany("INSERT INTO workflow_entity VALUES(?,?,?,?,?,?)", self.workflows)
            db.execute(
                "INSERT INTO credentials_entity VALUES(?,?,?,?)",
                (self.inbound_id, gate.inbound.CREDENTIAL_NAME,
                 gate.inbound.CREDENTIAL_TYPE, "encrypted-inbound-opaque-metadata"),
            )
            db.execute(
                "INSERT INTO shared_credentials VALUES(?,?,?)",
                (self.inbound_id, self.project, "credential:owner"),
            )
            db.execute(
                "INSERT INTO shared_workflow VALUES(?,?,?)",
                (self.receiver_id, self.project, "workflow:owner"),
            )

    def _snapshot(self):
        return gate._read_snapshot(self.dbfile)

    def _add_encrypted_credential(self, *, name=None, credential_id=NEW_ID):
        with sqlite3.connect(self.dbfile) as db:
            db.execute(
                "INSERT INTO credentials_entity VALUES(?,?,?,?)",
                (credential_id, name or gate.CREDENTIAL_NAME,
                 gate.CREDENTIAL_TYPE, "encrypted-receipt-opaque-metadata"),
            )
            db.execute(
                "INSERT INTO shared_credentials VALUES(?,?,?)",
                (credential_id, self.project, "credential:owner"),
            )

    def test_exact_private_snapshot_and_expected_bound_inbound(self):
        before = self._snapshot()
        gate._check_receiver_and_credentials(before, self.source)
        self.assertEqual(before.receiver_id, self.receiver_id)
        self.assertEqual(before.execution_count, 0)

    def test_default_is_read_only_and_does_not_contact_1password(self):
        with (
            patch.dict(os.environ, self.env),
            patch.object(gate, "preflight", return_value=(self._snapshot(),self.source)),
            patch.object(gate, "LocalN8nOnePasswordCredential") as provider,
            patch.object(gate, "import_once") as importer,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(gate.run(self.default), 0)
        provider.assert_not_called()
        importer.assert_not_called()
        self.assertIn("read-only", out.getvalue())

    def test_real_local_preflight_requires_no_secret_or_mutation(self):
        # The suite itself uses a fake database. This test checks that the
        # public preflight reaches the expected private network and schema.
        with (
            patch.object(gate, "inspect_private_local_n8n") as network,
            patch.object(gate.receiver, "_db_path", return_value=self.dbfile),
            patch.object(gate.receiver, "_source", return_value=self.source),
        ):
            actual, src = gate.preflight()
        network.assert_called_once()
        self.assertEqual(actual.receiver_id, self.receiver_id)
        self.assertEqual(src, self.source)

    def test_wrong_environment_and_no_approval_never_access_provider(self):
        bad = [
            ["--target", "PRODUCTION"],
            self.default+["--import-one"],
            self.default+["--approved-source-sha256",gate.SOURCE_DIGEST],
            self.approved[:],
        ]
        bad[-1][bad[-1].index("--approved-source-sha256")+1]="sha256:"+"0"*64
        for args in bad:
            with (
                self.subTest(args=args),
                patch.dict(os.environ,self.env),
                patch.object(gate,"preflight") as preflight,
                patch.object(gate,"LocalN8nOnePasswordCredential") as provider,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(gate.run(args),2)
                preflight.assert_not_called()
                provider.assert_not_called()
        for name, value in (
            ("CI","true"),("GITHUB_ACTIONS","true"),
            ("AVUHZ_ENVIRONMENT","PRODUCTION"),
        ):
            with (
                self.subTest(env=name),
                patch.dict(os.environ,{**self.env,name:value}),
                patch.object(gate,"preflight") as preflight,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(gate.run(self.approved),2)
                preflight.assert_not_called()

    def test_wrong_receiver_id_denied_before_reading_password(self):
        args=self.approved[:]
        args[args.index("--approved-receiver-id")+1]="wrong"
        with (
            patch.dict(os.environ,self.env),
            patch.object(gate,"preflight",return_value=(self._snapshot(),self.source)),
            patch.object(gate,"LocalN8nOnePasswordCredential") as provider,
            patch.object(gate,"import_once") as importer,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(gate.run(args),2)
            provider.return_value.assert_not_called()
            importer.assert_not_called()

    def test_import_once_native_encrypted_credential_cli_exact_type_and_header(self):
        captured=[]
        def fake_run(command, **kwargs):
            captured.append((command,kwargs))
            return subprocess.CompletedProcess(command,0,b"",b"")
        with patch.object(gate.subprocess,"run",side_effect=fake_run):
            gate.import_once(self.project,TOKEN,NEW_ID)
        self.assertEqual(len(captured),1)
        command,kwargs=captured[0]
        self.assertEqual(command,[
            "docker","exec","-i","n8n","n8n","import:credentials",
            "--input=/dev/stdin","--projectId="+self.project,
        ])
        self.assertNotIn(TOKEN,str(command))
        self.assertNotIn(TOKEN,str(kwargs.get("stderr")))
        self.assertEqual(json.loads(kwargs["input"]),[{
            "id": NEW_ID, "name": gate.CREDENTIAL_NAME,
            "type": "httpHeaderAuth",
            "data": {"name": "X-Avuhz-Receipt-Bridge-Token", "value": TOKEN},
        }])

    def test_import_failure_one_attempt_no_secret_in_error(self):
        with patch.object(gate.subprocess,"run",return_value=subprocess.CompletedProcess(
            [], 1, b"sensitive provider diagnostic", b"sensitive provider diagnostic"
        )) as run:
            with self.assertRaises(gate.ReceiptCredentialDenied) as exc:
                gate.import_once(self.project,TOKEN,NEW_ID)
        self.assertEqual(run.call_count,1)
        self.assertNotIn(TOKEN,str(exc.exception))
        self.assertNotIn("sensitive",str(exc.exception))

    def test_successful_import_and_metadata_postcondition(self):
        before=self._snapshot()
        self.assertFalse(gate.postcondition(before,NEW_ID))
        self._add_encrypted_credential()
        self.assertTrue(gate.postcondition(before,NEW_ID))

    def test_rejects_unencrypted_entry_wrong_name_and_extra_credential(self):
        for mode in ("plaintext", "wrong-name", "extra"):
            with self.subTest(mode=mode):
                before=self._snapshot()
                self._add_encrypted_credential(
                    name="Other local header" if mode=="wrong-name" else None
                )
                with sqlite3.connect(self.dbfile) as db:
                    if mode=="plaintext":
                        db.execute(
                            "UPDATE credentials_entity SET data=? WHERE id=?",
                            ('{"name":"unsafe","value":"plaintext"}',NEW_ID),
                        )
                    if mode=="extra":
                        db.execute(
                            "INSERT INTO credentials_entity VALUES(?,?,?,?)",
                            ("extra-id","Something else","httpHeaderAuth","encrypted-secret"),
                        )
                self.assertFalse(gate.postcondition(before,NEW_ID))
                with sqlite3.connect(self.dbfile) as db:
                    db.execute("DELETE FROM credentials_entity WHERE id IN (?,?)",(NEW_ID,"extra-id"))
                    db.execute("DELETE FROM shared_credentials WHERE credentialsId=?",(NEW_ID,))

    def test_rejects_workflow_drift_new_execution_and_share_modification(self):
        for mode in ("workflow", "execution", "sharing"):
            with self.subTest(mode=mode):
                before=self._snapshot()
                self._add_encrypted_credential()
                with sqlite3.connect(self.dbfile) as db:
                    if mode=="workflow":
                        db.execute("UPDATE workflow_entity SET active=1 WHERE id=?",(self.receiver_id,))
                    if mode=="execution":
                        db.execute("INSERT INTO execution_entity VALUES(?)",("fictional-execution",))
                    if mode=="sharing":
                        db.execute("DELETE FROM shared_workflow")
                self.assertFalse(gate.postcondition(before,NEW_ID))
                with sqlite3.connect(self.dbfile) as db:
                    db.execute("UPDATE workflow_entity SET active=0")
                    db.execute("DELETE FROM execution_entity")
                    db.execute("DELETE FROM shared_workflow")
                    db.execute("INSERT INTO shared_workflow VALUES(?,?,?)",(
                        self.receiver_id,self.project,"workflow:owner"
                    ))
                    db.execute("DELETE FROM credentials_entity WHERE id=?",(NEW_ID,))
                    db.execute("DELETE FROM shared_credentials WHERE credentialsId=?",(NEW_ID,))

    def test_approved_write_one_issuer_read_one_import_and_no_retry(self):
        before=self._snapshot()
        with (
            patch.dict(os.environ,self.env),
            patch.object(gate,"preflight",return_value=(before,self.source)) as pf,
            patch.object(gate,"LocalN8nOnePasswordCredential") as provider,
            patch.object(gate,"import_once") as importer,
            patch.object(gate,"postcondition",return_value=True) as post,
            patch.object(gate.uuid,"uuid4",return_value=__import__("uuid").UUID(NEW_ID)),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            provider.return_value.return_value=TOKEN
            self.assertEqual(gate.run(self.approved),0)
        self.assertEqual(pf.call_count,2)
        provider.return_value.assert_called_once()
        importer.assert_called_once_with(self.project,TOKEN,NEW_ID)
        post.assert_called_once_with(before,NEW_ID)
        self.assertNotIn(TOKEN,out.getvalue())
        self.assertNotIn(REFERENCE,out.getvalue())

    def test_drift_after_secret_read_stops_before_n8n_import(self):
        from dataclasses import replace
        before=self._snapshot()
        drifted=replace(before,webhook_count=before.webhook_count+1)
        with (
            patch.dict(os.environ,self.env),
            patch.object(gate,"preflight",side_effect=[(before,self.source),(drifted,self.source)]) as pf,
            patch.object(gate,"LocalN8nOnePasswordCredential") as provider,
            patch.object(gate,"import_once") as importer,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            provider.return_value.return_value=TOKEN
            self.assertEqual(gate.run(self.approved),2)
        self.assertEqual(pf.call_count,2)
        provider.return_value.assert_called_once()
        importer.assert_not_called()
        self.assertNotIn(TOKEN,out.getvalue())
        self.assertIn("no retry",out.getvalue())

    def test_failed_postcondition_is_fail_closed_with_no_retry(self):
        before=self._snapshot()
        with (
            patch.dict(os.environ,self.env),
            patch.object(gate,"preflight",return_value=(before,self.source)),
            patch.object(gate,"LocalN8nOnePasswordCredential") as provider,
            patch.object(gate,"import_once") as importer,
            patch.object(gate,"postcondition",return_value=False),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            provider.return_value.return_value=TOKEN
            self.assertEqual(gate.run(self.approved),2)
        importer.assert_called_once()
        self.assertIn("no retry",out.getvalue())


if __name__=="__main__":
    unittest.main()
