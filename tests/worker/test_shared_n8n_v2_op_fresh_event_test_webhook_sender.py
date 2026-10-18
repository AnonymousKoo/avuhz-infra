"""Offline fictional SQL fixtures and mocks only; never inspect the live machine."""
import copy
from contextlib import contextmanager, ExitStack
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_shared_n8n_v2_op_fresh_event_test_webhook_sender as fresh

ENDPOINT = "http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts"


class FreshEventTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE local_n8n_receipts
              (trusted_tenant_id TEXT,event_id TEXT,delivery_key TEXT,envelope_digest TEXT);
            CREATE TABLE project (id TEXT,type TEXT);
            CREATE TABLE workflow_entity
              (id TEXT,name TEXT,active INTEGER,isArchived INTEGER,nodes TEXT,
               connections TEXT,settings TEXT,staticData TEXT,pinData TEXT);
            CREATE TABLE credentials_entity (id TEXT,name TEXT,type TEXT,data TEXT);
            CREATE TABLE shared_credentials (credentialsId TEXT,projectId TEXT,role TEXT);
            CREATE TABLE shared_workflow (workflowId TEXT,projectId TEXT,role TEXT);
            CREATE TABLE webhook_entity (workflowId TEXT);
        """)
        old = fresh.qa.fictional_event()
        self.db.execute("INSERT INTO local_n8n_receipts VALUES (?,?,?,?)", (
            fresh.qa.TENANT_ID, old["event_id"], old["delivery_idempotency_key"],
            fresh.HISTORICAL_SHA256))
        self.source = fresh._source()
        nodes = copy.deepcopy(self.source["nodes"])
        for idx, ident, name in (
            (0, fresh.INBOUND_ID, fresh.qa.inbound.CREDENTIAL_NAME),
            (2, fresh.RECEIPT_ID, fresh.qa.receipt.CREDENTIAL_NAME),
        ):
            nodes[idx]["credentials"] = {"httpHeaderAuth": {"id": ident, "name": name}}
            self.db.execute("INSERT INTO credentials_entity VALUES (?,?,?,NULL)",
                            (ident, name, "httpHeaderAuth"))
            self.db.execute("INSERT INTO shared_credentials VALUES (?,?,?)",
                            (ident, fresh.PROJECT_ID, "credential:owner"))
        nodes[2]["parameters"]["url"] = ENDPOINT
        self.db.execute("INSERT INTO project VALUES (?, 'personal')", (fresh.PROJECT_ID,))
        self.db.execute("INSERT INTO shared_workflow VALUES (?,?,?)",
                        (fresh.RECEIVER_ID, fresh.PROJECT_ID, "workflow:owner"))
        self.db.execute("INSERT INTO workflow_entity VALUES (?,?,0,0,?,?,?,NULL,NULL)",
                        (fresh.RECEIVER_ID, self.source["name"], json.dumps(nodes),
                         json.dumps(self.source["connections"]), json.dumps(self.source["settings"])))
        for index in range(6):
            self.db.execute("INSERT INTO workflow_entity VALUES (?,?,0,?,NULL,NULL,NULL,NULL,NULL)",
                            (str(index), "fictional-other-" + str(index), int(index == 5)))
        self.queries = []
        self.db.set_trace_callback(self.queries.append)
        # Fail even if a future refactor tries a derived encrypted-column read.
        def authorize(action, table, column, *_):
            if action == sqlite3.SQLITE_READ and table == "credentials_entity" and column == "data":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        self.db.set_authorizer(authorize)
        @contextmanager
        def readonly(*args, **kwargs):
            yield self.db
        self.readonly = readonly

    def receipt(self):
        with patch.object(fresh, "_readonly", self.readonly):
            fresh._receipt_readback(Path("/unused-fixture"))

    def receiver(self, endpoint=ENDPOINT):
        with patch.object(fresh, "_readonly", self.readonly):
            fresh._receiver_metadata(Path("/unused-fixture"), self.source, endpoint)

    def test_exact_event_digest_and_only_three_replacements(self):
        old, new = fresh.qa.fictional_event(), fresh.fictional_event()
        self.assertEqual(set(new), fresh.FIELDS)
        self.assertEqual(len(new), 8)
        self.assertEqual({k for k in old if old[k] != new[k]},
                         {"event_id", "correlation_id", "delivery_idempotency_key"})
        self.assertEqual(new["tenant_id"], "a4730000-0000-4000-8000-000000000001")
        self.assertEqual(fresh.qa._digest(new), fresh.EVENT_SHA256)
        new["authoritative_subject_reference"]["reference_id"] = "mutated"
        self.assertEqual(fresh.qa._digest(fresh.fictional_event()), fresh.EVENT_SHA256)

    def test_one_exact_historical_receipt(self):
        self.receipt()
        self.assertEqual(len(self.queries), 1)
        self.assertTrue(self.queries[0].startswith("SELECT count(*)"))

    def test_empty_and_extra_receipts_denied(self):
        self.db.execute("DELETE FROM local_n8n_receipts")
        with self.assertRaises(fresh.FreshEventDenied):
            self.receipt()
        self.db.execute("INSERT INTO local_n8n_receipts VALUES ('x','x','x','x')")
        self.db.execute("INSERT INTO local_n8n_receipts VALUES ('y','y','y','y')")
        with self.assertRaises(fresh.FreshEventDenied):
            self.receipt()

    def test_each_historical_identity_field_must_match(self):
        for column in ("trusted_tenant_id", "event_id", "delivery_key", "envelope_digest"):
            with self.subTest(column=column):
                self.db.execute("SAVEPOINT fixture")
                self.db.execute("UPDATE local_n8n_receipts SET " + column + "='wrong'")
                with self.assertRaises(fresh.FreshEventDenied):
                    self.receipt()
                self.db.execute("ROLLBACK TO fixture")
                self.db.execute("RELEASE fixture")

    def test_new_id_key_or_full_receipt_collision_denied(self):
        new = fresh.fictional_event()
        for event_id, key in ((new["event_id"], "other"), ("other", fresh.DELIVERY_KEY),
                              (new["event_id"], fresh.DELIVERY_KEY)):
            with self.subTest(event_id=event_id, key=key):
                self.db.execute("SAVEPOINT fixture")
                self.db.execute("INSERT INTO local_n8n_receipts VALUES (?,?,?,?)",
                                (fresh.qa.TENANT_ID, event_id, key, fresh.EVENT_SHA256))
                with self.assertRaises(fresh.FreshEventDenied):
                    self.receipt()
                self.db.execute("ROLLBACK TO fixture")
                self.db.execute("RELEASE fixture")

    def test_metadata_only_exact_receiver(self):
        self.receiver()
        self.assertFalse(any("length(" in sql or "substr(" in sql for sql in self.queries))
        self.assertFalse(any("execution_entity" in sql for sql in self.queries))

    def test_missing_or_wrong_metadata_and_widened_shares_denied(self):
        changes = (
            "DELETE FROM credentials_entity", "DELETE FROM shared_credentials",
            "DELETE FROM shared_workflow", "DELETE FROM project",
            "UPDATE project SET id='other'", "UPDATE credentials_entity SET type='other'",
            "UPDATE credentials_entity SET id='other'", "UPDATE shared_credentials SET role='other'",
            "UPDATE shared_workflow SET role='other'",
            "INSERT INTO shared_credentials SELECT credentialsId,'other',role FROM shared_credentials",
            "INSERT INTO shared_workflow SELECT workflowId,'other',role FROM shared_workflow",
            "UPDATE workflow_entity SET active=1", "UPDATE workflow_entity SET active=NULL",
            "INSERT INTO webhook_entity VALUES ('unintended')",
            "UPDATE workflow_entity SET staticData='unexpected'",
            "UPDATE workflow_entity SET pinData='unexpected'",
            "UPDATE workflow_entity SET nodes='[]'",
            "UPDATE workflow_entity SET connections='{}'",
            "UPDATE workflow_entity SET settings='{}'",
            "DELETE FROM workflow_entity WHERE id='0'",
        )
        for sql in changes:
            with self.subTest(sql=sql):
                self.db.execute("SAVEPOINT fixture")
                self.db.execute(sql)
                with self.assertRaises(fresh.FreshEventDenied):
                    self.receiver()
                self.db.execute("ROLLBACK TO fixture")
                self.db.execute("RELEASE fixture")

    def test_installed_endpoint_drift_denied(self):
        with self.assertRaises(fresh.FreshEventDenied):
            self.receiver("http://172.17.0.1:12345/v1/avuhz/local-n8n-receipts")

    def test_source_hash_and_fixture_drift_denied(self):
        with patch.object(fresh, "SOURCE_FILES", {"SECURITY.md": "0" * 64}):
            with self.assertRaises(fresh.FreshEventDenied):
                fresh._source()
        with patch.object(fresh.qa.receiver, "SOURCE_SHA256", "wrong"):
            with self.assertRaises(fresh.FreshEventDenied):
                fresh._source()
        with patch.object(fresh.qa, "EXPECTED_FIXTURE_SHA256", "wrong"):
            with self.assertRaises(fresh.qa.FirstEventQaDenied):
                fresh.fictional_event()

    def test_owner_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture"
            path.write_text("fictional")
            path.chmod(0o600)
            fresh._protected_file(path, receipt=True)
            with patch.object(fresh.os, "getuid", return_value=-1):
                with self.assertRaises(fresh.FreshEventDenied):
                    fresh._protected_file(path, receipt=True)
            for mode in (0o644, 0o660, 0o400):
                path.chmod(mode)
                with self.assertRaises(fresh.FreshEventDenied):
                    fresh._protected_file(path, receipt=True)
            alias = Path(directory) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(fresh.FreshEventDenied):
                fresh._protected_file(alias, receipt=True)
            with self.assertRaises(fresh.FreshEventDenied):
                fresh._protected_file(Path(directory), receipt=True)

    def test_readonly_connection_flags_transaction_and_close(self):
        from unittest.mock import MagicMock
        connection = MagicMock()
        with patch.object(fresh, "_protected_file"), patch.object(
                fresh.sqlite3, "connect", return_value=connection) as connect:
            with fresh._readonly(Path("/fictional.sqlite"), receipt=True):
                pass
        connect.assert_called_once_with("file:///fictional.sqlite?mode=ro", uri=True, timeout=4)
        self.assertEqual([c.args[0] for c in connection.execute.call_args_list],
                         ["PRAGMA query_only=ON", "BEGIN"])
        connection.close.assert_called_once()

    def runtime_mocks(self, stack):
        from types import SimpleNamespace
        stack.enter_context(patch.object(fresh.qa.service, "inspect_private_local_n8n",
                                         return_value=SimpleNamespace(gateway="172.17.0.1")))
        stack.enter_context(patch.object(fresh.qa.service, "validate_storage_path"))
        stack.enter_context(patch.object(fresh, "_protected_file"))
        listener = stack.enter_context(patch.object(fresh.qa.binding, "_service_listener",
                                                    return_value=(ENDPOINT, 4242)))
        stack.enter_context(patch.object(fresh, "_process_sources"))
        stack.enter_context(patch.object(fresh.qa.receiver, "_db_path", return_value=Path("/unused")))
        stack.enter_context(patch.object(fresh, "_readonly", self.readonly))
        return listener

    def test_composed_preflight_never_uses_first_send_zero_count_gate(self):
        with ExitStack() as stack:
            self.runtime_mocks(stack)
            forbidden = stack.enter_context(patch.object(fresh.qa, "preflight", side_effect=AssertionError))
            evidence = fresh.preflight()
            self.assertFalse(evidence.ready_for_send)
            self.assertFalse(evidence.test_listener_verified)
            forbidden.assert_not_called()

    def test_missing_bridge_and_endpoint_pid_drift_denied(self):
        for results in (ValueError("private detail"), [(ENDPOINT, 4242), (ENDPOINT, 4243)]):
            with ExitStack() as stack:
                listener = self.runtime_mocks(stack)
                listener.side_effect = results
                with self.assertRaisesRegex(fresh.FreshEventDenied, "^fresh_event_readback_denied$"):
                    fresh.preflight()

    def test_readonly_no_secrets_subprocess_or_network(self):
        import socket
        import subprocess
        from avuhz_worker.local_n8n_onepassword_credential import LocalN8nOnePasswordCredential
        with ExitStack() as stack:
            self.runtime_mocks(stack)
            stack.enter_context(patch.dict(os.environ, {"AVUHZ_ENVIRONMENT": "LOCAL"}, clear=True))
            stack.enter_context(patch.object(fresh.platform, "node", return_value="DefNet"))
            guards = [stack.enter_context(patch.object(obj, name, side_effect=AssertionError))
                      for obj, name in ((socket, "socket"), (subprocess, "Popen"),
                                        (LocalN8nOnePasswordCredential, "__call__"))]
            output = stack.enter_context(patch("sys.stdout", new_callable=io.StringIO))
            self.assertEqual(fresh.run(["--target", fresh.TARGET]), 0)
            self.assertIn("NOT READY FOR SEND", output.getvalue())
            self.assertNotIn(ENDPOINT, output.getvalue())
            self.assertNotIn(fresh.HISTORICAL_SHA256, output.getvalue())
            for guard in guards:
                guard.assert_not_called()

    def test_cross_tenant_fresh_collisions_denied(self):
        for event_id, key in ((fresh.EVENT_ID, "other"), ("other", fresh.DELIVERY_KEY)):
            with self.subTest(event_id=event_id), self.assertRaises(fresh.FreshEventDenied):
                self.db.execute("SAVEPOINT collision")
                try:
                    self.db.execute("INSERT INTO local_n8n_receipts VALUES (?,?,?,?)",
                                    ("other-tenant", event_id, key, fresh.EVENT_SHA256))
                    self.receipt()
                finally:
                    self.db.execute("ROLLBACK TO collision")
                    self.db.execute("RELEASE collision")

    def test_missing_relative_and_writable_metadata_paths_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing"
            with self.assertRaises(FileNotFoundError):
                fresh._protected_file(path, receipt=True)
            with self.assertRaises(fresh.FreshEventDenied):
                fresh._protected_file(Path("relative"), receipt=False)
            path.write_text("fictional")
            for mode in (0o620, 0o602):
                path.chmod(mode)
                with self.assertRaises(fresh.FreshEventDenied):
                    fresh._protected_file(path, receipt=False)

    def test_readonly_setup_failure_closes_connection(self):
        from unittest.mock import MagicMock
        connection = MagicMock()
        connection.execute.side_effect = sqlite3.DatabaseError("private-detail")
        with patch.object(fresh, "_protected_file"), patch.object(
                fresh.sqlite3, "connect", return_value=connection):
            with self.assertRaises(sqlite3.DatabaseError):
                with fresh._readonly(Path("/fictional.sqlite")):
                    self.fail("must not yield after setup failure")
        connection.close.assert_called_once()

    def test_every_runtime_boundary_failure_is_sanitized(self):
        for name in ("_source", "_protected_file", "_process_sources",
                     "_receiver_metadata", "_receipt_readback"):
            with self.subTest(name=name), ExitStack() as stack:
                self.runtime_mocks(stack)
                stack.enter_context(patch.object(fresh, name,
                    side_effect=ValueError("private-detail")))
                with self.assertRaisesRegex(fresh.FreshEventDenied,
                                             "^fresh_event_readback_denied$"):
                    fresh.preflight()

    def test_send_unconditionally_denied_before_inspection(self):
        with patch.object(fresh, "preflight", side_effect=AssertionError) as check, \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(fresh.run(["--target", fresh.TARGET, "--send-one"]), 2)
            check.assert_not_called()
            self.assertIn("BLOCKED future-send", output.getvalue())

    def test_approval_flags_not_accepted_as_authority(self):
        for flag in ("--approved-source-commit", "--approved-event-digest", "--token-fd",
                     "--approved-secret-reference", "--ui-listener-ready"):
            with self.subTest(flag=flag), patch("sys.stderr", new_callable=io.StringIO), \
                    patch.object(fresh, "preflight", side_effect=AssertionError) as check:
                with self.assertRaises(SystemExit) as error:
                    fresh.run(["--target", fresh.TARGET, "--send-one", flag, "unapproved"])
                self.assertEqual(error.exception.code, 2)
                check.assert_not_called()

    def test_wrong_environment_machine_target_and_sanitized_failure(self):
        for env, machine, target in (({}, "DefNet", fresh.TARGET),
                ({"AVUHZ_ENVIRONMENT": "PRODUCTION"}, "DefNet", fresh.TARGET),
                ({"AVUHZ_ENVIRONMENT": "LOCAL", "CI": "true"}, "DefNet", fresh.TARGET),
                ({"AVUHZ_ENVIRONMENT": "LOCAL"}, "wrong", fresh.TARGET),
                ({"AVUHZ_ENVIRONMENT": "LOCAL"}, "DefNet", "wrong")):
            with patch.dict(os.environ, env, clear=True), \
                    patch.object(fresh.platform, "node", return_value=machine), \
                    patch.object(fresh, "preflight", side_effect=AssertionError) as check, \
                    patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(fresh.run(["--target", target]), 2)
                check.assert_not_called()
        with patch.dict(os.environ, {"AVUHZ_ENVIRONMENT": "LOCAL"}, clear=True), \
                patch.object(fresh.platform, "node", return_value="DefNet"), \
                patch.object(fresh, "preflight", side_effect=ValueError("sensitive-detail")), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(fresh.run(["--target", fresh.TARGET]), 2)
            self.assertNotIn("sensitive-detail", output.getvalue())


if __name__ == "__main__":
    unittest.main()
