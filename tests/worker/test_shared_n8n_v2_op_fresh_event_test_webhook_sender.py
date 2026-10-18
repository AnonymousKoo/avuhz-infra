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

    def test_post_send_aggregate_requires_exact_historical_and_fresh(self):
        with patch.object(fresh, "_readonly", self.readonly):
            with self.assertRaises(fresh.FreshEventDenied):
                fresh._receipt_readback(Path("/unused"), after=True)
            self.db.execute("INSERT INTO local_n8n_receipts VALUES (?,?,?,?)", (
                fresh.qa.TENANT_ID, fresh.EVENT_ID, fresh.DELIVERY_KEY, fresh.EVENT_SHA256))
            fresh._receipt_readback(Path("/unused"), after=True)
            for column in ("trusted_tenant_id", "event_id", "delivery_key", "envelope_digest"):
                with self.subTest(column=column):
                    self.db.execute("SAVEPOINT postcheck")
                    self.db.execute("UPDATE local_n8n_receipts SET " + column + "='wrong'")
                    with self.assertRaises(fresh.FreshEventDenied):
                        fresh._receipt_readback(Path("/unused"), after=True)
                    self.db.execute("ROLLBACK TO postcheck")
                    self.db.execute("RELEASE postcheck")
            self.db.execute("INSERT INTO local_n8n_receipts VALUES (?,?,?,?)", (
                "other-tenant", fresh.EVENT_ID, fresh.DELIVERY_KEY, fresh.EVENT_SHA256))
            with self.assertRaises(fresh.FreshEventDenied):
                fresh._receipt_readback(Path("/unused"), after=True)

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
                     "--approved-secret-reference", "--ui-listener-ready",
                     "--authorization-artifact", "--owner-identity"):
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


class GovernedAttemptTests(unittest.TestCase):
    """Offline adapter doubles are not an implemented owner trust root."""

    def setUp(self):
        import hashlib
        from unittest.mock import MagicMock
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, {"AVUHZ_ENVIRONMENT": "LOCAL"}, clear=True))
        self.stack.enter_context(patch.object(fresh.platform, "node", return_value="DefNet"))
        self.clock = self.stack.enter_context(patch.object(fresh.time, "time", return_value=1000))
        self.state = fresh.Evidence(ENDPOINT, 4242, fresh.EVENT_SHA256, gateway="172.17.0.1")
        self.observed = dict(
            owner_identity="fictional-owner", issuer_account="fictional-account",
            issuer_user="fictional-user", issuer_session="fictional-session",
            issuer_kind="SIGNED_IN_OWNER", inbound_reference="op://fictional/item/inbound",
            issuer_metadata_sha256="d" * 64, native_listener_id="fictional-listener",
            listener_registered_at=990, listener_expires_at=1110, observed_at=1000,
            test_url=fresh.TEST_URL, project_id=fresh.PROJECT_ID,
            workflow_id=fresh.RECEIVER_ID, inbound_id=fresh.INBOUND_ID,
        )
        self.binding = {k: v for k, v in self.observed.items() if k != "observed_at"}
        self.binding.update(
            environment="LOCAL", machine="DefNet", target=fresh.TARGET,
            source_commit="a" * 40,
            sender_sha256=hashlib.sha256(Path(fresh.__file__).read_bytes()).hexdigest(),
            receiver_sha256=fresh.SOURCE_SHA256, event_id=fresh.EVENT_ID,
            correlation_id=fresh.CORRELATION_ID, delivery_key=fresh.DELIVERY_KEY,
            event_sha256=fresh.EVENT_SHA256, tenant_id=fresh.qa.TENANT_ID,
            historical_sha256=fresh.HISTORICAL_SHA256, receipt_store=str(fresh.STORE),
            gateway="172.17.0.1", receipt_endpoint=ENDPOINT, bridge_pid=4242,
            max_attempts=1, receipt_before=[1, 1, 0, 0], receipt_after=[2, 1, 1, 1],
        )
        self.grant = fresh._OwnerAuthorization("b" * 64, "fictional-attempt",
                                             "fictional-owner", 990, 1100, self.binding)
        self.preflight = self.stack.enter_context(patch.object(fresh, "preflight", return_value=self.state))
        self.observe = self.stack.enter_context(patch.object(
            fresh, "_listener_and_issuer_observation", side_effect=lambda: dict(self.observed)))
        self.commit = self.stack.enter_context(patch.object(
            fresh.first, "_pinned_source_commit", return_value="a" * 40))
        self.authorize = self.stack.enter_context(patch.object(
            fresh, "_verified_owner_authorization", return_value=self.grant))
        self.claimed = False
        self.order = []
        def consume(grant):
            self.order.append("consume")
            self.assertIs(grant, self.grant)
            if self.claimed:
                return False
            self.claimed = True
            return True
        self.consume = self.stack.enter_context(patch.object(
            fresh, "_consume_owner_authorization", side_effect=consume))
        def field():
            self.order.append("private-read")
            return "fictional-" + "x" * 32
        # Only the private I/O boundary is mocked; reference validation stays real.
        self.secret = self.stack.enter_context(patch.object(
            fresh.LocalN8nOnePasswordCredential, "__call__", side_effect=field))
        self.connection = MagicMock()
        self.response = self.connection.getresponse.return_value
        self.response.status = 202
        self.response.getheader.return_value = None
        self.response.read.return_value = b'{"accepted":true}'
        self.connection.request.side_effect = lambda *a, **kw: self.order.append("post")
        self.http = self.stack.enter_context(patch.object(
            fresh.http.client, "HTTPConnection", return_value=self.connection))

    def deny(self):
        with self.assertRaises(fresh.FreshEventDenied):
            fresh._governed_attempt()

    def test_valid_binding_one_private_field_anonymous_fd_one_post(self):
        import stat
        reader = fresh.first._read_inbound_from_fd
        fds = []
        def read(fd):
            fds.append(fd)
            self.assertTrue(stat.S_ISFIFO(os.fstat(fd).st_mode))
            self.assertEqual(os.fstat(fd).st_uid, os.getuid())
            self.assertFalse(os.get_inheritable(fd))
            return reader(fd)
        with patch.object(fresh.first, "_read_inbound_from_fd", side_effect=read) as fd_read:
            fresh._governed_attempt()
        self.assertEqual(self.order, ["consume", "private-read", "post"])
        self.secret.assert_called_once_with()
        fd_read.assert_called_once()
        with self.assertRaises(OSError):
            os.fstat(fds[0])
        self.http.assert_called_once_with("127.0.0.1", 5678, timeout=8)
        self.connection.request.assert_called_once()
        call = self.connection.request.call_args
        self.assertEqual(call.args, ("POST", "/webhook-test/avuhz-events"))
        self.assertEqual(json.loads(call.kwargs["body"]), fresh.fictional_event())
        self.assertEqual(call.kwargs["headers"]["X-Avuhz-Delivery-Key"], fresh.DELIVERY_KEY)
        self.connection.close.assert_called_once()
        self.assertEqual(self.preflight.call_args_list[-1].kwargs, {"after": True})
        self.deny()
        self.secret.assert_called_once()
        self.connection.request.assert_called_once()

    def test_every_exact_artifact_binding_mismatch_denied_before_secret(self):
        for key in self.binding:
            with self.subTest(key=key):
                original = self.binding[key]
                self.binding[key] = "mismatch"
                try:
                    self.deny()
                finally:
                    self.binding[key] = original
        self.consume.assert_not_called()
        self.secret.assert_not_called()
        self.http.assert_not_called()

    def test_boolean_cannot_substitute_for_attempt_count(self):
        self.binding["max_attempts"] = True
        self.deny()
        self.secret.assert_not_called()

    def test_wrong_owner_artifact_window_or_identity(self):
        from dataclasses import replace
        for changes in ({"owner_identity": "different"}, {"artifact_sha256": "wrong"},
                        {"authorization_id": ""}, {"valid_until": 1000},
                        {"valid_from": 1001}, {"valid_from": 0}, {"valid_from": True}):
            with self.subTest(changes=changes):
                self.authorize.return_value = replace(self.grant, **changes)
                self.deny()
        self.secret.assert_not_called()
        self.consume.assert_not_called()

    def test_missing_or_revoked_independent_authority_denied_before_runtime(self):
        self.authorize.side_effect = fresh.FreshEventDenied("owner_artifact_revoked")
        self.deny()
        self.preflight.assert_not_called()
        self.secret.assert_not_called()

    def test_issuer_listener_observation_mismatch_and_stale_denied(self):
        cases = {
            "owner_identity": "different", "issuer_account": "", "issuer_user": "",
            "issuer_session": "", "issuer_kind": "SERVICE_ACCOUNT", "inbound_reference": "invalid",
            "issuer_metadata_sha256": "invalid", "native_listener_id": "",
            "listener_registered_at": 1001, "listener_expires_at": 1000,
            "observed_at": 994, "test_url": "http://127.0.0.1:5678/webhook/avuhz-events",
            "project_id": "other", "workflow_id": "other", "inbound_id": fresh.RECEIPT_ID,
        }
        for key, value in cases.items():
            with self.subTest(key=key):
                old = self.observed[key]
                self.observed[key] = value
                try:
                    self.deny()
                finally:
                    self.observed[key] = old
        self.consume.assert_not_called()
        self.secret.assert_not_called()

    def test_observation_fields_cannot_be_missing_or_extended(self):
        for observed in ({}, {**self.observed, "approved": True}):
            self.observe.side_effect = None
            self.observe.return_value = observed
            self.deny()
        self.secret.assert_not_called()

    def test_commit_or_runtime_drift_before_claim_denies_secret(self):
        from dataclasses import replace
        self.commit.return_value = "c" * 40
        self.deny()
        self.commit.return_value = "a" * 40
        self.preflight.side_effect = [self.state, replace(self.state, listener_pid=999)]
        self.deny()
        self.consume.assert_not_called()
        self.secret.assert_not_called()

    def test_atomic_claim_failure_never_reads_secret(self):
        for result in (False, None, 1):
            self.consume.side_effect = None
            self.consume.return_value = result
            self.deny()
        self.secret.assert_not_called()
        self.http.assert_not_called()

    def test_atomic_claim_error_never_reads_secret(self):
        self.consume.side_effect = OSError("private-detail")
        with self.assertRaisesRegex(fresh.FreshEventDenied, "^attempt_unverified_no_retry$"):
            fresh._governed_attempt()
        self.secret.assert_not_called()

    def test_secret_failure_remains_consumed_no_fallback(self):
        self.secret.side_effect = OSError("private-detail")
        self.deny()
        self.deny()
        self.assertTrue(self.claimed)
        self.secret.assert_called_once()
        self.http.assert_not_called()

    def test_runtime_drift_after_secret_retains_claim_without_post(self):
        from dataclasses import replace
        self.preflight.side_effect = [self.state, self.state, replace(self.state, listener_pid=999)]
        self.deny()
        self.assertTrue(self.claimed)
        self.secret.assert_called_once()
        self.http.assert_not_called()

    def test_listener_expiry_after_secret_retains_claim_without_post(self):
        self.clock.side_effect = [1000, 1000, 1111]
        self.deny()
        self.assertTrue(self.claimed)
        self.secret.assert_called_once()
        self.http.assert_not_called()

    def test_timeout_is_ambiguous_consumed_and_no_retry(self):
        self.connection.getresponse.side_effect = TimeoutError("private-detail")
        with self.assertRaisesRegex(fresh.FreshEventDenied, "^transport_ambiguous_no_retry$"):
            fresh._governed_attempt()
        self.deny()
        self.assertTrue(self.claimed)
        self.secret.assert_called_once()
        self.connection.request.assert_called_once()
        self.connection.close.assert_called_once()
        self.assertFalse(any(call.kwargs.get("after") for call in self.preflight.call_args_list))

    def test_redirect_is_not_followed_or_read(self):
        self.response.status = 302
        self.deny()
        self.deny()
        self.http.assert_called_once()
        self.connection.request.assert_called_once()
        self.response.read.assert_not_called()

    def test_malformed_http202_always_fails_once(self):
        for body in (b'{"accepted":1}', b'{"accepted":false}', b'{"accepted":true,"extra":1}',
                     b'{"accepted":true,"accepted":true}', b'[]', b'null', b'"accepted"',
                     b'{"accepted":"true"}', b'not-json', b'\xff', b'x' * 513):
            with self.subTest(body=body):
                self.claimed = False  # independent fictional approvals per case
                self.connection.reset_mock()
                self.response.read.return_value = body
                self.deny()
                self.deny()
                self.connection.request.assert_called_once()
                self.connection.close.assert_called_once()

    def test_malformed_or_oversized_length_denied_without_read(self):
        for length in ("513", "-1", "nonnumeric", ""):
            self.claimed = False
            self.response.getheader.return_value = length
            self.deny()
        self.response.read.assert_not_called()

    def test_postcheck_failure_never_retries(self):
        self.preflight.side_effect = [self.state, self.state, self.state,
                                     fresh.FreshEventDenied("receipt_collision")]
        self.deny()
        self.assertTrue(self.claimed)
        self.connection.request.assert_called_once()
        self.secret.assert_called_once()

    def test_slow_observation_cannot_use_an_earlier_clock_sample(self):
        def slow_observation():
            self.clock.return_value = 1111
            return dict(self.observed)
        self.observe.side_effect = slow_observation
        self.deny()
        self.secret.assert_not_called()
        self.consume.assert_not_called()

    def test_private_pipe_write_failure_closes_fds_and_never_posts(self):
        pipe = os.pipe
        fds = []
        def opened():
            result = pipe()
            fds.extend(result)
            return result
        with patch.object(fresh.os, "pipe", side_effect=opened), \
                patch.object(fresh.os, "write", side_effect=OSError("private-detail")):
            self.deny()
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertTrue(self.claimed)
        self.secret.assert_called_once()
        self.http.assert_not_called()

    def test_invalid_private_field_stops_before_pipe(self):
        self.secret.side_effect = None
        for value in ("short", "x" * 513, "x" * 32 + "\n", "x" * 32 + "é"):
            self.claimed = False
            self.secret.return_value = value
            with patch.object(fresh.os, "pipe") as pipe:
                self.deny()
                pipe.assert_not_called()
        self.http.assert_not_called()

    def test_request_timeout_never_retries_or_reads_response(self):
        self.connection.request.side_effect = TimeoutError("private-detail")
        self.deny()
        self.deny()
        self.connection.request.assert_called_once()
        self.connection.getresponse.assert_not_called()
        self.connection.close.assert_called_once()

    def test_failure_diagnostics_do_not_print_private_value(self):
        with patch("sys.stdout", new_callable=io.StringIO) as out, \
                patch("sys.stderr", new_callable=io.StringIO) as err:
            self.connection.getresponse.side_effect = OSError("fictional-" + "x" * 32)
            with self.assertRaises(fresh.FreshEventDenied) as failure:
                fresh._governed_attempt()
        self.assertNotIn("fictional-", str(failure.exception))
        self.assertEqual(out.getvalue() + err.getvalue(), "")

    def test_cli_send_remains_disabled_even_with_valid_mock_adapters(self):
        with patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(fresh.run(["--target", fresh.TARGET, "--send-one"]), 2)
        self.authorize.assert_not_called()
        self.preflight.assert_not_called()
        self.secret.assert_not_called()
        self.http.assert_not_called()


class UnavailableTrustAdapterTests(unittest.TestCase):
    def test_no_local_artifact_can_self_authorize(self):
        with self.assertRaisesRegex(fresh.FreshEventDenied, "independent_owner_authorization_unavailable"):
            fresh._verified_owner_authorization()

    def test_native_listener_and_owner_issuer_verifier_unavailable(self):
        with self.assertRaisesRegex(fresh.FreshEventDenied, "listener_and_issuer_verifier_unavailable"):
            fresh._listener_and_issuer_observation()

    def test_durable_consumer_is_not_an_in_memory_claim(self):
        with self.assertRaisesRegex(fresh.FreshEventDenied, "durable_authorization_consumption_unavailable"):
            fresh._consume_owner_authorization(None)

    def test_direct_core_call_still_denies_before_any_runtime_or_secret(self):
        with patch.dict(os.environ, {"AVUHZ_ENVIRONMENT": "LOCAL"}, clear=True), \
                patch.object(fresh.platform, "node", return_value="DefNet"), \
                patch.object(fresh, "preflight") as preflight, \
                patch.object(fresh.LocalN8nOnePasswordCredential, "__call__") as secret:
            with self.assertRaises(fresh.FreshEventDenied):
                fresh._governed_attempt()
        preflight.assert_not_called()
        secret.assert_not_called()

    def test_old_first_event_guard_is_still_zero_receipts(self):
        from types import SimpleNamespace
        with patch.object(fresh.qa, "preflight", return_value=SimpleNamespace(
                stored_receipts=1, active_workflows=0, visible_workflows=6)) as preflight:
            with self.assertRaises(fresh.first.TestWebhookSendDenied):
                fresh.first._one_readonly_preflight()
        preflight.assert_called_once_with(expect_one=False)


if __name__ == "__main__":
    unittest.main()
