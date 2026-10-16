"""Pure temporary SQLite and mocked CLI for a single inactive n8n receiver import.

No installed n8n/credentials accessed by this suite. Only repository source
plus disposable Python test database, with no external network.
"""
from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_shared_n8n_receiver_v2_local as install


def create_db(path: pathlib.Path, *, competing_receiver=False):
    source=install._source()
    with sqlite3.connect(path) as db:
        db.executescript("""
            create table project(id text,type text);
            create table workflow_entity(
                id text,name text,active integer,nodes text,
                connections text,settings text
            );
            create table execution_entity(id integer);
            create table shared_workflow(workflowId text);
            insert into project values('personal-fixture-001','personal');
        """)
        if competing_receiver:
            db.execute(
                "insert into workflow_entity values(?,?,?,?,?,?)",
                ("old-legacy","unexpected unrelated inactive",0,
                 json.dumps([{
                     "type":"n8n-nodes-base.webhook",
                     "parameters":{"path":"avuhz-events"},
                 }]),"{}","{}"),
            )
    return source


class LocalN8nReceiverInactiveInstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="avuhz-n8n-src-")
        self.addCleanup(self.tmp.cleanup)
        self.path=pathlib.Path(self.tmp.name)/"only-fictional-n8n.sqlite"
        self.source=create_db(self.path)

    def inventory(self,**kwargs):
        with sqlite3.connect(self.path.as_uri()+"?mode=ro",uri=True) as db:
            db.execute("pragma query_only=ON")
            return install._inventory(db,self.source,**kwargs)

    def test_canonical_source_digest_is_exact_and_unbound(self):
        self.assertEqual(
            install.SOURCE_SHA256,
            "fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f",
        )
        self.assertFalse(self.source["active"])
        self.assertNotIn("credentials",self.source)
        self.assertEqual(
            self.source["nodes"][2]["parameters"]["url"],install.UNBOUND_RECEIPT,
        )
        with patch.object(install,"SOURCE_SHA256","0"*64):
            with self.assertRaisesRegex(install.LocalReceiverInstallDenied,
                                        "^receiver_source_untrusted$"):
                install._source()

    def test_readonly_inventory_cannot_approve_preexisting_receiver_or_path(self):
        self.assertEqual(self.inventory().workflow_count,0)
        with sqlite3.connect(self.path) as db:
            db.execute("insert into workflow_entity values(?,?,?,?,?,?)",
                ("prior","unrelated inactive",0,
                 json.dumps([{"type":"n8n-nodes-base.webhook",
                              "parameters":{"path":"avuhz-events"}}]),
                 "{}","{}"))
        with self.assertRaisesRegex(install.LocalReceiverInstallDenied,
                                    "^local_receiver_install_boundary_denied$"):
            self.inventory()

    def test_active_workflow_execution_or_second_personal_project_blocks(self):
        changes=(
            "insert into workflow_entity values('any','unrelated',1,'[]','{}','{}')",
            "insert into execution_entity values(1)",
            "insert into project values('second','personal')",
        )
        for statement in changes:
            with self.subTest(statement=statement):
                with sqlite3.connect(self.path) as db:db.execute(statement)
                with self.assertRaisesRegex(install.LocalReceiverInstallDenied,
                                            "^local_receiver_install_boundary_denied$"):
                    self.inventory()
                with sqlite3.connect(self.path) as db:
                    if "workflow_entity" in statement:db.execute("delete from workflow_entity")
                    if "execution_entity" in statement:db.execute("delete from execution_entity")
                    if "project" in statement:db.execute("delete from project where id='second'")

    def test_inactive_import_postcondition_requires_exact_source_one_workflow(self):
        previous=self.inventory()
        with sqlite3.connect(self.path) as db:
            db.execute("insert into workflow_entity values(?,?,?,?,?,?)",(
                "1234567890abcdef",self.source["name"],0,
                json.dumps(self.source["nodes"]),
                json.dumps(self.source["connections"]),
                json.dumps(self.source["settings"]),
            ))
            db.execute("insert into shared_workflow values('1234567890abcdef')")
        result=self.inventory(
            expected_install_id="1234567890abcdef",
            previous_count=previous.workflow_count,
        )
        self.assertEqual(result.receiver_matches,1)
        self.assertEqual(result.active_count,0)
        self.assertEqual(result.executions,0)
        self.assertEqual(result.shared_webhook_paths,1)
        with self.assertRaises(install.LocalReceiverInstallDenied):
            self.inventory()  # deny accidental reinstallation

    def test_wrong_or_credential_bound_postcondition_fails_closed(self):
        previous=self.inventory()
        corrupted=[dict(node) for node in self.source["nodes"]]
        corrupted[0]["credentials"]={"httpHeaderAuth":{"id":"fake-secret-binding"}}
        with sqlite3.connect(self.path) as db:
            db.execute("insert into workflow_entity values(?,?,?,?,?,?)",(
                "1234567890abcdef",self.source["name"],0,
                json.dumps(corrupted),json.dumps(self.source["connections"]),
                json.dumps(self.source["settings"]),
            ))
            db.execute("insert into shared_workflow values('1234567890abcdef')")
        with self.assertRaisesRegex(install.LocalReceiverInstallDenied,
                                    "^local_receiver_install_boundary_denied$"):
            self.inventory(
                expected_install_id="1234567890abcdef",
                previous_count=previous.workflow_count,
            )

    def test_preflight_never_issues_install_or_prints_project_id(self):
        original=install._inspect_source_and_installed
        report=self.inventory()
        with (
            patch.object(install,"_inspect_source_and_installed",
                         return_value=(self.source,self.path,report)),
            patch.object(install,"_import_one") as do_import,
            patch.dict("os.environ",{"CI":"","GITHUB_ACTIONS":"",
                                     "AVUHZ_ENVIRONMENT":"LOCAL"}),
        ):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                result=install.run(["--target",install.TARGET])
        self.assertEqual(result,0)
        self.assertIn("no resource changes",output.getvalue())
        self.assertNotIn("personal-fixture-001",output.getvalue())
        do_import.assert_not_called()

    def test_missing_explicit_approval_or_ci_blocks_before_touching_any_db(self):
        import os
        cases=[
            ([],{"CI":"","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"LOCAL"}),
            (["--approved-source-sha256","sha256:"+"0"*64],
             {"CI":"","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"LOCAL"}),
            (["--approved-source-sha256","sha256:"+install.SOURCE_SHA256],
             {"CI":"true","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"LOCAL"}),
            (["--approved-source-sha256","sha256:"+install.SOURCE_SHA256],
             {"CI":"","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"PRODUCTION"}),
        ]
        for rest,env in cases:
            with (
                self.subTest(rest=rest,env=env),
                patch.dict(os.environ,env),
                patch.object(install,"_inspect_source_and_installed") as check,
                patch.object(install,"_import_one") as do_import,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                status=install.run(["--target",install.TARGET,"--install-inactive"]+rest)
                self.assertEqual(status,2)
                check.assert_not_called()
                do_import.assert_not_called()

    def test_import_uses_one_supported_n8n_cli_command_no_credentials(self):
        code="1234567890abcdef"
        args=[]
        def mock_run(cmd,**kwargs):
            args.append((cmd,kwargs))
            return subprocess.CompletedProcess(cmd,0,b"",b"")
        with patch.object(install.subprocess,"run",side_effect=mock_run):
            install._import_one(self.source,"personal-fixture-001",code)
        self.assertEqual(len(args),1)
        cmd,opts=args[0]
        self.assertEqual(cmd,["docker","exec","-i","n8n","n8n",
                             "import:workflow","--input=/dev/stdin",
                             "--projectId=personal-fixture-001"])
        sent=json.loads(opts["input"])
        self.assertEqual(len(sent),1)
        self.assertEqual(sent[0]["id"],code)
        self.assertFalse(sent[0]["active"])
        self.assertNotIn("credentials",sent[0])
        self.assertFalse(any("credentials" in node for node in sent[0]["nodes"]))
        self.assertNotIn("secret_value",json.dumps(sent).lower())
        self.assertTrue(opts["timeout"]<=60)

    def test_failed_cli_does_not_retry_or_expose_output(self):
        with patch.object(install.subprocess,"run",
             return_value=subprocess.CompletedProcess([],1,b"private-token",b"secret")) as proc:
            with self.assertRaisesRegex(install.LocalReceiverInstallDenied,
                          "^inactive_receiver_import_unverified$"):
                install._import_one(self.source,"personal-fixture-001","1234567890abcdef")
        self.assertEqual(proc.call_count,1)

    def test_exact_opt_in_calls_one_cli_and_checks_db_postconditions(self):
        report=self.inventory()
        run_calls=[]
        def import_one(source,project,id_value):
            run_calls.append((project,id_value))
            with sqlite3.connect(self.path) as db:
                db.execute("insert into workflow_entity values(?,?,?,?,?,?)",(
                    id_value,source["name"],0,json.dumps(source["nodes"]),
                    json.dumps(source["connections"]),
                    json.dumps(source["settings"]),
                ))
                db.execute("insert into shared_workflow values(?)",(id_value,))
        import os
        with (
            patch.object(install,"_inspect_source_and_installed",
                         return_value=(self.source,self.path,report)),
            patch.object(install,"_import_one",side_effect=import_one),
            patch.object(install.secrets,"token_hex",return_value="1234567890abcdef"),
            patch.dict(os.environ,{"CI":"","GITHUB_ACTIONS":"",
                                   "AVUHZ_ENVIRONMENT":"LOCAL"}),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            outcome=install.run([
                "--target",install.TARGET,"--install-inactive",
                "--approved-source-sha256","sha256:"+install.SOURCE_SHA256,
            ])
        self.assertEqual(outcome,0)
        self.assertEqual(len(run_calls),1)
        self.assertEqual(run_calls[0],("personal-fixture-001","1234567890abcdef"))
        self.assertIn("exactly one new inactive",output.getvalue())
        self.assertNotIn("personal-fixture-001",output.getvalue())
        self.assertNotIn("1234567890abcdef",output.getvalue())


if __name__=="__main__":
    unittest.main()
