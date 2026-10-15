"""LOCAL-only preflight: source-bound n8n workflow without side effects."""
from __future__ import annotations

import copy
import json
import sqlite3
import unittest
from pathlib import Path

from src.avuhz_worker.local_system001_n8n_readiness import (
    LocalN8nPreflightDenied, examine_installed_workflow,
)

ROOT=Path(__file__).resolve().parents[2]
SOURCE=json.loads((ROOT/"contracts/templates/n8n/avuhz-system-001-revenue-receipt-gated-inactive-v2.json").read_text())
QA=json.loads((ROOT/"tests/fixtures/system001_qa_tenant_local_v1.json").read_text())


def make_db(source=None, *, active=0, executions=0, assigned=True):
    source=SOURCE if source is None else source
    db=sqlite3.connect(":memory:")
    db.execute("create table workflow_entity (id text,name text,active integer,nodes text,connections text,settings text)")
    db.execute("create table shared_workflow (workflowId text)")
    db.execute("create table execution_entity (id integer)")
    db.execute("insert into workflow_entity values (?,?,?,?,?,?)",(
        "only-local-qa-child",source["name"],active,
        json.dumps(source["nodes"]),json.dumps(source["connections"]),json.dumps(source["settings"]),
    ))
    if assigned:
        db.execute("insert into shared_workflow values (?)",("only-local-qa-child",))
    if executions:
        db.execute("insert into execution_entity values (1)")
    return db


class LocalN8nReadinessTests(unittest.TestCase):
    def test_exact_installed_inactive_child_and_fictional_qa_are_safely_reported(self):
        with make_db() as db:
            ready=examine_installed_workflow(db,SOURCE,QA)
            self.assertEqual(ready["installed_node_count"],5)
            self.assertEqual(ready["existing_execution_rows"],0)
            self.assertFalse(ready["real_n8n_execution_certified"])
            self.assertFalse(ready["credential_bound"])
            self.assertFalse(ready["receipt_endpoint_configured"])
            self.assertFalse(ready["owner_lookup_connected"])
            self.assertTrue(ready["qa_fixture_is_fictional"])

    def test_any_activation_prior_execution_or_missing_project_assignment_denies(self):
        for args in ({"active":1},{"executions":1},{"assigned":False}):
            with self.subTest(args=args),make_db(**args) as db:
                with self.assertRaises(LocalN8nPreflightDenied):
                    examine_installed_workflow(db,SOURCE,QA)

    def test_source_drift_hardcoded_keys_or_patched_endpoint_denies(self):
        for edit in ("api","bad-url","secret","deleted-node","edges"):
            src=copy.deepcopy(SOURCE)
            if edit=="api": src["nodes"][2]["parameters"]["method"]="GET"
            if edit=="bad-url": src["nodes"][2]["parameters"]["url"]="https://public.example.invalid"
            if edit=="secret": src["nodes"][2]["credentials"]={"httpHeaderAuth":{"id":"do-not-trust"}}
            if edit=="deleted-node": src["nodes"].pop()
            if edit=="edges": src["connections"]={}
            with self.subTest(edit=edit),make_db(src) as db:
                with self.assertRaises(LocalN8nPreflightDenied):
                    examine_installed_workflow(db,SOURCE,QA)

    def test_reject_fake_qa_verification_or_real_email(self):
        for field,value in (
            ("owner_is_real_or_verified",True),
            ("production_allowed",True),
            ("hosted_data_insert_authorized",True),
            ("fixture_name","SekInfra"),
        ):
            q=copy.deepcopy(QA);q[field]=value
            with self.subTest(field=field),make_db() as db:
                with self.assertRaises(LocalN8nPreflightDenied):
                    examine_installed_workflow(db,SOURCE,q)
        q=copy.deepcopy(QA);q["request"]["contact_email"]="real@example.com"
        with make_db() as db,self.assertRaises(LocalN8nPreflightDenied):
            examine_installed_workflow(db,SOURCE,q)

    def test_absent_or_duplicated_workflow_denies(self):
        with make_db() as db:
            db.execute("delete from workflow_entity")
            with self.assertRaises(LocalN8nPreflightDenied):
                examine_installed_workflow(db,SOURCE,QA)
        with make_db() as db:
            db.execute("insert into workflow_entity select 'clone',name,active,nodes,connections,settings from workflow_entity")
            with self.assertRaises(LocalN8nPreflightDenied):
                examine_installed_workflow(db,SOURCE,QA)


if __name__=="__main__":
    unittest.main()
