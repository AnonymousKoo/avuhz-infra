"""Offline no-network tests for a read-only first shared receiver QA gate."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_shared_n8n_v2_local_first_event_qa as qa
from avuhz_worker.local_n8n_receipt_store import LocalN8nReceiptStore


class FirstSharedEventTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="avuhz-shared-first-event-qa-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.receipts = self.root / "receipts.sqlite"
        self.workflow = self.root / "n8n.sqlite"
        self.event = qa.fictional_event()

    def _receipt_db(self, rows=()):
        with sqlite3.connect(self.receipts) as db:
            db.execute("""
              CREATE TABLE local_n8n_receipts (
                trusted_tenant_id TEXT,
                delivery_key TEXT,
                event_id TEXT,
                envelope_digest TEXT
              )
            """)
            db.executemany(
                "INSERT INTO local_n8n_receipts VALUES(?,?,?,?)",rows
            )
        os.chmod(self.receipts, 0o600)

    def _good_row(self):
        return (qa.TENANT_ID,qa.QA_DELIVERY_KEY,qa.QA_EVENT_ID,qa._digest(self.event))

    def test_transport_event_has_strict_eight_fields_no_customer_data(self):
        self.assertEqual(set(self.event), {
            "event_id","event_type","tenant_id","correlation_id",
            "occurred_at","authoritative_subject_reference",
            "authoritative_subject_version","delivery_idempotency_key",
        })
        self.assertEqual(self.event["tenant_id"],qa.TENANT_ID)
        self.assertEqual(self.event["authoritative_subject_reference"],{
            "reference_type":"ACQUISITION_INTAKE",
            "reference_id":"a4730000-0000-4000-8000-000000000021",
        })
        encoded=json.dumps(self.event)
        for prohibited in ("qa-operator","contact_email","Fictional QA Operator","business_name","diagnostic_summary"):
            self.assertNotIn(prohibited,encoded)
        self.assertLessEqual(len(encoded.encode()),4096)
        pure=object.__new__(LocalN8nReceiptStore)
        pure._tenant_id=qa.TENANT_ID
        pure._allowed=frozenset({"acquisition.intake.received"})
        actual=pure._validated_digest(self.event,delivery_header=qa.QA_DELIVERY_KEY)
        self.assertEqual(actual,qa._digest(self.event))

    def test_fixture_hash_or_fake_owner_drift_is_denied(self):
        with patch.object(qa,"_sha256",return_value="drift"):
            with self.assertRaises(qa.FirstEventQaDenied):
                qa.fictional_event()
        raw=json.loads(qa.FIXTURE_PATH.read_text())
        raw["owner_is_real_or_verified"]=True
        with (
            patch.object(qa,"_sha256",return_value=qa.EXPECTED_FIXTURE_SHA256),
            patch.object(Path,"read_text",return_value=json.dumps(raw)),
        ):
            with self.assertRaises(qa.FirstEventQaDenied):
                qa.fictional_event()

    def test_empty_private_receipts_required_before_first_event(self):
        self._receipt_db()
        self.assertEqual(qa._receipt_readback(self.receipts,self.event,False),0)
        with self.assertRaises(ValueError):
            qa._receipt_readback(self.receipts,self.event,True)

    def test_one_exact_receipt_only_after_separately_authorized_test(self):
        self._receipt_db([self._good_row()])
        self.assertEqual(qa._receipt_readback(self.receipts,self.event,True),1)
        with self.assertRaises(ValueError):
            qa._receipt_readback(self.receipts,self.event,False)

    def test_tampering_cross_tenant_digest_and_duplicate_row_are_denied(self):
        for bad in (
            ("a4730000-0000-4000-8000-000000000099",qa.QA_DELIVERY_KEY,qa.QA_EVENT_ID,qa._digest(self.event)),
            (qa.TENANT_ID,qa.QA_DELIVERY_KEY,qa.QA_EVENT_ID,"0"*64),
            (qa.TENANT_ID,"other.qa.delivery",qa.QA_EVENT_ID,qa._digest(self.event)),
            (qa.TENANT_ID,qa.QA_DELIVERY_KEY,"a4730000-0000-4000-8000-000000000099",qa._digest(self.event)),
        ):
            with self.subTest(field=bad[:3]):
                if self.receipts.exists():self.receipts.unlink()
                self._receipt_db([bad])
                with self.assertRaises(ValueError):
                    qa._receipt_readback(self.receipts,self.event,True)
        self.receipts.unlink()
        self._receipt_db([self._good_row(),self._good_row()])
        with self.assertRaises(ValueError):
            qa._receipt_readback(self.receipts,self.event,True)

    def test_bad_permission_or_symlink_private_store_denied(self):
        self._receipt_db([self._good_row()])
        os.chmod(self.receipts,0o644)
        with self.assertRaises(ValueError):
            qa._receipt_readback(self.receipts,self.event,True)
        os.chmod(self.receipts,0o600)
        link=self.root/"symlink.sqlite"
        link.symlink_to(self.receipts)
        with self.assertRaises(ValueError):
            qa._receipt_readback(link,self.event,True)

    def _create_synthetic_n8n(self, *, drift=None):
        source=qa.receiver._source()
        nodes=copy.deepcopy(source["nodes"])
        inbound_id="synthetic-only-inbound"
        nodes[0]["credentials"]={
            "httpHeaderAuth":{"id":inbound_id,"name":qa.inbound.CREDENTIAL_NAME}
        }
        nodes[2]["parameters"]["url"]="http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts"
        nodes[2]["credentials"]={
            "httpHeaderAuth":{"id":qa.RECEIPT_CREDENTIAL_ID,"name":qa.receipt.CREDENTIAL_NAME}
        }
        if drift=="wrong_token_reference":
            nodes[2]["credentials"]["httpHeaderAuth"]["id"]="wrong"
        if drift=="unsafe_url":
            nodes[2]["parameters"]["url"]="http://0.0.0.0:3333"
        records=[
            (qa.RECEIVER_ID,source["name"],0,0,json.dumps(nodes),
             json.dumps(source["connections"]),json.dumps(source["settings"]),None,None)
        ]
        for i in range(6):
            records.append((
                "dummy-"+str(i),"Synthetic inactive workflow "+str(i),0,int(i==5),
                "[]","{}","{}",None,None,
            ))
        if drift=="active":
            rec=list(records[0]);rec[2]=1;records[0]=tuple(rec)
        with sqlite3.connect(self.workflow) as db:
            db.executescript("""
              CREATE TABLE project(id TEXT,type TEXT);
              CREATE TABLE workflow_entity(
                id TEXT,name TEXT,active INTEGER,isArchived INTEGER,nodes TEXT,
                connections TEXT,settings TEXT,staticData TEXT,pinData TEXT
              );
              CREATE TABLE credentials_entity(id TEXT,name TEXT,type TEXT,data TEXT);
              CREATE TABLE shared_credentials(credentialsId TEXT,projectId TEXT,role TEXT);
              CREATE TABLE shared_workflow(workflowId TEXT,projectId TEXT,role TEXT);
              CREATE TABLE execution_entity(id TEXT);
            """)
            db.execute("INSERT INTO project VALUES(?,?)",("test-only-project","personal"))
            db.executemany("INSERT INTO workflow_entity VALUES(?,?,?,?,?,?,?,?,?)",records)
            db.executemany("INSERT INTO credentials_entity VALUES(?,?,?,?)",[
                (inbound_id,qa.inbound.CREDENTIAL_NAME,"httpHeaderAuth","a"*100),
                (qa.RECEIPT_CREDENTIAL_ID,qa.receipt.CREDENTIAL_NAME,"httpHeaderAuth","b"*100),
            ])
            db.executemany("INSERT INTO shared_credentials VALUES(?,?,?)",[
                (inbound_id,"test-only-project","credential:owner"),
                (qa.RECEIPT_CREDENTIAL_ID,"test-only-project","credential:owner"),
            ])
            db.execute("INSERT INTO shared_workflow VALUES(?,?,?)",
                (qa.RECEIVER_ID,"test-only-project","workflow:owner"))
        return source

    def test_installed_bound_receiver_requires_only_approved_url_and_credentials(self):
        source=self._create_synthetic_n8n()
        with patch.object(qa.receiver,"_db_path",return_value=self.workflow):
            self.assertEqual(qa._bound_receiver_readback(
                source,"http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts"
            ),(6,1,0,0))

    def test_wrong_credential_url_or_activation_fails_closed(self):
        for drift in ("wrong_token_reference","unsafe_url","active"):
            with self.subTest(drift=drift):
                if self.workflow.exists():self.workflow.unlink()
                source=self._create_synthetic_n8n(drift=drift)
                with patch.object(qa.receiver,"_db_path",return_value=self.workflow):
                    with self.assertRaises(ValueError):
                        qa._bound_receiver_readback(
                            source,"http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts"
                        )

    def test_default_cli_never_activates_executes_or_reads_secrets(self):
        report=qa.QaReadback(
            "http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts",
            54321,0,6,1,0,0,
        )
        with (
            patch.dict(os.environ,{"CI":"","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"LOCAL"}),
            patch.object(qa,"preflight",return_value=report) as pre,
            patch.object(qa,"subprocess",create=True) as disallowed,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(qa.run(["--target",qa.TARGET]),0)
        pre.assert_called_once_with(expect_one=False)
        disallowed.assert_not_called()
        self.assertIn("no event sent",output.getvalue())

    def test_wrong_target_ci_prod_all_block_before_inspection(self):
        for args,env in (
            (["--target","PRODUCTION"],{"AVUHZ_ENVIRONMENT":"LOCAL"}),
            (["--target",qa.TARGET],{"AVUHZ_ENVIRONMENT":"PRODUCTION"}),
            (["--target",qa.TARGET],{"AVUHZ_ENVIRONMENT":"TEST"}),
            (["--target",qa.TARGET],{"CI":"true"}),
            (["--target",qa.TARGET],{"GITHUB_ACTIONS":"true"}),
        ):
            with (
                self.subTest(args=args,env=env),
                patch.dict(os.environ,{"CI":"","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"LOCAL",**env}),
                patch.object(qa,"preflight") as pre,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(qa.run(args),2)
                pre.assert_not_called()
                self.assertNotIn("PASS",output.getvalue())

    def test_expect_one_mode_never_claims_real_n8n_or_work_certification(self):
        report=qa.QaReadback(
            "http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts",
            54321,1,6,1,0,0,
        )
        with (
            patch.dict(os.environ,{"CI":"","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"LOCAL"}),
            patch.object(qa,"preflight",return_value=report),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(qa.run(["--target",qa.TARGET,"--expect-one-receipt"]),0)
        self.assertIn("NOT CERTIFIED",output.getvalue())
        self.assertIn("transport storage only",output.getvalue())


if __name__=="__main__":
    unittest.main()
