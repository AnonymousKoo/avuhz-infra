#!/usr/bin/env python3
"""Certify one real LOCAL n8n -> durable receipt -> QA-owned PostgreSQL Work Item.

CONFIRMED target: DefNet LOCAL Docker n8n bridge, currently inactive v2 child.
NO hosted DATA/AUTH, production, public URL, customer, or external provider writes.
Secret stays in memory/pipe, is encrypted by n8n importer at rest, never logged.
Reuses or creates exactly one inactive manual QA parent and encrypted credential;
never direct-mutates SQLite.
"""
from __future__ import annotations

import copy
import json
import os
import pathlib
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/"src"))
from avuhz_worker.local_n8n_receipt_dev_runner import inspect_private_local_n8n
from avuhz_worker.local_n8n_receipt_store import LocalN8nReceiptStore
from avuhz_worker.local_system001_n8n_readiness import examine_installed_workflow

CONTAINER="n8n"
CHILD_NAME="Avuhz System #001 Revenue Intake - DURABLE RECEIPT GATE (LOCAL TEST / INACTIVE v2)"
PARENT_NAME="Avuhz System #001 LOCAL QA manual valid-ID retry - INACTIVE"
CRED_NAME="Avuhz System #001 LOCAL QA temporary encrypted receipt 20261015"

def say(stage,ok=True):
    print(("PASS " if ok else "BLOCKED ")+stage,flush=True)

def safe_run(args,stdin=None,timeout=50):
    # Provider CLI output discarded: never relay incidental credential/log contents.
    p=subprocess.run(args,input=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                     timeout=timeout,check=False)
    return p.returncode==0

def get_db():
    mount=subprocess.check_output(["docker","inspect","-f",
       '{{range .Mounts}}{{if eq .Destination "/home/node/.n8n"}}{{.Source}}{{end}}{{end}}',
       CONTAINER],text=True,stderr=subprocess.DEVNULL,timeout=8).strip()
    path=pathlib.Path(mount)/"database.sqlite"
    if not path.is_file() or path.is_symlink(): raise RuntimeError("local_db_unavailable")
    return path

def query(path,sql,args=()):
    with sqlite3.connect("file:"+str(path)+"?mode=ro",uri=True,timeout=5) as db:
        return db.execute(sql,args).fetchall()

def import_stdin(kind,document,project):
    encoded=json.dumps([document],separators=(",",":")).encode("utf-8")
    if not safe_run(["docker","exec","-i",CONTAINER,"n8n",
                     "import:"+kind,"--input=/dev/stdin","--projectId="+project],
                    stdin=encoded,timeout=55):
        raise RuntimeError("n8n_import_"+kind+"_failed")

def build_committed_local_acquisition_envelope(qa: dict) -> tuple[dict, str]:
    """Test-only real shared HTTP/writer/outbox projection, never hosted auth.

    Use the existing isolated synthetic HTTP identity+DATA doubles to stage the
    exact approved fictional QA request. Its actual committed event is then
    projected by the existing shared OutboxWorker + N8nOutboxSink. A synthetic
    HTTPS transport captures the sanitized event *without* contacting n8n,
    using a generated in-memory credential. The result is passed to the real
    installed n8n child by the existing LOCAL-only certifier.

    This bridge is not a real autonomous/hosted acquisition SQL connector.
    No browser/n8n-supplied claims or synthetic owner may authorize hosted work.
    """
    from avuhz_worker import MemoryOutboxUnitOfWork, OutboxWorker, WorkerSettings
    from avuhz_worker.n8n_event_sink import N8nOutboxSink
    from tests.integration.test_acquisition_http_to_n8n_synthetic_journey import (
        event_and_outbox_from_committed_intake,
    )
    service_tests = str(ROOT / "tests" / "service")
    worker_tests = str(ROOT / "tests" / "worker")
    for path in (service_tests, worker_tests):
        if path not in sys.path:
            sys.path.insert(0, path)
    from test_development_acquisition_http import application, request, TOKEN
    from test_outbox_worker import MutableClock, context

    if (
        type(qa) is not dict
        or qa.get("fixture_type") != "LOCAL_TEST_ONLY_FICTIONAL_CLIENT"
        or qa.get("owner_is_real_or_verified") is not False
        or qa.get("production_allowed") is not False
        or qa.get("hosted_data_insert_authorized") is not False
        or type(qa.get("request")) is not dict
        or qa.get("tenant_id") != "a4730000-0000-4000-8000-000000000001"
        or qa["request"].get("external_request_id") != "a4730000-0000-4000-8000-000000000021"
        or qa["request"].get("contact_email") != "qa-operator@example.invalid"
        or qa["request"].get("source_system") != "avuhz.qa"
    ):
        raise RuntimeError("fictional_acquisition_fixture_invalid")

    app, store = application()
    status, result, headers = request(app, obj=qa["request"])
    if (
        status != 202
        or type(result) is not dict
        or result.get("duplicate") is not False
        or type(result.get("intake_id")) is not str
        or headers.get("Cache-Control") != "no-store"
        or len(store.connections) != 2
    ):
        raise RuntimeError("fictional_acquisition_not_committed")
    memory = event_and_outbox_from_committed_intake(store)
    if (
        len(memory.events) != 1
        or memory.events[0].get("event_type") != "acquisition.intake.received"
        or memory.events[0].get("tenant_id") != qa["tenant_id"]
        or memory.events[0].get("authoritative_subject_reference") != {
            "reference_type": "ACQUISITION_INTAKE",
            "reference_id": result["intake_id"],
        }
    ):
        raise RuntimeError("fictional_acquisition_event_invalid")

    # The real sink performs canonical event schema and tenant validation and
    # excludes metadata, contact information and all other PII. The post
    # callback cannot make network calls and sees a synthetic .invalid URL.
    delivered = []
    ephemeral = secrets.token_urlsafe(32)
    def capture_qa_delivery(url, headers, raw):
        if (
            url != "https://n8n.example.invalid/webhook/avuhz-events"
            or headers.get("X-Avuhz-Webhook-Token") != ephemeral
            or headers.get("Content-Type") != "application/json"
            or len(raw) > 4096
        ):
            return 403
        delivered.append((headers["X-Avuhz-Delivery-Key"], bytes(raw)))
        return 202

    sink = N8nOutboxSink(
        environment="TEST", tenant_id=qa["tenant_id"],
        endpoint="https://n8n.example.invalid/webhook/avuhz-events",
        expected_host="n8n.example.invalid",
        credential_provider=lambda: ephemeral, post=capture_qa_delivery,
    )
    worker = OutboxWorker(
        memory, MemoryOutboxUnitOfWork, sink, context(tenant=qa["tenant_id"]),
        WorkerSettings(
            tenant_id=qa["tenant_id"],
            worker_reference="outbox.worker-local-system001-qa",
            base_backoff_seconds=5, max_attempts=3,
        ),
        clock=MutableClock(),
    )
    outcome = worker.run_once()
    if (
        outcome != {
            "claimed": 1, "published": 1,
            "retry_scheduled": 0, "dead_lettered": 0,
        }
        or len(delivered) != 1
        or memory.outbox[0]["status"] != "PUBLISHED"
        or worker.run_once()["claimed"] != 0
    ):
        raise RuntimeError("fictional_acquisition_outbox_not_published")
    envelope = json.loads(delivered[0][1])
    if (
        type(envelope) is not dict
        or set(envelope) != {
            "event_id", "event_type", "tenant_id", "correlation_id",
            "occurred_at", "authoritative_subject_reference",
            "authoritative_subject_version", "delivery_idempotency_key",
        }
        or envelope["delivery_idempotency_key"] != delivered[0][0]
        or envelope["tenant_id"] != qa["tenant_id"]
        or envelope["authoritative_subject_reference"]["reference_id"]
            != result["intake_id"]
        or any(
            type(qa["request"].get(k)) is str and
            qa["request"][k] in delivered[0][1].decode("utf-8")
            for k in ("contact_name", "contact_email", "business_name",
                      "diagnostic_summary")
        )
        or TOKEN in delivered[0][1].decode("utf-8")
        or ephemeral in delivered[0][1].decode("utf-8")
    ):
        raise RuntimeError("fictional_acquisition_envelope_invalid")
    return envelope, result["intake_id"]


def verify_local_real_n8n_to_postgres(
    qa:dict, envelope:dict, receipt:LocalN8nReceiptStore, private:pathlib.Path, *,
    committed_acquisition_id:str,
) -> None:
    """Receipt from ACTUAL n8n -> LOCAL test acquisition -> real PostgreSQL.

    The lookup and identity are entirely synthetic and separately created
    by this LOCAL/TEST certifier, never by the untrusted n8n envelope.
    The PostgreSQL writer uses existing Avuhz migrations, restricted service
    role, member checks, RLS, lifecycle events and idempotency.
    """
    from avuhz_service.shared_work_intake_candidate import WorkIntakeCommand, WorkIntakeDenied
    from avuhz_service.shared_revenue_followup_review import FollowupReviewPolicy
    from avuhz_service.shared_due_work_reader_candidate import SharedDueWorkReadCandidate
    from avuhz_worker.local_system001_governed_handoff import (
        AuthorizedAcquisitionSnapshot, LocalSystem001GovernedHandoff,
        LocalSystem001HandoffDenied,
    )
    from tests.integration.test_shared_work_intake_postgres_candidate import (
        SharedDurableWorkIntakePostgresTests, TENANT_A
    )
    if (qa["tenant_id"]!=TENANT_A or
        qa["work_item_id"]==qa["request"]["external_request_id"] or
        envelope["tenant_id"]!=TENANT_A or
        envelope["authoritative_subject_reference"]["reference_id"]!=committed_acquisition_id):
        raise RuntimeError("pg_source_tenant_mismatch")
    if not receipt.committed(envelope,delivery_header=envelope["delivery_idempotency_key"]):
        raise RuntimeError("receipt_not_committed")
    # Independently prepare the synthetic QA source registry; the envelope is
    # not trusted as source metadata. Source data comes ONLY from local fixture.
    lookup_db=private/"qa-acquisition.sqlite"
    with sqlite3.connect(lookup_db) as db:
        db.execute('CREATE TABLE qa_acquisition (intake_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, work_item_id TEXT NOT NULL, source TEXT NOT NULL, classification TEXT NOT NULL, due TEXT NOT NULL, owner_evidence TEXT NOT NULL)')
        db.execute('INSERT INTO qa_acquisition VALUES (?,?,?,?,?,?,?)',(
            committed_acquisition_id,qa["tenant_id"],
            qa["work_item_id"],"web","service_request",qa["next_action_due_at"],
            "sender"))
    case=SharedDurableWorkIntakePostgresTests(
        methodName="test_local_committed_n8n_receipt_requires_independent_owner_for_real_work_writer"
    )
    case.setUpClass()
    case.setUp()
    try:
        case.writer._clock=lambda:datetime(2030,1,15,16,0,tzinfo=timezone.utc)
        def resolve_source(intake_id):
            with sqlite3.connect("file:"+str(lookup_db)+"?mode=ro",uri=True) as db:
                row=db.execute(
                    'SELECT intake_id, tenant_id, work_item_id, source, classification, due, owner_evidence FROM qa_acquisition WHERE intake_id=?',
                    (intake_id,)
                ).fetchone()
            if row is None:
                return None
            return AuthorizedAcquisitionSnapshot(
                tenant_id=row[1],intake_id=row[0],work_item_id=row[2],
                state="RECEIVED",source=row[3],classification=row[4],
                next_action_due_at=row[5],owner_identity_evidence=row[6],
            )
        handoff=LocalSystem001GovernedHandoff(
            receipt_store=receipt,
            resolve_acquisition=resolve_source,
            resolve_owner_identity=case.resolve_identity,
            work_writer=case.writer,
        )
        # Valid HUMAN from another tenant must NOT get a side effect.
        with sqlite3.connect(lookup_db) as db:
            db.execute('UPDATE qa_acquisition SET owner_evidence=?',
                       ("outside",))
        try:
            handoff.open_receipted_intake(envelope,delivery_header=envelope["delivery_idempotency_key"])
        except LocalSystem001HandoffDenied:
            pass
        else:
            raise RuntimeError("cross_tenant_owner_not_denied")
        if case.table("avuhz_work_items"):
            raise RuntimeError("unauthorized_work_inserted")
        say("cross-tenant human denied before actual PostgreSQL Work Item writer")
        with sqlite3.connect(lookup_db) as db:
            db.execute('UPDATE qa_acquisition SET owner_evidence=?',
                       ("sender",))
        created=handoff.open_receipted_intake(
            envelope,delivery_header=envelope["delivery_idempotency_key"])
        replay=handoff.open_receipted_intake(
            envelope,delivery_header=envelope["delivery_idempotency_key"])
        if not (created.accepted_version==1 and not created.replayed
                and replay.accepted_version==1 and replay.replayed):
            raise RuntimeError("durable_handoff_not_idempotent")
        for table in ("avuhz_work_items","avuhz_idempotency_records",
                      "avuhz_lifecycle_events","avuhz_outbox_deliveries"):
            if len(case.table(table))!=1:
                raise RuntimeError("durable_work_table_count_invalid")
        item=case.table("avuhz_work_items")[0]
        if (str(item["tenant_id"])!=TENANT_A
            or item["owner_reference"]!=qa["work_owner_reference"]
            or item["next_action_due_at"].strftime("%Y-%m-%dT%H:%M:%SZ")!=qa["next_action_due_at"]):
            raise RuntimeError("durable_work_owner_due_invalid")
        say("real n8n receipt -> exactly one PG Work Item/idempotency/lifecycle/outbox and deadline")
        reader=SharedDueWorkReadCandidate(
            case.store,resolve_identity=case.resolve_identity,
            resolve_tenant_member=case.resolve_tenant_member,
        )
        policy=FollowupReviewPolicy(escalation_after_minutes=15)
        due=reader.review_owned_due(
            "sender",policy=policy,now=datetime(2030,1,15,16,5,tzinfo=timezone.utc))
        escalation=reader.review_owned_due(
            "sender",policy=policy,now=datetime(2030,1,15,16,21,tzinfo=timezone.utc))
        denied=reader.review_owned_due(
            "outside",policy=policy,now=datetime(2030,1,15,16,21,tzinfo=timezone.utc))
        if (len(due)!=1 or due[0].kind!="FOLLOWUP_DUE"
            or len(escalation)!=1 or escalation[0].kind!="FOLLOWUP_ESCALATION_REVIEW_REQUIRED"
            or denied!=()):
            raise RuntimeError("due_or_tenant_isolation_unverified")
        say("persisted due review/escalation and tenant isolation certified")
        # Handoff and resolution through the shared core service, not n8n.
        case.writer.execute("sender",WorkIntakeCommand(
            "OFFER_HANDOFF",qa["work_item_id"],"qa-live-offer-0001",
            expected_record_version=1,recipient="worker.receiver"))
        case.writer.execute("receiver",WorkIntakeCommand(
            "ACCEPT_HANDOFF",qa["work_item_id"],"qa-live-accept-0001",
            expected_record_version=2))
        case.writer.execute("receiver",WorkIntakeCommand(
            "RESOLVE",qa["work_item_id"],"qa-live-resolve-0001",
            expected_record_version=3))
        if (case.table("avuhz_work_items")[0]["state"]!="RESOLVED"
            or case.table("avuhz_work_items")[0]["owner_reference"]!="worker.receiver"
            or len(case.table("avuhz_lifecycle_events"))!=4
            or len(case.table("avuhz_outbox_deliveries"))!=4):
            raise RuntimeError("handoff_resolution_failed")
        try:
            case.writer.execute("sender",WorkIntakeCommand(
                "BLOCK",qa["work_item_id"],"qa-old-owner-block-0001",
                expected_record_version=4))
        except WorkIntakeDenied:
            pass
        else:
            raise RuntimeError("previous_owner_not_revoked")
        say("authorized handoff, resolution and revoked former owner certified")
    finally:
        case.tearDown()


def main():
    target=inspect_private_local_n8n()
    db=get_db()
    qa=json.loads((ROOT/"tests/fixtures/system001_qa_tenant_local_v1.json").read_text())
    source=json.loads((ROOT/"contracts/templates/n8n/avuhz-system-001-revenue-receipt-gated-inactive-v2.json").read_text())
    if not (qa["fixture_type"]=="LOCAL_TEST_ONLY_FICTIONAL_CLIENT"
            and qa["owner_is_real_or_verified"] is False and qa["production_allowed"] is False
            and qa["request"]["contact_email"].endswith(".invalid")
            and source["active"] is False):
        raise RuntimeError("fixture_or_source_boundary")
    childrows=query(db,"SELECT id,active,nodes FROM workflow_entity WHERE name=?",(CHILD_NAME,))
    projects=query(db,"SELECT id FROM project WHERE type='personal'")
    parents=query(db,"SELECT id,active FROM workflow_entity WHERE name=?",(PARENT_NAME,))
    old_cred=query(db,"SELECT id FROM credentials_entity WHERE name=?",(CRED_NAME,))
    old_qa=query(db,"SELECT id,active FROM workflow_entity WHERE name=?",(
        "Avuhz System #001 LOCAL QA one-off MANUAL TEST - INACTIVE",))
    if not (len(childrows)==len(projects)==1 and not childrows[0][1]
            and len(parents)<=1 and len(old_cred)<=1 and len(old_qa)<=1
            and (not parents or (len(parents[0][0])==16 and not parents[0][1]))
            and (not old_qa or (len(old_qa[0][0])==36 and not old_qa[0][1]))
            and len(query(db,"SELECT id FROM workflow_entity WHERE active=1"))==0
            and len(query(db,"SELECT id FROM execution_entity"))==0):
        raise RuntimeError("n8n_not_pristine")
    child_id=childrows[0][0]; project=projects[0][0]
    if len(child_id)>16:
        raise RuntimeError("n8n_child_id_invalid")
    cred_id=old_cred[0][0] if old_cred else str(uuid.uuid4())
    p_id=parents[0][0] if parents else secrets.token_hex(8)
    with sqlite3.connect("file:"+str(db)+"?mode=ro",uri=True) as reader:
        examine_installed_workflow(reader,source,qa)
    say("exact LOCAL n8n project, inactive child, synthetic-only QA fixture")
    # One root-owned scratch receipt dir; only local receipt test data.
    with tempfile.TemporaryDirectory(prefix="avuhz-qa-receipt-") as dirname:
        private=pathlib.Path(dirname)
        os.chmod(private,0o700)
        dbpath=private/"receipt.sqlite"
        token=secrets.token_urlsafe(48)
        read_fd,write_fd=os.pipe()
        cmd=[sys.executable,"-m","avuhz_worker.local_n8n_receipt_dev_runner",
             "--target","LOCAL_DEVELOPMENT_N8N_5678",
             "--trusted-tenant-id",qa["tenant_id"],"--receipt-db",str(dbpath),
             "--serve","--token-fd",str(read_fd)]
        env=os.environ.copy()
        env["PYTHONPATH"]=str(ROOT/"src")+":"+str(ROOT)
        receipt=subprocess.Popen(cmd,cwd=str(ROOT),env=env,stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                 text=True,bufsize=1,pass_fds=(read_fd,))
        os.close(read_fd)
        os.write(write_fd,token.encode("ascii"))
        os.close(write_fd)
        changed=False
        try:
            first=receipt.stdout.readline().strip()
            matched=re.fullmatch(
              r"LOCAL_DEVELOPMENT_RECEIPT_BOUND_PRIVATE http://(172\.\d+\.\d+\.\d+):(\d+)",
              first)
            if not matched or matched.group(1)!=target.gateway or receipt.poll() is not None:
                raise RuntimeError("receipt_private_bind_failed")
            url="http://"+target.gateway+":"+matched.group(2)+"/v1/avuhz/local-n8n-receipts"
            say("private receipt listener bound to verified Docker bridge")
            # Provision/reuse exactly one LOCAL QA credential through n8n's
            # supported encrypted import; never write raw tokens to a file.
            credential={"id":cred_id,"name":CRED_NAME,"type":"httpHeaderAuth",
                        "data":{"name":"X-Avuhz-Receipt-Bridge-Token","value":token}}
            import_stdin("credentials",credential,project)
            token=None
            # Do not read stored secret; verify encrypted n8n data is present
            # and is not plain JSON, and no duplicate credential name exists.
            check=query(db,"SELECT id,type,length(data),substr(data,1,1) FROM credentials_entity WHERE name=?",(CRED_NAME,))
            if (len(check)!=1 or check[0][0]!=cred_id
                or check[0][1]!="httpHeaderAuth" or check[0][2]<20
                or check[0][3]=="{"):
                raise RuntimeError("encrypted_n8n_credential_unverified")
            say("one dedicated QA header credential encrypted by n8n")
            child=copy.deepcopy(source)
            child["id"]=child_id
            child["nodes"][2]["parameters"]["url"]=url
            child["nodes"][2]["credentials"]={"httpHeaderAuth":{"id":cred_id,"name":CRED_NAME}}
            child["active"]=False
            import_stdin("workflow",child,project)
            changed=True
            rows=query(db,"SELECT active,nodes,connections FROM workflow_entity WHERE id=?",(child_id,))
            if len(rows)!=1 or rows[0][0] or query(db,"SELECT id FROM workflow_entity WHERE active=1"):
                raise RuntimeError("child_not_inactive")
            patched=json.loads(rows[0][1])
            if patched[2]["parameters"]["url"]!=url or patched[2]["credentials"]["httpHeaderAuth"]["id"]!=cred_id:
                raise RuntimeError("child_receipt_binding_unverified")
            say("one inactive v2 child bound only to private QA receipt")
            # The event now originates from the shared synthetic HTTP
            # intake's committed lifecycle/outbox, then the real Avuhz
            # outbox worker projects it. No manually invented event payload.
            event, authoritative_intake_id=build_committed_local_acquisition_envelope(qa)
            say("fictional shared HTTP acquisition committed and outbox projected one PII-free event")
            code="return [{json:"+json.dumps(event,separators=(",",":"))+"}];"
            # Current n8n CLI treats workflow IDs over 16 chars as invalid.
            # Reuse the known inactive QA parent, or create one native ID.
            if len(p_id)!=16: raise RuntimeError("parent_id_invalid")
            nodes=[
                {"id":str(uuid.uuid4()),"name":"Manual QA only","type":"n8n-nodes-base.manualTrigger","typeVersion":1,"position":[0,0],"parameters":{}},
                {"id":str(uuid.uuid4()),"name":"Emit one fictional Avuhz event","type":"n8n-nodes-base.code","typeVersion":2,"position":[300,0],"parameters":{"mode":"runOnceForAllItems","jsCode":code}},
                {"id":str(uuid.uuid4()),"name":"Run installed System 001 child","type":"n8n-nodes-base.executeWorkflow","typeVersion":1,"position":[620,0],"parameters":{"source":"database","workflowId":child_id,"mode":"once","waitForSubWorkflow":True}},
            ]
            parent={
                "id":p_id,"name":PARENT_NAME,"nodes":nodes,
                "connections":{
                    nodes[0]["name"]:{"main":[[{"node":nodes[1]["name"],"type":"main","index":0}]]},
                    nodes[1]["name"]:{"main":[[{"node":nodes[2]["name"],"type":"main","index":0}]]},
                },
                "settings":{"executionOrder":"v1","saveDataErrorExecution":"none",
                            "saveDataSuccessExecution":"none","saveManualExecutions":False},
                "active":False,"tags":[]
            }
            import_stdin("workflow",parent,project)
            parents=query(db,"SELECT id,active,nodes FROM workflow_entity WHERE name=?",(PARENT_NAME,))
            if len(parents)!=1 or parents[0][0]!=p_id or parents[0][1]:
                raise RuntimeError("manual_parent_not_inactive")
            say("manual-only, inactive fictional QA input workflow installed")
            # Only ONE manual invocation; never activate or expose a webhook.
            run=subprocess.run(
                ["docker","exec","-e","N8N_RUNNERS_BROKER_PORT=5687",CONTAINER,
                 "n8n","execute","--id="+p_id],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=75,check=False
            )
            invoked=run.returncode==0
            # Never display raw CLI output or event content. The CLI may
            # dump full execution JSON; only static allowlisted classes.
            diagnostic=(run.stdout+run.stderr).decode("utf-8","replace")
            signals=[
                ("task_runner_notice",r"(?i)task.runner|task runner.*(error|timeout|failed)|runner.*not available"),
                ("broker_port_in_use",r"(?i)EADDRINUSE|address already in use"),
                ("subworkflow_denied",r"(?i)workflow.*(not allowed|permission|not found)|not authorized.*workflow"),
                ("event_validation_denied",r"RECEIPT_ENVELOPE_DENIED"),
                ("durable_receipt_not_confirmed",r"DURABLE_RECEIPT_NOT_CONFIRMED"),
                ("receipt_connection_refused",r"(?i)ECONNREFUSED|connect ECONN|connection refused"),
                ("execution_failed",r"Execution was NOT successful|Error executing workflow"),
                ("cli_missing_start",r"Missing node to start execution"),
                ("owner_boundary_marker",r"OWNER_LOOKUP_REQUIRED"),
                ("receipt_new_marker",r"NEW_DURABLE_RECEIPT"),
            ]
            print("QA_CLI_EXECUTION_DIAGNOSTIC "+
                  json.dumps({"returncode_nonzero":not invoked,
                              "matched_safe_classes":[name for name,pattern in signals
                                  if re.search(pattern,diagnostic)]},
                             sort_keys=True),flush=True)
            # No CLI output is exposed; inspect private committed receipt.
            receipts=query(dbpath,"SELECT COUNT(*),COUNT(DISTINCT delivery_key) FROM local_n8n_receipts")
            rows=query(db,"SELECT active FROM workflow_entity WHERE id IN (?,?)",(child_id,p_id))
            if len(rows)!=2 or any(row[0] for row in rows):
                raise RuntimeError("unexpected_workflow_activation")
            if invoked and receipts==[(1,1)] and "OWNER_LOOKUP_REQUIRED" in diagnostic:
                say("ONE actual n8n manual execution delivered exactly one private durable QA receipt")
                verify_local_real_n8n_to_postgres(
                    qa,event,
                    LocalN8nReceiptStore(
                        dbpath,trusted_tenant_id=qa["tenant_id"],
                        allowed_event_types=frozenset({"acquisition.intake.received"})
                    ),private,committed_acquisition_id=authoritative_intake_id
                )
            else:
                say("n8n CLI execution did not certify exact one receipt",False)
                raise RuntimeError("real_n8n_receipt_not_proven")
        finally:
            # Restore v2 child to exact unconfigured source, always inactive.
            if changed:
                clean=copy.deepcopy(source);clean["id"]=child_id;clean["active"]=False
                try:
                    import_stdin("workflow",clean,project)
                    rows=query(db,"SELECT active,nodes FROM workflow_entity WHERE id=?",(child_id,))
                    if len(rows)!=1 or rows[0][0] or "credentials" in json.loads(rows[0][1])[2]:
                        say("child restoration unverified; do not activate",False)
                    else:
                        say("original unbound inactive System #001 child restored")
                except Exception:
                    say("child restoration failed; operator intervention required",False)
            receipt.terminate()
            try:receipt.wait(timeout=5)
            except subprocess.TimeoutExpired:
                receipt.kill();receipt.wait(timeout=5)
            say("private receipt service stopped; local ephemeral receipt database removed")
            # n8n itself retains encrypted QA credential and one inactive
            # manual-only parent. Never delete rows directly from its database.
    say("NO hosted AUTH/DATA/production/customer/billing changes")
if __name__=="__main__":
    try:main()
    except Exception as ex:
        code=str(ex)
        # Keep exact diagnostic safe and limited to static known test codes.
        known={
            "local_db_unavailable","fixture_or_source_boundary",
            "n8n_not_pristine","workflow_changed","receipt_private_bind_failed",
            "n8n_import_credentials_failed","encrypted_n8n_credential_unverified",
            "n8n_import_workflow_failed","child_not_inactive",
            "child_receipt_binding_unverified","manual_parent_not_inactive",
            "unexpected_workflow_activation","real_n8n_receipt_not_proven",
            "prior_qa_artifact_state_mismatch","parent_id_invalid",
            "n8n_child_id_invalid",
            "fictional_acquisition_fixture_invalid",
            "fictional_acquisition_not_committed",
            "fictional_acquisition_event_invalid",
            "fictional_acquisition_outbox_not_published",
            "fictional_acquisition_envelope_invalid",
            "pg_source_tenant_mismatch","receipt_not_committed",
            "cross_tenant_owner_not_denied","unauthorized_work_inserted",
            "durable_handoff_not_idempotent","durable_work_table_count_invalid",
            "durable_work_owner_due_invalid","due_or_tenant_isolation_unverified",
            "handoff_resolution_failed","previous_owner_not_revoked",
        }
        print("QA_RUN_BLOCKED "+(code if code in known else "unexpected_safe_boundary"),flush=True)
        raise SystemExit(2)
