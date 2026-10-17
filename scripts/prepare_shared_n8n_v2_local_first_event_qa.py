#!/usr/bin/env python3
"""Read-only DefNet LOCAL QA readiness and later receipt-only readback.

No execution, activation, credential retrieval, HTTP request, workflow import,
service control, SQLite creation, or customer-data operation in either mode.
A stored receipt does not establish an n8n execution or Work Item authority.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
from dataclasses import dataclass

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from scripts import prepare_shared_n8n_receiver_v2_local as receiver
from scripts import prepare_shared_n8n_receiver_v2_header_credential_local as inbound
from scripts import prepare_shared_n8n_v2_op_receipt_credential_local as receipt
from scripts import prepare_shared_n8n_v2_local_receipt_node_binding as binding
from scripts import prepare_local_n8n_receipt_op_service_launcher as service

TARGET = "LOCAL_DEVELOPMENT_N8N_5678"
RECEIVER_ID = "0068feb4c96bdb5f"
RECEIPT_CREDENTIAL_ID = "154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2"
TENANT_ID = "a4730000-0000-4000-8000-000000000001"
EXPECTED_RECEIVER_SHA256 = "fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f"
EXPECTED_FIXTURE_SHA256 = "217da325ebd1740211934e4d515db2f8a0d67b7b565f383fbd2a7c348ed16fea"
FIXTURE_PATH = ROOT / "tests/fixtures/system001_qa_tenant_local_v1.json"
QA_EVENT_ID = "a4730000-0000-4000-8000-000000000041"
QA_CORRELATION_ID = "a4730000-0000-4000-8000-000000000042"
QA_DELIVERY_KEY = "avuhz.qa.system001.first-receipt-001"
QA_TIMESTAMP = "2030-01-15T16:00:00Z"
RECEIPT_COLUMNS = ("trusted_tenant_id", "delivery_key", "event_id", "envelope_digest")


class FirstEventQaDenied(RuntimeError):
    """Fixed, non-sensitive failure only."""


@dataclass(frozen=True)
class QaReadback:
    endpoint: str
    listener_pid: int
    stored_receipts: int
    visible_workflows: int
    archived_workflows: int
    active_workflows: int
    saved_executions: int


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fictional_event() -> dict:
    """Deterministic PII-free transport fixture; not an authoritative event."""
    if _sha256(FIXTURE_PATH) != EXPECTED_FIXTURE_SHA256:
        raise FirstEventQaDenied("fictional_qa_fixture_drift")
    value = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    if (
        value.get("fixture_type") != "LOCAL_TEST_ONLY_FICTIONAL_CLIENT"
        or value.get("fixture_name") != "Avuhz QA Tenant 001"
        or value.get("tenant_id") != TENANT_ID
        or value.get("owner_is_real_or_verified") is not False
        or value.get("hosted_data_insert_authorized") is not False
        or value.get("production_allowed") is not False
        or value.get("request", {}).get("source_system") != "avuhz.qa"
        or value.get("request", {}).get("contact_email") != "qa-operator@example.invalid"
        or value.get("request", {}).get("external_request_id") != "a4730000-0000-4000-8000-000000000021"
    ):
        raise FirstEventQaDenied("fictional_qa_fixture_drift")
    return {
        "event_id": QA_EVENT_ID,
        "event_type": "acquisition.intake.received",
        "tenant_id": TENANT_ID,
        "correlation_id": QA_CORRELATION_ID,
        "occurred_at": QA_TIMESTAMP,
        "authoritative_subject_reference": {
            "reference_type": "ACQUISITION_INTAKE",
            "reference_id": value["request"]["external_request_id"],
        },
        "authoritative_subject_version": 1,
        "delivery_idempotency_key": QA_DELIVERY_KEY,
    }


def _digest(event: dict) -> str:
    return hashlib.sha256(json.dumps(
        event, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")).hexdigest()


def _bound_receiver_readback(source: dict, endpoint: str) -> tuple[int, int, int, int]:
    path = receiver._db_path()
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
        db.execute("PRAGMA query_only=ON")
        projects = db.execute("SELECT id FROM project WHERE type=?", ("personal",)).fetchall()
        if len(projects) != 1:
            raise ValueError
        project_id = projects[0][0]
        workflows = db.execute(
            "SELECT id,name,active,isArchived,nodes,connections,settings,staticData,pinData "
            "FROM workflow_entity ORDER BY id"
        ).fetchall()
        visible = sum(row[3] == 0 for row in workflows)
        archived = sum(row[3] == 1 for row in workflows)
        active = sum(bool(row[2]) for row in workflows)
        executions = db.execute("SELECT count(*) FROM execution_entity").fetchone()[0]
        matches = [row for row in workflows if row[0] == RECEIVER_ID and row[1] == source["name"]]
        if (
            (visible, archived, active) != (6, 1, 0)
            or len(matches) != 1 or matches[0][3] != 0
            or matches[0][7:] != (None, None)
        ):
            raise ValueError
        creds = db.execute(
            "SELECT id,name,type,length(data),substr(data,1,1) "
            "FROM credentials_entity WHERE name IN (?,?)",
            (receipt.CREDENTIAL_NAME, inbound.CREDENTIAL_NAME),
        ).fetchall()
        if len(creds) != 2:
            raise ValueError
        by_name = {x[1]: x for x in creds}
        incoming = by_name[inbound.CREDENTIAL_NAME]
        outbound = by_name[receipt.CREDENTIAL_NAME]
        if (
            outbound[0] != RECEIPT_CREDENTIAL_ID
            or incoming[0] == outbound[0]
            or incoming[2] != "httpHeaderAuth"
            or outbound[2] != "httpHeaderAuth"
            or any(type(x[3]) is not int or x[3] < 20 or x[4] == "{" for x in creds)
        ):
            raise ValueError
        for cred in (incoming, outbound):
            if db.execute(
                "SELECT count(*) FROM shared_credentials "
                "WHERE credentialsId=? AND projectId=?",
                (cred[0], project_id),
            ).fetchone()[0] != 1:
                raise ValueError
        if db.execute(
            "SELECT count(*) FROM shared_workflow WHERE workflowId=? AND projectId=?",
            (RECEIVER_ID, project_id),
        ).fetchone()[0] != 1:
            raise ValueError
        row = matches[0]
        wanted = copy.deepcopy(source["nodes"])
        wanted[0]["credentials"] = {
            "httpHeaderAuth": {"id": incoming[0], "name": inbound.CREDENTIAL_NAME}
        }
        wanted[2]["parameters"]["url"] = endpoint
        wanted[2]["credentials"] = {
            "httpHeaderAuth": {"id": RECEIPT_CREDENTIAL_ID, "name": receipt.CREDENTIAL_NAME}
        }
        if (
            row[2] != 0 or json.loads(row[4]) != wanted
            or json.loads(row[5]) != source["connections"]
            or json.loads(row[6]) != source["settings"]
        ):
            raise ValueError
    return visible, archived, active, executions


def _receipt_readback(path: Path, event: dict, expect_one: bool) -> int:
    st = path.stat()
    if (
        path.is_symlink() or not stat.S_ISREG(st.st_mode)
        or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600
    ):
        raise ValueError
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=4) as db:
        db.execute("PRAGMA query_only=ON")
        count = db.execute("SELECT count(*) FROM local_n8n_receipts").fetchone()[0]
        if not expect_one and count != 0:
            raise ValueError
        if expect_one:
            if count != 1:
                raise ValueError
            match = db.execute(
                "SELECT count(*) FROM local_n8n_receipts WHERE "
                "trusted_tenant_id=? AND delivery_key=? AND event_id=? "
                "AND envelope_digest=?",
                (TENANT_ID, event["delivery_idempotency_key"],
                 event["event_id"], _digest(event)),
            ).fetchone()[0]
            if match != 1:
                raise ValueError
    return count


def preflight(*, expect_one: bool = False) -> QaReadback:
    """Independently inspect post-binding runtime; never reuse the unbound gate."""
    try:
        event = fictional_event()
        if receiver.SOURCE_SHA256 != EXPECTED_RECEIVER_SHA256:
            raise ValueError
        source = receiver._source()
        boundary = service.inspect_private_local_n8n()
        store = Path.home() / service.QA_DB_RELATIVE
        service.validate_storage_path(store)
        if store != Path("/home/network-p/.local/share/avuhz-qa-receipts.sqlite"):
            raise ValueError
        endpoint, pid = binding._service_listener(boundary.gateway, TENANT_ID, store)
        if not endpoint.startswith("http://" + boundary.gateway + ":"):
            raise ValueError
        counts = _bound_receiver_readback(source, endpoint)
        stored = _receipt_readback(store, event, expect_one)
        return QaReadback(endpoint, pid, stored, *counts)
    except Exception:
        raise FirstEventQaDenied("first_shared_receiver_qa_readback_denied") from None


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--expect-one-receipt", action="store_true")
    args = parser.parse_args(argv)
    if (
        args.target != TARGET or os.environ.get("CI")
        or os.environ.get("GITHUB_ACTIONS")
        or os.environ.get("AVUHZ_ENVIRONMENT", "LOCAL") != "LOCAL"
    ):
        print("BLOCKED wrong LOCAL QA target/environment")
        return 2
    try:
        result = preflight(expect_one=args.expect_one_receipt)
    except FirstEventQaDenied:
        print("BLOCKED shared receiver LOCAL QA readback; no changes")
        return 2
    if args.expect_one_receipt:
        print("PASS exact fictional receipt stored once; transport storage only")
        print("NOT CERTIFIED: n8n execution response, duplicate/denial, or Work Item authority")
    else:
        print("PASS bound inactive shared n8n receiver, private QA service, encrypted credentials")
        print("PASS empty private receipt store; 6 non-archived, 1 archived, no active workflows")
        print("PASS PII-free deterministic QA transport fixture available in source")
        print("PASS read-only; no event sent, credentials read, workflows activated or resources modified")
    print("PASS current private receipt endpoint " + result.endpoint)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
