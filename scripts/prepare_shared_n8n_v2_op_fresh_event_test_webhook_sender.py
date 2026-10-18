#!/usr/bin/env python3
"""Preparation-only LOCAL fresh-event gate; DEFAULT IS READ ONLY.

--send-one is unconditionally BLOCKED. No issuer, token FD or HTTP sender is
called. CLI flags cannot establish independent owner authorization. Runtime
inspection is intended for a later authorized read-only invocation; source-only
preparation runs this module only with mocked runtime boundaries.
"""
from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from scripts import prepare_shared_n8n_v2_local_first_event_qa as qa

TARGET = "LOCAL_DEVELOPMENT_N8N_5678"
BASE_COMMIT = "24e941207974931d14f940945b39d4bbdf2b2d9d"
PROJECT_ID = "axT3GLERZRiPXxnj"
RECEIVER_ID = "0068feb4c96bdb5f"
INBOUND_ID = "6ece28c3-f72d-4021-942d-8d0eb072b711"
RECEIPT_ID = "154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2"
SOURCE_SHA256 = "fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f"
EVENT_ID = "822db2e6-fd66-4b17-a85f-f3d4c5221921"
CORRELATION_ID = "8ada11c9-bebe-4935-b4ec-a46deba50a0d"
DELIVERY_KEY = "avuhz.qa.system001.fresh-receipt-002"
EVENT_SHA256 = "0dd4988ba6f3c365d63c4ca933d02ed21190a1a3c008d3fc06008ebeeee39b70"
HISTORICAL_SHA256 = "5d6483c5d7d971a30f2416f03174c4e6ee480eeb00ead3667699b26ec22f4974"
STORE = Path("/home/network-p/.local/share/avuhz-qa-receipts.sqlite")
TEST_URL = "http://127.0.0.1:5678/webhook-test/avuhz-events"
FIELDS = frozenset({
    "event_id", "event_type", "tenant_id", "correlation_id", "occurred_at",
    "authoritative_subject_reference", "authoritative_subject_version",
    "delivery_idempotency_key",
})
# Relevant unchanged helpers from the archive, not a claim of a clean Git HEAD.
SOURCE_FILES = {
    "scripts/prepare_shared_n8n_v2_local_first_event_qa.py":
        "56898a6af424107db8933290e9c539abd3d071b9cf09f207f016768cd9a04a7e",
    "scripts/prepare_shared_n8n_receiver_v2_local.py":
        "fe65f14e64036fe0bb7ecc2fa39653ae0a562f43973258707eb249ddf2c3b5de",
    "scripts/prepare_shared_n8n_v2_local_receipt_node_binding.py":
        "2e2c3bd1b73f35030fea429bbbb78636e3d08c65060059fd6b941b9b5d98506e",
    "scripts/prepare_local_n8n_receipt_op_service_launcher.py":
        "414c3f4cc4ce0725a99ebf55eb4435088ed0555ac328a3b805f8d642178ab679",
    "src/avuhz_worker/local_n8n_receipt_dev_runner.py":
        "97f2f4bbda81bc6f382484ec8c2d351ea016d0e615fad2cf2d1343cf046ce421",
}


class FreshEventDenied(RuntimeError):
    """Fixed category only; never include database, process or secret content."""


@dataclass(frozen=True)
class Evidence:
    endpoint: str
    listener_pid: int
    event_digest: str
    historical_receipts: int = 1
    fresh_collisions: int = 0
    # Native registration is ephemeral, not proven by webhook_entity counts.
    test_listener_verified: bool = False
    ready_for_send: bool = False


def fictional_event() -> dict:
    event = qa.fictional_event()
    if qa._digest(event) != HISTORICAL_SHA256 or set(event) != FIELDS:
        raise FreshEventDenied("historical_source_drift")
    event = copy.deepcopy(event)
    event.update(event_id=EVENT_ID, correlation_id=CORRELATION_ID,
                 delivery_idempotency_key=DELIVERY_KEY)
    if qa._digest(event) != EVENT_SHA256 or event["tenant_id"] != qa.TENANT_ID:
        raise FreshEventDenied("fresh_source_drift")
    return event


def _source() -> dict:
    for name, digest in SOURCE_FILES.items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise FreshEventDenied("helper_source_drift")
    if qa.receiver.SOURCE_SHA256 != SOURCE_SHA256:
        raise FreshEventDenied("receiver_source_drift")
    return qa.receiver._source()


def _protected_file(path: Path, *, receipt: bool) -> None:
    if not path.is_absolute() or path.resolve() != path:
        raise FreshEventDenied("storage_path_denied")
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) & 0o022
            or (receipt and stat.S_IMODE(st.st_mode) != 0o600)):
        raise FreshEventDenied("storage_owner_or_mode_denied")


@contextmanager
def _readonly(path: Path, *, receipt: bool = False):
    _protected_file(path, receipt=receipt)
    # No immutable=1: it could ignore current WAL receipts and miss collisions.
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=4)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")  # consistent aggregate/metadata read transaction
        yield db
    finally:
        db.close()


def _receipt_readback(path: Path) -> None:
    old, new = qa.fictional_event(), fictional_event()
    with _readonly(path, receipt=True) as db:
        counts = db.execute(
            "SELECT count(*), "
            "coalesce(sum(trusted_tenant_id=? AND event_id=? AND delivery_key=? "
            "AND envelope_digest=?),0), "
            "coalesce(sum(event_id=? OR delivery_key=?),0) "
            "FROM local_n8n_receipts",
            (qa.TENANT_ID, old["event_id"], old["delivery_idempotency_key"],
             HISTORICAL_SHA256, new["event_id"], new["delivery_idempotency_key"]),
        ).fetchone()
        if counts != (1, 1, 0):
            raise FreshEventDenied("receipt_baseline_or_collision_denied")


def _receiver_metadata(path: Path, source: dict, endpoint: str) -> None:
    with _readonly(path) as db:
        if db.execute("SELECT id FROM project WHERE type='personal'").fetchall() != [(PROJECT_ID,)]:
            raise FreshEventDenied("project_denied")
        counts = db.execute(
            "SELECT count(*), coalesce(sum(isArchived=0),0), "
            "coalesce(sum(isArchived=1),0), coalesce(sum(active!=0),0), "
            "coalesce(sum(active IS NULL),0) FROM workflow_entity"
        ).fetchone()
        if counts != (7, 6, 1, 0, 0):
            raise FreshEventDenied("workflow_inventory_denied")
        if db.execute("SELECT count(*) FROM webhook_entity").fetchone() != (0,):
            raise FreshEventDenied("persistent_webhook_denied")
        # Execution metadata/content is not necessary to prove this boundary.
        expected = ((INBOUND_ID, qa.inbound.CREDENTIAL_NAME),
                    (RECEIPT_ID, qa.receipt.CREDENTIAL_NAME))
        for ident, name in expected:
            rows = db.execute(
                "SELECT id,name,type FROM credentials_entity WHERE id=? OR name=?",
                (ident, name),
            ).fetchall()
            if rows != [(ident, name, "httpHeaderAuth")]:
                raise FreshEventDenied("credential_metadata_denied")
            if db.execute(
                "SELECT projectId,role FROM shared_credentials WHERE credentialsId=?",
                (ident,),
            ).fetchall() != [(PROJECT_ID, "credential:owner")]:
                raise FreshEventDenied("credential_share_denied")
        if db.execute(
            "SELECT projectId,role FROM shared_workflow WHERE workflowId=?",
            (RECEIVER_ID,),
        ).fetchall() != [(PROJECT_ID, "workflow:owner")]:
            raise FreshEventDenied("workflow_share_denied")
        rows = db.execute(
            "SELECT id,name,active,isArchived,nodes,connections,settings,"
            "staticData IS NULL,pinData IS NULL FROM workflow_entity WHERE id=? OR name=?",
            (RECEIVER_ID, source["name"]),
        ).fetchall()
        wanted = copy.deepcopy(source["nodes"])
        wanted[0]["credentials"] = {
            "httpHeaderAuth": {"id": INBOUND_ID, "name": qa.inbound.CREDENTIAL_NAME}}
        wanted[2]["parameters"]["url"] = endpoint
        wanted[2]["credentials"] = {
            "httpHeaderAuth": {"id": RECEIPT_ID, "name": qa.receipt.CREDENTIAL_NAME}}
        if (len(wanted) != 5 or len(rows) != 1
                or rows[0][:4] != (RECEIVER_ID, source["name"], 0, 0)
                or rows[0][7:] != (1, 1)
                or json.loads(rows[0][4]) != wanted
                or json.loads(rows[0][5]) != source["connections"]
                or json.loads(rows[0][6]) != source["settings"]):
            raise FreshEventDenied("installed_receiver_drift")


def _process_sources(pid: int) -> None:
    """Check owned process source paths, never environment or private token FDs."""
    _, parent = qa.binding._proc_uid_parent(pid)
    qa.binding._proc_uid_parent(parent)
    runner = "src/avuhz_worker/local_n8n_receipt_dev_runner.py"
    launcher = "scripts/prepare_local_n8n_receipt_op_service_launcher.py"
    child_cwd = (Path("/proc") / str(pid) / "cwd").resolve(strict=True)
    parent_cwd = (Path("/proc") / str(parent) / "cwd").resolve(strict=True)
    args = qa.binding._proc_args(parent)
    paths = [Path(arg) for arg in args if arg.endswith(launcher)]
    if len(paths) != 1:
        raise FreshEventDenied("launcher_path_denied")
    launch_path = paths[0] if paths[0].is_absolute() else parent_cwd / paths[0]
    for path, name in ((child_cwd / runner, runner), (launch_path, launcher)):
        if hashlib.sha256(path.read_bytes()).hexdigest() != SOURCE_FILES[name]:
            raise FreshEventDenied("process_source_drift")


def preflight() -> Evidence:
    """Compose safe helpers, replacing only incompatible first-receipt gates."""
    try:
        event = fictional_event()
        source = _source()
        boundary = qa.service.inspect_private_local_n8n()
        qa.service.validate_storage_path(STORE)
        _protected_file(STORE, receipt=True)
        endpoint, pid = qa.binding._service_listener(boundary.gateway, qa.TENANT_ID, STORE)
        if not endpoint.startswith("http://" + boundary.gateway + ":"):
            raise FreshEventDenied("endpoint_denied")
        _process_sources(pid)
        _receiver_metadata(qa.receiver._db_path(), source, endpoint)
        _receipt_readback(STORE)
        # Detect process/endpoint drift across the read-only inspection.
        if qa.binding._service_listener(boundary.gateway, qa.TENANT_ID, STORE) != (endpoint, pid):
            raise FreshEventDenied("bridge_drift")
        return Evidence(endpoint, pid, qa._digest(event))
    except Exception:
        raise FreshEventDenied("fresh_event_readback_denied") from None


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--send-one", action="store_true",
                        help="Always BLOCKED; future execution is not implemented")
    args = parser.parse_args(argv)
    if args.send_one:
        print("BLOCKED future-send: independent approvals, issuer metadata and native listener proof missing")
        return 2
    if (args.target != TARGET or platform.node() != "DefNet"
            or os.environ.get("AVUHZ_ENVIRONMENT") != "LOCAL"
            or os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")):
        print("BLOCKED wrong LOCAL preparation boundary")
        return 2
    try:
        preflight()
    except Exception:
        print("BLOCKED LOCAL read-only preparation; source or runtime evidence unavailable")
        return 2
    print("PASS read-only source, receiver metadata, private bridge and aggregate receipt checks")
    print("PASS exactly one historical QA receipt; zero fresh event-ID/key collisions")
    print("PASS fictional fresh event sha256:" + EVENT_SHA256)
    print("NOT READY FOR SEND: native test listener unverified; future-send BLOCKED")
    print("NO credential access, listener registration, HTTP request or receipt write")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
