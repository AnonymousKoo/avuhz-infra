#!/usr/bin/env python3
"""Guarded source-only LOCAL receiver receipt HTTP node binding.

Read-only by default. --bind-one requires fresh, exact authorization and
performs at most ONE native n8n import for ONE inactive shared receiver.
No workflow activation, execution, credential reads, service start or retry.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import pathlib
import re
import sqlite3
import stat
import subprocess
import sys
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from scripts import prepare_shared_n8n_receiver_v2_local as source_gate
from scripts import prepare_shared_n8n_receiver_v2_header_credential_local as inbound_gate
from scripts import prepare_shared_n8n_v2_op_receipt_credential_local as receipt_gate
from scripts import prepare_local_n8n_receipt_op_service_launcher as service_gate

TARGET = "LOCAL_DEVELOPMENT_N8N_5678"
RECEIVER_ID = "0068feb4c96bdb5f"
RECEIPT_ID = "154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2"
RECEIPT_NAME = receipt_gate.CREDENTIAL_NAME
QA_TENANT = "a4730000-0000-4000-8000-000000000001"
RECEIPT_ROUTE = "/v1/avuhz/local-n8n-receipts"
PID_RE = re.compile(r"pid=(\d+),fd=\d+")
NODE_INDEX = 2


class ReceiptBindingDenied(RuntimeError):
    """Sanitized boundary failure, no raw subprocess or secret output."""


@dataclass(frozen=True)
class Snapshot:
    db_path: pathlib.Path
    receiver_id: str
    project_id: str
    endpoint: str
    listener_pid: int
    storage_path: pathlib.Path
    workflows: tuple[tuple, ...]
    credential_meta: tuple[tuple, ...]
    credential_shares: tuple[tuple, ...]
    workflow_shares: tuple[tuple, ...]
    webhooks: int
    executions: int


def _proc_args(pid: int) -> tuple[str, ...]:
    if pid <= 1:
        raise ValueError
    cmdline = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()
    return tuple(x.decode("utf-8") for x in cmdline.split(b"\x00") if x)


def _proc_uid_parent(pid: int) -> tuple[int, int]:
    lines = pathlib.Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines()
    uid_line = next(row for row in lines if row.startswith("Uid:"))
    ppid_line = next(row for row in lines if row.startswith("PPid:"))
    uids = [int(v) for v in uid_line.split()[1:]]
    if len(uids) != 4 or any(v != os.getuid() for v in uids):
        raise ValueError
    return uids[0], int(ppid_line.split()[1])


def _flag(args: tuple[str, ...], key: str) -> str:
    if args.count(key) != 1:
        raise ValueError
    i = args.index(key)
    if i >= len(args) - 1:
        raise ValueError
    return args[i + 1]


def _service_listener(expected_gateway: str, expected_tenant: str, db_path: pathlib.Path) -> tuple[str, int]:
    """Metadata-only proof: one private owned live service supervised by approved launcher."""
    result = subprocess.run(
        ["ss", "-H", "-lntp"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=5, check=False, text=True,
    )
    if result.returncode:
        raise ValueError
    matched = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        endpoint = parts[3]
        if not endpoint.startswith(expected_gateway + ":"):
            continue
        port = endpoint.rsplit(":", 1)[1]
        if not port.isdecimal() or not 1024 <= int(port) <= 65535:
            raise ValueError
        pids = set(PID_RE.findall(line))
        if len(pids) != 1:
            raise ValueError
        matched.append((endpoint, int(next(iter(pids)))))
    if len(matched) != 1:
        raise ValueError
    endpoint, pid = matched[0]
    _uid, parent = _proc_uid_parent(pid)
    args = _proc_args(pid)
    if (
        "avuhz_worker.local_n8n_receipt_dev_runner" not in args
        or args.count("--serve") != 1
        or args.count("--token-fd") != 1
        or _flag(args, "--target") != TARGET
        or _flag(args, "--trusted-tenant-id") != expected_tenant
        or _flag(args, "--receipt-db") != str(db_path)
    ):
        raise ValueError
    _proc_uid_parent(parent)
    parent_args = _proc_args(parent)
    if (
        not any(x.endswith("scripts/prepare_local_n8n_receipt_op_service_launcher.py") for x in parent_args)
        or "--serve-one" not in parent_args
        or _flag(parent_args, "--target") != TARGET
        or _flag(parent_args, "--approved-qa-tenant-id") != QA_TENANT
        or _flag(parent_args, "--approved-receipt-credential-id") != RECEIPT_ID
        or _flag(parent_args, "--approved-runner-sha256") != "sha256:" + service_gate.RUNNER_SHA256
    ):
        raise ValueError
    return "http://" + endpoint + RECEIPT_ROUTE, pid


def _snapshot(db_path: pathlib.Path, endpoint: str, pid: int, store: pathlib.Path) -> Snapshot:
    with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
        db.execute("PRAGMA query_only=ON")
        projects = db.execute("SELECT id FROM project WHERE type='personal'").fetchall()
        if len(projects) != 1:
            raise ValueError
        project_id = projects[0][0]
        rows = tuple(db.execute(
            "SELECT id,name,active,nodes,connections,settings,staticData,pinData "
            "FROM workflow_entity ORDER BY id"
        ).fetchall())
        credentials = tuple(db.execute(
            "SELECT id,name,type,length(data),substr(data,1,1) "
            "FROM credentials_entity ORDER BY id"
        ).fetchall())
        cred_shares = tuple(db.execute(
            "SELECT credentialsId,projectId,role FROM shared_credentials "
            "ORDER BY credentialsId,projectId,role"
        ).fetchall())
        wf_shares = tuple(db.execute(
            "SELECT workflowId,projectId,role FROM shared_workflow "
            "ORDER BY workflowId,projectId,role"
        ).fetchall())
        webhook_count = db.execute("SELECT COUNT(*) FROM webhook_entity").fetchone()[0]
        executions = db.execute("SELECT COUNT(*) FROM execution_entity").fetchone()[0]
    return Snapshot(db_path, RECEIVER_ID, project_id, endpoint, pid, store,
                    rows, credentials, cred_shares, wf_shares, webhook_count, executions)


def _exact_receiver(state: Snapshot, source: dict) -> None:
    matches = [row for row in state.workflows if row[0] == RECEIVER_ID and row[1] == source["name"]]
    inbound = [x for x in state.credential_meta if
               x[1] == inbound_gate.CREDENTIAL_NAME and x[2] == inbound_gate.CREDENTIAL_TYPE]
    receipt = [x for x in state.credential_meta if x[1] == RECEIPT_NAME]
    if (
        len(matches) != 1 or len(inbound) != 1 or len(receipt) != 1
        or receipt[0][0] != RECEIPT_ID or receipt[0][2] != "httpHeaderAuth"
        or any(not isinstance(c[3], int) or c[3] < 20 or c[4] == "{" for c in (inbound[0], receipt[0]))
        or any(row[2] for row in state.workflows)
        or state.executions != 0 or matches[0][6:] != (None, None)
        or sum(1 for x in state.workflow_shares if x[0] == RECEIVER_ID
               and x[1] == state.project_id) != 1
        or any(sum(1 for x in state.credential_shares if
                   x[0] == credential[0] and x[1] == state.project_id) != 1
               for credential in (inbound[0], receipt[0]))
    ):
        raise ValueError
    expected = copy.deepcopy(source["nodes"])
    expected[0]["credentials"] = {
        inbound_gate.CREDENTIAL_TYPE: {
            "id": inbound[0][0], "name": inbound_gate.CREDENTIAL_NAME,
        }
    }
    if (
        json.loads(matches[0][3]) != expected
        or json.loads(matches[0][4]) != source["connections"]
        or json.loads(matches[0][5]) != source["settings"]
        or expected[NODE_INDEX]["type"] != "n8n-nodes-base.httpRequest"
        or expected[NODE_INDEX]["parameters"]["url"] != source_gate.UNBOUND_RECEIPT
        or expected[NODE_INDEX]["parameters"]["authentication"] != "genericCredentialType"
        or expected[NODE_INDEX]["parameters"]["genericAuthType"] != "httpHeaderAuth"
        or "credentials" in expected[NODE_INDEX]
    ):
        raise ValueError


def preflight() -> tuple[Snapshot, dict]:
    """Fail-closed read-only reconciliation with the existing live LOCAL service."""
    try:
        boundary = service_gate.preflight()
        if (
            boundary.tenant_id != QA_TENANT
            or boundary.receiver_id != RECEIVER_ID
            or boundary.receipt_credential_id != RECEIPT_ID
        ):
            raise ValueError
        store = boundary.db_path
        st = store.stat()
        if (
            store.is_symlink() or not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077
        ):
            raise ValueError
        with sqlite3.connect(store.as_uri() + "?mode=ro", uri=True, timeout=3) as db:
            db.execute("PRAGMA query_only=ON")
            # Never select event details, tenant identifiers or payload.
            if db.execute("SELECT COUNT(*) FROM local_n8n_receipts").fetchone()[0] != 0:
                raise ValueError
        endpoint, pid = _service_listener(boundary.gateway, QA_TENANT, store)
        source = source_gate._source()
        snapshot = _snapshot(source_gate._db_path(), endpoint, pid, store)
        _exact_receiver(snapshot, source)
        return snapshot, source
    except Exception:
        raise ReceiptBindingDenied("local_receipt_node_preflight_denied") from None


def binding_document(before: Snapshot, source: dict) -> dict:
    """Keep exact receiver template, modify only receipt URL and credential metadata."""
    document = copy.deepcopy(source)
    old = next(x for x in before.workflows if x[0] == RECEIVER_ID)
    nodes = json.loads(old[3])
    if (
        nodes[NODE_INDEX]["parameters"]["url"] != source_gate.UNBOUND_RECEIPT
        or "credentials" in nodes[NODE_INDEX]
        or any("credentials" in n for n in nodes[1:])
    ):
        raise ReceiptBindingDenied("receipt_node_binding_source_denied")
    document["id"] = RECEIVER_ID
    document["active"] = False
    document["nodes"] = copy.deepcopy(nodes)
    document["nodes"][NODE_INDEX]["parameters"]["url"] = before.endpoint
    document["nodes"][NODE_INDEX]["credentials"] = {
        "httpHeaderAuth": {"id": RECEIPT_ID, "name": RECEIPT_NAME}
    }
    return document


def bind_once(before: Snapshot, source: dict) -> None:
    """Exactly one supported n8n workflow import, no credential value involved."""
    data = json.dumps([binding_document(before, source)], separators=(",", ":"), sort_keys=True).encode()
    try:
        result = subprocess.run(
            ["docker", "exec", "-i", "n8n", "n8n", "import:workflow",
             "--input=/dev/stdin", "--projectId=" + before.project_id],
            input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=60, check=False,
        )
        if result.returncode:
            raise ValueError
    except (OSError, subprocess.SubprocessError, ValueError):
        raise ReceiptBindingDenied("local_receipt_single_import_unverified") from None
    finally:
        data = None


def postcondition(before: Snapshot, source: dict) -> bool:
    """Read-only check that only the inactive receipt node differs."""
    try:
        after = _snapshot(before.db_path, before.endpoint, before.listener_pid, before.storage_path)
        if (
            after.credential_meta != before.credential_meta
            or after.credential_shares != before.credential_shares
            or after.workflow_shares != before.workflow_shares
            or after.webhooks != before.webhooks
            or after.executions != 0
            or len(after.workflows) != len(before.workflows)
            or any(w[2] for w in after.workflows)
        ):
            return False
        expected = list(before.workflows)
        indexes = [i for i, row in enumerate(expected) if row[0] == RECEIVER_ID]
        if len(indexes) != 1:
            return False
        idx = indexes[0]
        row = list(expected[idx])
        row[3] = json.dumps(binding_document(before, source)["nodes"])
        expected[idx] = tuple(row)
        for observed, want in zip(after.workflows, expected):
            if observed[:3] != want[:3] or observed[6:] != want[6:]:
                return False
            if json.loads(observed[3]) != json.loads(want[3]):
                return False
            if json.loads(observed[4]) != json.loads(want[4]):
                return False
            if json.loads(observed[5]) != json.loads(want[5]):
                return False
        # Prove that the same authorized service is still listening privately.
        boundary = service_gate.inspect_private_local_n8n() if hasattr(
            service_gate, "inspect_private_local_n8n") else None
        if boundary is None:
            return False
        live_endpoint, live_pid = _service_listener(
            boundary.gateway, QA_TENANT, before.storage_path
        )
        if (live_endpoint, live_pid) != (before.endpoint, before.listener_pid):
            return False
        with sqlite3.connect(before.storage_path.as_uri() + "?mode=ro", uri=True, timeout=3) as db:
            db.execute("PRAGMA query_only=ON")
            return db.execute("SELECT COUNT(*) FROM local_n8n_receipts").fetchone()[0] == 0
    except Exception:
        return False


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--bind-one", action="store_true")
    parser.add_argument("--approved-receiver-id")
    parser.add_argument("--approved-receipt-credential-id")
    parser.add_argument("--approved-endpoint")
    parser.add_argument("--approved-source-sha256")
    args = parser.parse_args(argv)
    try:
        if (
            args.target != TARGET
            or os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")
            or os.environ.get("AVUHZ_ENVIRONMENT", "LOCAL") != "LOCAL"
        ):
            raise ReceiptBindingDenied("local_only")
        if args.bind_one:
            if (
                args.approved_receiver_id != RECEIVER_ID
                or args.approved_receipt_credential_id != RECEIPT_ID
                or args.approved_source_sha256 != "sha256:" + source_gate.SOURCE_SHA256
                or not isinstance(args.approved_endpoint, str)
                or not args.approved_endpoint.startswith("http://172.17.0.1:")
                or not args.approved_endpoint.endswith(RECEIPT_ROUTE)
            ):
                raise ReceiptBindingDenied("fresh_exact_binding_authorization_required")
        elif any((
            args.approved_receiver_id, args.approved_receipt_credential_id,
            args.approved_endpoint, args.approved_source_sha256,
        )):
            raise ReceiptBindingDenied("read_only_does_not_claim_write_approval")
        before, source = preflight()
        print("PASS private LOCAL QA service and unbound inactive v2 receipt node preflight", flush=True)
        print("PASS receipt endpoint " + before.endpoint, flush=True)
        if not args.bind_one:
            print("PASS read-only; workflow remains unmodified and inactive", flush=True)
            return 0
        if args.approved_endpoint != before.endpoint:
            raise ReceiptBindingDenied("approved_endpoint_mismatch")
        latest, _ = preflight()
        if latest != before:
            raise ReceiptBindingDenied("source_or_runtime_drift_before_import")
        bind_once(before, source)
        if not postcondition(before, source):
            raise ReceiptBindingDenied("receipt_node_binding_postcondition_unverified_no_retry")
        print("PASS exactly one inactive LOCAL receiver receipt URL and credential reference bound", flush=True)
        print("PASS no other workflow changes, executions, credential changes or service restarts", flush=True)
        return 0
    except ReceiptBindingDenied:
        print("BLOCKED receipt node binding prerequisite or postcondition; no retry", flush=True)
        return 2
    except Exception:
        print("BLOCKED LOCAL receipt node binding unavailable; no retry", flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
