#!/usr/bin/env python3
"""Source-only preparation for ONE operator-approved LOCAL private receipt service.

Default read-only. Never launch, create SQLite, or call 1Password by default.
A separate exact authorization is required for --serve-one. The service
runs in the foreground without restart and receives its secret by inherited FD.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import select
import signal
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from avuhz_worker.local_n8n_onepassword_credential import (
    LocalN8nOnePasswordCredential, LocalN8nSecretUnavailable,
)
from avuhz_worker.local_n8n_receipt_dev_runner import (
    inspect_private_local_n8n, validate_storage_path,
)
from scripts import prepare_shared_n8n_receiver_v2_local as receiver
from scripts import prepare_shared_n8n_receiver_v2_header_credential_local as inbound

TARGET = "LOCAL_DEVELOPMENT_N8N_5678"
RUNNER = ROOT / "src/avuhz_worker/local_n8n_receipt_dev_runner.py"
RUNNER_SHA256 = "97f2f4bbda81bc6f382484ec8c2d351ea016d0e615fad2cf2d1343cf046ce421"
FIXTURE = ROOT / "tests/fixtures/system001_qa_tenant_local_v1.json"
FIXTURE_SHA256 = "217da325ebd1740211934e4d515db2f8a0d67b7b565f383fbd2a7c348ed16fea"
RECEIVER_ID = "0068feb4c96bdb5f"
RECEIPT_CREDENTIAL_ID = "154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2"
RECEIPT_NAME = "Avuhz Shared Receiver v2 LOCAL receipt bridge"
RECEIPT_TYPE = "httpHeaderAuth"
QA_DB_RELATIVE = pathlib.Path(".local/share/avuhz-qa-receipts.sqlite")
BANNER = "LOCAL_DEVELOPMENT_RECEIPT_BOUND_PRIVATE "
MAX_BANNER = 250


class LocalReceiptLaunchDenied(RuntimeError):
    """A fixed, non-sensitive failure; never include provider output."""


@dataclass(frozen=True)
class Preflight:
    tenant_id: str
    db_path: pathlib.Path
    gateway: str
    client: str
    network_cidr: str
    receiver_id: str
    receipt_credential_id: str


def _digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check_fictional_qa_fixture() -> str:
    if _digest(FIXTURE) != FIXTURE_SHA256:
        raise ValueError
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if (
        value.get("fixture_type") != "LOCAL_TEST_ONLY_FICTIONAL_CLIENT"
        or value.get("fixture_name") != "Avuhz QA Tenant 001"
        or value.get("owner_is_real_or_verified") is not False
        or value.get("hosted_data_insert_authorized") is not False
        or value.get("production_allowed") is not False
        or value.get("tenant_id") != "a4730000-0000-4000-8000-000000000001"
    ):
        raise ValueError
    return value["tenant_id"]


def _check_receipt_n8n_metadata() -> None:
    source = receiver._source()  # validates canonical hash before any service action
    path = receiver._db_path()
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
        db.execute("PRAGMA query_only=ON")
        rows = db.execute(
            "SELECT id,active,nodes,connections,settings FROM workflow_entity "
            "WHERE name=?", (source["name"],),
        ).fetchall()
        if len(rows) != 1 or rows[0][0] != RECEIVER_ID or rows[0][1] != 0:
            raise ValueError
        nodes = json.loads(rows[0][2])
        inbound_ids = db.execute(
            "SELECT id,length(data),substr(data,1,1) FROM credentials_entity "
            "WHERE name=? AND type=?",
            (inbound.CREDENTIAL_NAME, inbound.CREDENTIAL_TYPE),
        ).fetchall()
        if (
            len(inbound_ids) != 1 or not isinstance(inbound_ids[0][1], int)
            or inbound_ids[0][1] < 20 or inbound_ids[0][2] == "{"
        ):
            raise ValueError
        expected = json.loads(json.dumps(source["nodes"]))
        expected[0]["credentials"] = {
            "httpHeaderAuth": {
                "id": inbound_ids[0][0], "name": inbound.CREDENTIAL_NAME
            }
        }
        receipt = db.execute(
            "SELECT id,type,length(data),substr(data,1,1) "
            "FROM credentials_entity WHERE name=?", (RECEIPT_NAME,),
        ).fetchall()
        project = db.execute("SELECT id FROM project WHERE type='personal'").fetchall()
        if (
            len(receipt) != 1 or receipt[0][0] != RECEIPT_CREDENTIAL_ID
            or receipt[0][1] != RECEIPT_TYPE
            or not isinstance(receipt[0][2], int) or receipt[0][2] < 20
            or receipt[0][3] == "{"
            or len(project) != 1
            or db.execute(
                "SELECT count(*) FROM shared_credentials "
                "WHERE credentialsId=? AND projectId=?",
                (RECEIPT_CREDENTIAL_ID, project[0][0]),
            ).fetchone()[0] != 1
            or db.execute(
                "SELECT count(*) FROM shared_credentials "
                "WHERE credentialsId=? AND projectId=?",
                (inbound_ids[0][0], project[0][0]),
            ).fetchone()[0] != 1
            or nodes != expected
            or json.loads(rows[0][3]) != source["connections"]
            or json.loads(rows[0][4]) != source["settings"]
            or expected[2]["parameters"]["url"] != receiver.UNBOUND_RECEIPT
            or "credentials" in expected[2]
            or db.execute("SELECT count(*) FROM workflow_entity WHERE active=1").fetchone()[0]
            or db.execute("SELECT count(*) FROM execution_entity").fetchone()[0]
        ):
            raise ValueError


def preflight() -> Preflight:
    try:
        if _digest(RUNNER) != RUNNER_SHA256:
            raise ValueError
        tenant = _check_fictional_qa_fixture()
        db_path = pathlib.Path.home() / QA_DB_RELATIVE
        validate_storage_path(db_path)
        if db_path.exists() and db_path.stat().st_uid != os.getuid():
            raise ValueError
        network = inspect_private_local_n8n()
        _check_receipt_n8n_metadata()
        return Preflight(
            tenant_id=tenant, db_path=db_path,
            gateway=network.gateway, client=network.client,
            network_cidr=network.cidr, receiver_id=RECEIVER_ID,
            receipt_credential_id=RECEIPT_CREDENTIAL_ID,
        )
    except Exception:
        raise LocalReceiptLaunchDenied("local_receipt_preflight_denied") from None


def _read_start_banner(child: subprocess.Popen, gateway: str) -> str:
    """Read bounded sanitized startup metadata only; never forward raw output."""
    if child.stdout is None:
        raise LocalReceiptLaunchDenied("receipt_start_unverified")
    buffer = bytearray()
    deadline = time.monotonic() + 10
    while len(buffer) < MAX_BANNER:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LocalReceiptLaunchDenied("receipt_start_unverified")
        ready, _, _ = select.select([child.stdout], [], [], remaining)
        if not ready:
            raise LocalReceiptLaunchDenied("receipt_start_unverified")
        part = os.read(child.stdout.fileno(), MAX_BANNER - len(buffer))
        if not part:
            raise LocalReceiptLaunchDenied("receipt_start_unverified")
        buffer.extend(part)
        if b"\n" in buffer:
            break
    expected = (
        r"^" + re.escape(BANNER) + r"http://" + re.escape(gateway)
        + r":([0-9]{1,5})\n$"
    )
    match = re.fullmatch(expected, buffer.decode("ascii", errors="replace"))
    if match is None or not 1 <= int(match[1]) <= 65535:
        raise LocalReceiptLaunchDenied("receipt_start_unverified")
    if child.poll() is not None:
        raise LocalReceiptLaunchDenied("receipt_start_unverified")
    return f"http://{gateway}:{match[1]}"


def _stop_child(child: subprocess.Popen) -> None:
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
    if child.stdout is not None:
        child.stdout.close()


def start_once(token: str, state: Preflight) -> int:
    """One foreground child only; no daemonization or restart."""
    if (
        type(token) is not str or not 32 <= len(token) <= 512
        or any(ord(c) < 33 or ord(c) > 126 for c in token)
    ):
        raise LocalReceiptLaunchDenied("private_receipt_secret_invalid")
    reader = writer = None
    child = None
    original_sigterm = None

    def handle_term(_signum, _frame):
        raise KeyboardInterrupt

    try:
        original_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, handle_term)
        reader, writer = os.pipe()
        argv = [
            sys.executable, "-m", "avuhz_worker.local_n8n_receipt_dev_runner",
            "--target", TARGET, "--trusted-tenant-id", state.tenant_id,
            "--receipt-db", str(state.db_path),
            "--serve", "--token-fd", str(reader),
        ]
        child_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(pathlib.Path.home()),
            "PYTHONPATH": str(ROOT / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "AVUHZ_ENVIRONMENT": "LOCAL",
            "LANG": "C.UTF-8",
        }
        child = subprocess.Popen(
            argv, cwd=str(ROOT), env=child_env, pass_fds=(reader,),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, close_fds=True,
        )
        os.close(reader)
        reader = None
        raw = token.encode("ascii")
        written = 0
        while written < len(raw):
            size = os.write(writer, raw[written:])
            if size < 1:
                raise LocalReceiptLaunchDenied("private_receipt_pipe_unavailable")
            written += size
        os.close(writer)
        writer = None
        address = _read_start_banner(child, state.gateway)
        print("PASS one private LOCAL receipt service running at " + address, flush=True)
        print("PASS foreground-only; stop launcher to stop service; no auto-restart", flush=True)
        status = child.wait()
        if status != 0:
            raise LocalReceiptLaunchDenied("receipt_service_stopped_unexpectedly")
        return 0
    except KeyboardInterrupt:
        print("PASS approved LOCAL receipt service shutdown requested", flush=True)
        return 0
    except (OSError, subprocess.SubprocessError, ValueError):
        raise LocalReceiptLaunchDenied("private_receipt_runtime_unverified") from None
    finally:
        if original_sigterm is not None:
            signal.signal(signal.SIGTERM, original_sigterm)
        if reader is not None:
            os.close(reader)
        if writer is not None:
            os.close(writer)
        if child is not None:
            _stop_child(child)


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--serve-one", action="store_true")
    parser.add_argument("--approved-qa-tenant-id")
    parser.add_argument("--approved-receipt-credential-id")
    parser.add_argument("--approved-runner-sha256")
    parser.add_argument("--approved-secret-reference")
    args = parser.parse_args(argv)
    try:
        if (
            args.target != TARGET or os.environ.get("CI")
            or os.environ.get("GITHUB_ACTIONS")
            or os.environ.get("AVUHZ_ENVIRONMENT", "LOCAL") != "LOCAL"
        ):
            raise LocalReceiptLaunchDenied("local_only")
        approved = (
            args.approved_qa_tenant_id, args.approved_receipt_credential_id,
            args.approved_runner_sha256, args.approved_secret_reference,
        )
        if args.serve_one:
            if (
                args.approved_qa_tenant_id != "a4730000-0000-4000-8000-000000000001"
                or args.approved_receipt_credential_id != RECEIPT_CREDENTIAL_ID
                or args.approved_runner_sha256 != "sha256:" + RUNNER_SHA256
                or not args.approved_secret_reference
            ):
                raise LocalReceiptLaunchDenied("fresh_exact_service_approval_required")
            provider = LocalN8nOnePasswordCredential(
                environment="LOCAL",
                approved_secret_reference=args.approved_secret_reference,
            )
        elif any(x is not None for x in approved):
            raise LocalReceiptLaunchDenied("read_only_must_not_load_secrets")
        state = preflight()
        print("PASS exact QA-only private storage, Docker gateway, and inactive LOCAL n8n", flush=True)
        if not args.serve_one:
            print("PASS read-only: no secret read, database or listener creation", flush=True)
            return 0
        secret = provider()
        try:
            # Re-verify exact LOCAL resource state after approved secret read.
            if preflight() != state:
                raise LocalReceiptLaunchDenied("resource_drift_before_service_start")
            return start_once(secret, state)
        finally:
            secret = None
    except (LocalReceiptLaunchDenied, LocalN8nSecretUnavailable, ValueError):
        print("BLOCKED LOCAL private receipt-service prerequisite or runtime; no retry", flush=True)
        return 2
    except Exception:
        print("BLOCKED LOCAL receipt-service unavailable; no retry", flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
