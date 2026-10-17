#!/usr/bin/env python3
"""Exact LOCAL-only private 1Password -> encrypted n8n receipt credential gate.

Default: read-only DefNet LOCAL preflight, no 1Password read and no mutation.
--import-one requires separate exact owner approval of receiver, source digest
and 1Password field. One native n8n import, no retry or implicit repair.
Never changes workflows, activates services, or copies credentials to disk.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import uuid
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from avuhz_worker.local_n8n_onepassword_credential import (
    LocalN8nOnePasswordCredential, LocalN8nSecretUnavailable,
)
from avuhz_worker.local_n8n_receipt_dev_runner import inspect_private_local_n8n
from scripts import prepare_shared_n8n_receiver_v2_local as receiver
from scripts import prepare_shared_n8n_receiver_v2_header_credential_local as inbound

TARGET = receiver.TARGET
SOURCE_DIGEST = "sha256:" + receiver.SOURCE_SHA256
CREDENTIAL_NAME = "Avuhz Shared Receiver v2 LOCAL receipt bridge"
CREDENTIAL_TYPE = "httpHeaderAuth"
HEADER_NAME = "X-Avuhz-Receipt-Bridge-Token"
CONTAINER = receiver.CONTAINER


class ReceiptCredentialDenied(RuntimeError):
    """Fixed non-sensitive error codes only."""


@dataclass(frozen=True, slots=True)
class Snapshot:
    db_path: pathlib.Path
    project_id: str
    receiver_id: str
    workflows: tuple[tuple, ...]
    credential_meta: tuple[tuple, ...]
    credential_shares: tuple[tuple, ...]
    workflow_shares: tuple[tuple, ...]
    webhook_count: int
    execution_count: int


def _read_snapshot(db_path: pathlib.Path) -> Snapshot:
    """Read metadata only. Never SELECT credentials_entity.data or reveal nodes."""
    with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
        db.execute("PRAGMA query_only=ON")
        projects = db.execute(
            "SELECT id FROM project WHERE type='personal'"
        ).fetchall()
        if len(projects) != 1 or not isinstance(projects[0][0], str):
            raise ValueError
        project_id = projects[0][0]
        workflows = tuple(db.execute(
            "SELECT id,name,active,nodes,connections,settings "
            "FROM workflow_entity ORDER BY id"
        ).fetchall())
        credential_meta = tuple(db.execute(
            "SELECT id,name,type,length(data),substr(data,1,1) "
            "FROM credentials_entity ORDER BY id"
        ).fetchall())
        credential_shares = tuple(db.execute(
            "SELECT credentialsId,projectId,role FROM shared_credentials "
            "ORDER BY credentialsId,projectId,role"
        ).fetchall())
        workflow_shares = tuple(db.execute(
            "SELECT workflowId,projectId,role FROM shared_workflow "
            "ORDER BY workflowId,projectId,role"
        ).fetchall())
        webhook_count = db.execute("SELECT COUNT(*) FROM webhook_entity").fetchone()[0]
        execution_count = db.execute("SELECT COUNT(*) FROM execution_entity").fetchone()[0]
        src = receiver._source()
        matches = [w for w in workflows if w[1] == src["name"]]
        if (
            len(matches) != 1 or len(matches[0][0]) != 16
            or any(bool(w[2]) for w in workflows)
            or execution_count != 0
        ):
            raise ValueError
        return Snapshot(
            db_path, project_id, matches[0][0], workflows,
            credential_meta, credential_shares, workflow_shares,
            webhook_count, execution_count,
        )


def _check_receiver_and_credentials(state: Snapshot, source: dict) -> None:
    matching = [w for w in state.workflows if w[0] == state.receiver_id]
    if len(matching) != 1:
        raise ValueError
    workflow = matching[0]
    expected_nodes = copy.deepcopy(source["nodes"])
    node_ref = json.loads(workflow[3])[0].get("credentials", {}).get(
        inbound.CREDENTIAL_TYPE
    )
    matching_inbound = [
        cred for cred in state.credential_meta
        if cred[1] == inbound.CREDENTIAL_NAME and cred[2] == inbound.CREDENTIAL_TYPE
    ]
    if len(matching_inbound) != 1 or not isinstance(node_ref, dict):
        raise ValueError
    inbound_id = matching_inbound[0][0]
    if node_ref != {"id": inbound_id, "name": inbound.CREDENTIAL_NAME}:
        raise ValueError
    expected_nodes[0]["credentials"] = {
        inbound.CREDENTIAL_TYPE: {
            "id": inbound_id, "name": inbound.CREDENTIAL_NAME,
        }
    }
    if (
        workflow[2] != 0
        or json.loads(workflow[3]) != expected_nodes
        or json.loads(workflow[4]) != source["connections"]
        or json.loads(workflow[5]) != source["settings"]
        or expected_nodes[2]["parameters"]["url"] != receiver.UNBOUND_RECEIPT
        or "credentials" in expected_nodes[2]
        or len([
            cred for cred in state.credential_meta
            if cred[1] == CREDENTIAL_NAME
        ]) != 0
        or len([
            entry for entry in state.credential_shares
            if entry[0] == inbound_id and entry[1] == state.project_id
        ]) != 1
        or len([
            entry for entry in state.workflow_shares
            if entry[0] == state.receiver_id and entry[1] == state.project_id
        ]) != 1
    ):
        raise ValueError
    encrypted_length, prefix = matching_inbound[0][3:]
    if type(encrypted_length) is not int or encrypted_length < 20 or prefix == "{":
        raise ValueError


def preflight() -> tuple[Snapshot, dict]:
    try:
        inspect_private_local_n8n()
        source = receiver._source()  # exact pinned source SHA-256
        state = _read_snapshot(receiver._db_path())
        _check_receiver_and_credentials(state, source)
        return state, source
    except Exception:
        raise ReceiptCredentialDenied("local_receipt_credential_preflight_denied") from None


def import_once(project_id: str, token: str, credential_id: str) -> None:
    """Only one n8n native encrypted credential import; token stays in memory."""
    if (
        type(token) is not str or not 32 <= len(token) <= 512
        or any(ord(c) < 33 or ord(c) > 126 for c in token)
        or type(credential_id) is not str
        or str(uuid.UUID(credential_id)) != credential_id
    ):
        raise ReceiptCredentialDenied("invalid_private_receipt_import_input")
    doc = {
        "id": credential_id,
        "name": CREDENTIAL_NAME,
        "type": CREDENTIAL_TYPE,
        "data": {"name": HEADER_NAME, "value": token},
    }
    payload = json.dumps([doc], separators=(",", ":")).encode("utf-8")
    try:
        result = subprocess.run(
            ["docker", "exec", "-i", CONTAINER, "n8n", "import:credentials",
             "--input=/dev/stdin", "--projectId=" + project_id],
            input=payload, stdin=None, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=60, check=False,
        )
        if result.returncode != 0:
            raise ValueError
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ReceiptCredentialDenied("single_encrypted_receipt_import_unverified") from None
    finally:
        doc = None
        payload = None


def postcondition(before: Snapshot, expected_id: str) -> bool:
    """Independent strict read-only check; no credential ciphertext read."""
    try:
        after = _read_snapshot(before.db_path)
        if (
            after.db_path != before.db_path
            or after.project_id != before.project_id
            or after.receiver_id != before.receiver_id
            or after.workflows != before.workflows
            or after.workflow_shares != before.workflow_shares
            or after.webhook_count != before.webhook_count
            or after.execution_count != 0
        ):
            return False
        new = [c for c in after.credential_meta if c[0] == expected_id]
        if (
            len(new) != 1 or new[0][1:3] != (CREDENTIAL_NAME, CREDENTIAL_TYPE)
            or type(new[0][3]) is not int or new[0][3] < 20
            or new[0][4] == "{"
            or set(after.credential_meta) - {new[0]} != set(before.credential_meta)
            or len(after.credential_meta) != len(before.credential_meta) + 1
        ):
            return False
        added_shares = set(after.credential_shares) - set(before.credential_shares)
        if (
            len(added_shares) != 1
            or not all(
                share[0] == expected_id and share[1] == before.project_id
                for share in added_shares
            )
            or set(before.credential_shares) - set(after.credential_shares)
            or len(after.credential_shares) != len(before.credential_shares) + 1
        ):
            return False
        # Check receiver shape and earlier inbound reference again, but
        # target receipt credential is now present so skip absent-name test.
        return True
    except (OSError, sqlite3.Error, TypeError, KeyError, ValueError,
            ReceiptCredentialDenied):
        return False


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--import-one", action="store_true")
    parser.add_argument("--approved-source-sha256")
    parser.add_argument("--approved-receiver-id")
    parser.add_argument("--approved-secret-reference")
    args = parser.parse_args(argv)
    try:
        if (
            args.target != TARGET
            or os.environ.get("CI")
            or os.environ.get("GITHUB_ACTIONS")
            or os.environ.get("AVUHZ_ENVIRONMENT", "LOCAL") not in ("LOCAL", "TEST")
        ):
            raise ReceiptCredentialDenied("local_only")
        if args.import_one:
            if (
                args.approved_source_sha256 != SOURCE_DIGEST
                or not args.approved_receiver_id
                or not args.approved_secret_reference
            ):
                raise ReceiptCredentialDenied("fresh_exact_approval_required")
            provider = LocalN8nOnePasswordCredential(
                environment="LOCAL",
                approved_secret_reference=args.approved_secret_reference,
            )
        elif any((args.approved_source_sha256, args.approved_receiver_id,
                  args.approved_secret_reference)):
            raise ReceiptCredentialDenied("read_only_must_not_access_secrets")
        before, source = preflight()
        print("PASS LOCAL bound inbound receiver, unbound receipt and zero executions", flush=True)
        if not args.import_one:
            print("PASS read-only; no 1Password read, credential import or workflow mutation", flush=True)
            return 0
        if args.approved_receiver_id != before.receiver_id:
            raise ReceiptCredentialDenied("receiver_id_mismatch")
        token = provider()
        try:
            # Recheck the exact target *after* secret retrieval and
            # immediately before the one n8n external import.
            current, _ = preflight()
            if current != before:
                raise ReceiptCredentialDenied("resource_drift")
            credential_id = str(uuid.uuid4())
            import_once(before.project_id, token, credential_id)
        finally:
            token = None
        if not postcondition(before, credential_id):
            raise ReceiptCredentialDenied("postcondition_unverified_no_retry")
        print("PASS exactly one encrypted LOCAL receipt bridge credential registered", flush=True)
        print("PASS workflows remain unchanged/inactive; no executions, receipt node unbound", flush=True)
        return 0
    except (ReceiptCredentialDenied, LocalN8nSecretUnavailable, ValueError):
        print("BLOCKED LOCAL receipt bridge credential prerequisite or postcondition; no retry", flush=True)
        return 2
    except Exception:
        print("BLOCKED LOCAL receipt bridge credential unavailable; no retry", flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
