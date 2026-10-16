#!/usr/bin/env python3
"""Prepare an exact LOCAL-only inactive n8n webhook credential binding.

Default is read-only. A separately approved --bind-one may update ONE existing
inactive receiver through n8n's supported workflow importer. Never retrieves,
exports, logs, or sends any credential secret. No automatic retry/rollback.
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
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from scripts import prepare_shared_n8n_receiver_v2_header_credential_local as credential_gate
from scripts import prepare_shared_n8n_receiver_v2_local as receiver_source

TARGET = receiver_source.TARGET
EXPECTED_SOURCE_DIGEST = "sha256:" + receiver_source.SOURCE_SHA256
WORKFLOW_COLUMNS = "id,name,active,nodes,connections,settings,staticData,pinData"


class BindingDenied(RuntimeError):
    """Fixed sanitized error code only."""


@dataclass(frozen=True)
class State:
    database: pathlib.Path
    receiver_id: str
    credential_id: str
    project_id: str
    workflow_rows: tuple[tuple, ...]
    credential_count: int
    shared_credential_count: int
    webhook_count: int
    execution_count: int
    sharing_rows: tuple[tuple, ...]


def _readonly_state(path: pathlib.Path) -> tuple[tuple[tuple, ...], int, int, int, int, tuple[tuple, ...]]:
    # No credential data field is ever selected.
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
        db.execute("PRAGMA query_only=ON")
        rows = tuple(db.execute(
            f"SELECT {WORKFLOW_COLUMNS} FROM workflow_entity ORDER BY id"
        ).fetchall())
        return (
            rows,
            db.execute("SELECT COUNT(*) FROM credentials_entity").fetchone()[0],
            db.execute("SELECT COUNT(*) FROM shared_credentials").fetchone()[0],
            db.execute("SELECT COUNT(*) FROM webhook_entity").fetchone()[0],
            db.execute("SELECT COUNT(*) FROM execution_entity").fetchone()[0],
            tuple(db.execute(
                "SELECT workflowId,projectId,role FROM shared_workflow ORDER BY workflowId,projectId,role"
            ).fetchall()),
        )


def preflight() -> tuple[State, dict]:
    """Inspect only the canonical DefNet LOCAL container and database."""
    try:
        credential_gate.inspect_private_local_n8n()
        report = credential_gate.child_preflight(root=ROOT)
        if not (
            report.get("all_workflows_inactive") is True
            and report.get("shared_receiver_bound") is False
            and report.get("credential_bound") is False
            and report.get("receipt_endpoint_configured") is False
            and report.get("existing_execution_rows") == 0
        ):
            raise ValueError
        source = receiver_source._source()  # validates fixed source SHA-256
        path = receiver_source._db_path()
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
            db.execute("PRAGMA query_only=ON")
            found = db.execute(
                "SELECT id FROM credentials_entity WHERE name=? AND type=?",
                (credential_gate.CREDENTIAL_NAME, credential_gate.CREDENTIAL_TYPE),
            ).fetchall()
            if len(found) != 1 or not isinstance(found[0][0], str):
                raise ValueError
            credential_id = found[0][0]
        snapshot = credential_gate.read_only_snapshot(
            path, require_credential=True, expected_id=credential_id
        )
        rows, credential_count, shared_count, webhook_count, executions, sharing = _readonly_state(path)
        matching = [row for row in rows if row[1] == source["name"]]
        if (
            len(matching) != 1
            or matching[0][0] != snapshot.receiver_id
            or bool(matching[0][2])
            or json.loads(matching[0][3]) != source["nodes"]
            or json.loads(matching[0][4]) != source["connections"]
            or json.loads(matching[0][5]) != source["settings"]
            or credential_count != snapshot.credential_count
            or shared_count != snapshot.shared_credential_count
            or executions != 0
            or sum(1 for row in rows if bool(row[2])) != 0
        ):
            raise ValueError
        return State(
            path, snapshot.receiver_id, credential_id, snapshot.project_id, rows,
            credential_count, shared_count, webhook_count, executions, sharing
        ), source
    except Exception:
        raise BindingDenied("exact_local_unbound_receiver_preflight_denied") from None


def binding_document(before: State, source: dict) -> dict:
    """Exactly one credentials entry on the inbound webhook node."""
    document = copy.deepcopy(source)
    if (
        document["active"] is not False
        or any("credentials" in n for n in document["nodes"])
        or document["nodes"][0]["type"] != "n8n-nodes-base.webhook"
        or document["nodes"][0]["parameters"]["authentication"] != "headerAuth"
    ):
        raise BindingDenied("source_binding_boundary_denied")
    document["id"] = before.receiver_id
    document["active"] = False
    document["nodes"][0]["credentials"] = {
        credential_gate.CREDENTIAL_TYPE: {
            "id": before.credential_id,
            "name": credential_gate.CREDENTIAL_NAME,
        }
    }
    return document


def bind_once(before: State, source: dict) -> None:
    """One supported n8n workflow import; secret value never involved."""
    document = binding_document(before, source)
    payload = json.dumps([document], separators=(",", ":"), sort_keys=True).encode()
    try:
        result = subprocess.run(
            ["docker", "exec", "-i", receiver_source.CONTAINER, "n8n",
             "import:workflow", "--input=/dev/stdin",
             "--projectId=" + before.project_id],
            input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=60, check=False,
        )
        if result.returncode != 0:
            raise ValueError
    except (ValueError, OSError, subprocess.SubprocessError):
        raise BindingDenied("single_inactive_binding_import_unverified") from None
    finally:
        payload = None


def postcondition(before: State, source: dict) -> bool:
    """Every workflow row must match exactly except the new webhook credentials."""
    try:
        rows, cred_count, shared_count, webhook_count, executions, sharing = _readonly_state(before.database)
        expected = list(before.workflow_rows)
        receiver_positions = [i for i, row in enumerate(expected) if row[0] == before.receiver_id]
        if len(receiver_positions) != 1:
            return False
        i = receiver_positions[0]
        prior = list(expected[i])
        modified_nodes = binding_document(before, source)["nodes"]
        prior[3] = json.dumps(modified_nodes, separators=(",", ":"))
        expected[i] = tuple(prior)
        # Compare parsed JSON because the n8n CLI may normalize key ordering.
        if len(rows) != len(expected):
            return False
        for actual, want in zip(rows, expected):
            if actual[0:3] != tuple(want[0:3]) or actual[5:] != tuple(want[5:]):
                return False
            if json.loads(actual[3]) != json.loads(want[3]):
                return False
            if json.loads(actual[4]) != json.loads(want[4]):
                return False
        if (
            cred_count != before.credential_count
            or shared_count != before.shared_credential_count
            or webhook_count != before.webhook_count
            or executions != 0
            or sharing != before.sharing_rows
            or any(bool(row[2]) for row in rows)
        ):
            return False
        # Credential still exists and is shared in the same project; no payload.
        with sqlite3.connect(before.database.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
            db.execute("PRAGMA query_only=ON")
            matching = db.execute(
                "SELECT COUNT(*) FROM credentials_entity WHERE id=? AND name=? AND type=?",
                (before.credential_id, credential_gate.CREDENTIAL_NAME, credential_gate.CREDENTIAL_TYPE)
            ).fetchone()[0]
            shared = db.execute(
                "SELECT COUNT(*) FROM shared_credentials WHERE credentialsId=? AND projectId=?",
                (before.credential_id, before.project_id),
            ).fetchone()[0]
        return matching == 1 and shared == 1
    except (OSError, sqlite3.Error, ValueError, TypeError, KeyError, IndexError, BindingDenied):
        return False


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--bind-one", action="store_true")
    parser.add_argument("--approved-source-sha256")
    parser.add_argument("--approved-credential-id")
    parser.add_argument("--approved-receiver-id")
    args = parser.parse_args(argv)
    try:
        if (
            args.target != TARGET
            or os.environ.get("CI")
            or os.environ.get("GITHUB_ACTIONS")
            or os.environ.get("AVUHZ_ENVIRONMENT", "LOCAL") not in ("LOCAL", "TEST")
        ):
            raise BindingDenied("local_only")
        if args.bind_one:
            if (
                args.approved_source_sha256 != EXPECTED_SOURCE_DIGEST
                or not args.approved_receiver_id
                or not args.approved_credential_id
            ):
                raise BindingDenied("fresh_exact_binding_approval_required")
        elif any((
            args.approved_source_sha256,
            args.approved_receiver_id,
            args.approved_credential_id,
        )):
            raise BindingDenied("read_only_mode_does_not_accept_approval")
        before, source = preflight()
        print("PASS LOCAL inactive v2 receiver and one dedicated encrypted credential preflight", flush=True)
        if not args.bind_one:
            print("PASS read-only; credential remains unbound and no workflow changes", flush=True)
            return 0
        if (
            args.approved_receiver_id != before.receiver_id
            or args.approved_credential_id != before.credential_id
        ):
            raise BindingDenied("approval_identity_mismatch")
        # Independent immediate recheck prior to the one permitted import.
        latest, _ = preflight()
        if latest != before:
            raise BindingDenied("resource_drift_before_binding")
        bind_once(before, source)
        if not postcondition(before, source):
            raise BindingDenied("binding_postcondition_unverified_no_retry")
        print("PASS exactly one LOCAL receiver webhook Header Auth reference bound", flush=True)
        print("PASS receiver inactive; all other workflows unchanged; no executions", flush=True)
        return 0
    except BindingDenied:
        print("BLOCKED exact LOCAL binding prerequisite or postcondition; no retry", flush=True)
        return 2
    except Exception:
        print("BLOCKED LOCAL binding unavailable; no retry", flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
