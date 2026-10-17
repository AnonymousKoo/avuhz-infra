#!/usr/bin/env python3
"""Prepare one in-place LOCAL inbound Header Auth credential rotation.

DEFAULT IS READ-ONLY. A separate, exact Gate B approval may authorize
--rotate-one, which reads one owner-approved 1Password field and updates ONE
existing n8n-encrypted credential ID using one native importer invocation.
Never exports n8n credentials, runs workflows, retries, or changes a secret store.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from avuhz_worker.local_n8n_onepassword_credential import (
    LocalN8nOnePasswordCredential, LocalN8nSecretUnavailable,
)
from scripts import prepare_shared_n8n_v2_local_first_event_qa as qa
from scripts import prepare_shared_n8n_receiver_v2_header_credential_local as inbound

TARGET = "LOCAL_DEVELOPMENT_N8N_5678"
RECEIVER_ID = "0068feb4c96bdb5f"
INBOUND_CREDENTIAL_ID = "6ece28c3-f72d-4021-942d-8d0eb072b711"
RECEIPT_CREDENTIAL_ID = "154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2"
RECEIVER_SHA256 = "sha256:fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f"
REF_RE = re.compile(r"op://[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/password\Z", re.ASCII)
EXPECTED_EXECUTIONS = frozenset()  # #13 and #14 now both absent; cause unknown


class RotationDenied(RuntimeError):
    """Only fixed sanitized error text."""


@dataclass(frozen=True)
class Snapshot:
    endpoint: str
    pid: int
    project_id: str
    receiver_rows: tuple[tuple, ...]
    all_workflows: tuple[tuple, ...]
    credentials: tuple[tuple, ...]
    credential_shares: tuple[tuple, ...]
    workflow_shares: tuple[tuple, ...]
    execution_rows: tuple[tuple, ...]
    total_webhooks: int
    receipt_count: int


def _read_only_snapshot() -> Snapshot:
    """Read only n8n metadata and owner-only QA-store row count; no secrets."""
    state = qa.preflight(expect_one=False)
    if (
        state.endpoint != "http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts"
        or state.stored_receipts != 0
        or state.active_workflows != 0
        or state.visible_workflows != 6 or state.archived_workflows != 1
        or qa.receiver.SOURCE_SHA256 != RECEIVER_SHA256.removeprefix("sha256:")
    ):
        raise RotationDenied("rotation_local_boundary_denied")
    dbfile = qa.receiver._db_path()
    with sqlite3.connect(dbfile.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
        db.execute("PRAGMA query_only=ON")
        personal = db.execute(
            "SELECT id FROM project WHERE type=?", ("personal",)
        ).fetchall()
        if len(personal) != 1:
            raise RotationDenied("rotation_personal_project_denied")
        project_id = personal[0][0]
        workflows = tuple(db.execute(
            "SELECT id,name,active,isArchived,nodes,connections,settings,staticData,pinData "
            "FROM workflow_entity ORDER BY id"
        ).fetchall())
        receiver = tuple(row for row in workflows if row[0] == RECEIVER_ID)
        credentials = tuple(db.execute(
            "SELECT id,name,type,length(data),substr(data,1,1),"
            "createdAt,updatedAt,isManaged FROM credentials_entity ORDER BY id"
        ).fetchall())
        shares = tuple(db.execute(
            "SELECT credentialsId,projectId,role FROM shared_credentials "
            "ORDER BY credentialsId,projectId,role"
        ).fetchall())
        workflow_shares = tuple(db.execute(
            "SELECT workflowId,projectId,role FROM shared_workflow "
            "ORDER BY workflowId,projectId,role"
        ).fetchall())
        executions = tuple(db.execute(
            "SELECT id,workflowId,mode,status,finished,startedAt,stoppedAt "
            "FROM execution_entity ORDER BY id"
        ).fetchall())
        webhooks = db.execute("SELECT count(*) FROM webhook_entity").fetchone()[0]
    incoming = [c for c in credentials if c[0] == INBOUND_CREDENTIAL_ID]
    receipt = [c for c in credentials if c[0] == RECEIPT_CREDENTIAL_ID]
    if (
        len(receiver) != 1 or len(workflows) != 7
        or any(row[2] for row in workflows)
        or len(incoming) != 1 or len(receipt) != 1
        or incoming[0][1:3] != (inbound.CREDENTIAL_NAME, "httpHeaderAuth")
        or receipt[0][1:3] != (qa.receipt.CREDENTIAL_NAME, "httpHeaderAuth")
        or any(type(c[3]) is not int or c[3] < 20 or c[4] == "{"
               for c in (incoming[0], receipt[0]))
        or sum(1 for c in credentials if c[1] == inbound.CREDENTIAL_NAME) != 1
        or sum(1 for c in credentials if c[1] == qa.receipt.CREDENTIAL_NAME) != 1
        or sum(1 for s in shares if s == (
            INBOUND_CREDENTIAL_ID, project_id, "credential:owner",
        )) != 1
        or sum(1 for s in shares if s == (
            RECEIPT_CREDENTIAL_ID, project_id, "credential:owner",
        )) != 1
        or any(s[0] in (INBOUND_CREDENTIAL_ID, RECEIPT_CREDENTIAL_ID)
               and s[1] != project_id for s in shares)
        or sum(1 for s in workflow_shares if
               s[0] == RECEIVER_ID and s[1] == project_id) != 1
        or {r[0] for r in executions} != EXPECTED_EXECUTIONS
        or any(r[1] != RECEIVER_ID or r[2] != "manual" for r in executions)
        # Both historical execution #13 and #14 disappeared since the incident.
        # Require NEW explicit acknowledgement of both absences at mutation;
        # never infer the cause or silently restore/delete execution evidence.
    ):
        raise RotationDenied("rotation_metadata_drift")
    # The canonical bound receiver gate validates *all* five nodes, their exact
    # two encrypted credential references and project shares, plus current URL.
    # Both historical executions are absent; any saved execution row blocks.
    source = qa.receiver._source()
    qa._bound_receiver_readback(source, state.endpoint)
    return Snapshot(
        endpoint=state.endpoint, pid=state.listener_pid,
        project_id=project_id, receiver_rows=receiver,
        all_workflows=workflows, credentials=credentials,
        credential_shares=shares, workflow_shares=workflow_shares,
        execution_rows=executions, total_webhooks=webhooks,
        receipt_count=state.stored_receipts,
    )


def _git_source_commit() -> str:
    for command in (
        ["git", "rev-parse", "--verify", "HEAD"],
        ["git", "status", "--porcelain", "--untracked-files=no"],
    ):
        result = subprocess.run(
            command, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=5, text=True, check=False,
        )
        if result.returncode:
            raise RotationDenied("rotation_source_untrusted")
        if command[1] == "status" and result.stdout.strip():
            raise RotationDenied("rotation_source_dirty")
        if command[1] == "rev-parse":
            head = result.stdout.strip()
            if not re.fullmatch(r"[0-9a-f]{40}", head):
                raise RotationDenied("rotation_source_untrusted")
    return head


def _check_arguments(args: argparse.Namespace, before: Snapshot) -> None:
    if (
        args.approved_receiver_id != RECEIVER_ID
        or args.approved_credential_id != INBOUND_CREDENTIAL_ID
        or args.approved_receipt_credential_id != RECEIPT_CREDENTIAL_ID
        or args.approved_project_id != before.project_id
        or args.approved_receiver_sha256 != RECEIVER_SHA256
        or args.approved_receipt_endpoint != before.endpoint
        or args.approved_execution_13_14_absence != "EXACT_13_AND_14_ABSENT"
        or not isinstance(args.approved_source_commit, str)
        or args.approved_source_commit != _git_source_commit()
        or not isinstance(args.approved_secret_reference, str)
        or REF_RE.fullmatch(args.approved_secret_reference) is None
    ):
        raise RotationDenied("rotation_exact_gate_b_approval_required")


def _native_update_once(project_id: str, new_token: str) -> None:
    """One native n8n 1.103.2 credential upsert on SAME ID, never a new item."""
    if (
        type(new_token) is not str or not 48 <= len(new_token) <= 64
        or not re.fullmatch(r"[A-Za-z0-9]{48,64}", new_token, re.ASCII)
    ):
        raise RotationDenied("replacement_secret_format_denied")
    credential = {
        "id": INBOUND_CREDENTIAL_ID,
        "name": inbound.CREDENTIAL_NAME,
        "type": "httpHeaderAuth",
        "data": {"name": inbound.HEADER_NAME, "value": new_token},
    }
    encoded = json.dumps([credential], separators=(",", ":"), ensure_ascii=True).encode("ascii")
    try:
        result = subprocess.run(
            ["docker", "exec", "-i", "n8n", "n8n", "import:credentials",
             "--input=/dev/stdin", "--projectId=" + project_id],
            input=encoded, stdin=None, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=75, check=False,
        )
        if result.returncode != 0:
            raise RotationDenied("single_inplace_credential_update_unverified")
    except (OSError, subprocess.SubprocessError):
        raise RotationDenied("single_inplace_credential_update_ambiguous_no_retry") from None
    finally:
        encoded = None
        credential = None


def _verify_postcondition(before: Snapshot, after: Snapshot) -> None:
    """Allow only encrypted storage length changes for the existing inbound ID.

    Ciphertext must not be selected or fingerprinted. Metadata-only checks
    cannot establish revocation of the old secret; a separate authorized
    authentication test is still required.
    """
    if (
        before.endpoint != after.endpoint or before.pid != after.pid
        or before.project_id != after.project_id
        or before.receiver_rows != after.receiver_rows
        or before.all_workflows != after.all_workflows
        or before.credential_shares != after.credential_shares
        or before.workflow_shares != after.workflow_shares
        or before.execution_rows != after.execution_rows
        or before.total_webhooks != after.total_webhooks
        or before.receipt_count != after.receipt_count
        or len(before.credentials) != len(after.credentials)
    ):
        raise RotationDenied("rotation_postcondition_unverified_no_retry")
    for old, new in zip(before.credentials, after.credentials):
        if old[0] != new[0] or old[1:3] != new[1:3]:
            raise RotationDenied("rotation_credential_identity_drift")
        if old[0] == INBOUND_CREDENTIAL_ID:
            if (
                not isinstance(new[3], int) or new[3] < 20 or new[4] == "{"
                or old[5] != new[5] or old[7] != new[7]
                or old[6] == new[6]
            ):
                # updatedAt must change to distinguish a genuine upsert from
                # a CLI command that swallowed an importer error (exit=0).
                raise RotationDenied("rotation_updated_metadata_not_proven")
        elif old != new:
            raise RotationDenied("rotation_unrelated_credential_modified")


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--rotate-one", action="store_true")
    for field in (
        "receiver-id", "credential-id", "receipt-credential-id",
        "project-id", "receiver-sha256", "receipt-endpoint",
        "source-commit", "secret-reference", "execution-13-14-absence",
    ):
        parser.add_argument("--approved-" + field)
    args = parser.parse_args(argv)
    if (
        args.target != TARGET or os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")
        or os.environ.get("AVUHZ_ENVIRONMENT", "LOCAL") != "LOCAL"
    ):
        print("BLOCKED wrong LOCAL inbound rotation environment")
        return 2
    try:
        before = _read_only_snapshot()
        if not args.rotate_one:
            if any(getattr(args, key) is not None for key in (
                "approved_receiver_id", "approved_credential_id",
                "approved_receipt_credential_id", "approved_project_id",
                "approved_receiver_sha256", "approved_receipt_endpoint",
                "approved_source_commit", "approved_secret_reference",
                "approved_execution_13_14_absence",
            )):
                raise RotationDenied("rotation_readonly_mode_disallows_approval_flags")
            print("PASS LOCAL inactive shared receiver, existing inbound encrypted credential")
            print("PASS receipt credential, executions #13 and #14 absent, zero receipts")
            print("PASS read-only: no 1Password field read, import, event or workflow change")
            print("REQUIRES new exact Gate B approval to update the existing encrypted ID")
            return 0
        _check_arguments(args, before)
        # Revalidate immediately before reading the already-rotated private field.
        if _read_only_snapshot() != before:
            raise RotationDenied("rotation_runtime_changed_before_secret_read")
        provider = LocalN8nOnePasswordCredential(
            environment="LOCAL", approved_secret_reference=args.approved_secret_reference,
        )
        token = provider()
        try:
            # After reading the new field, no other resource is changed before
            # the one native encrypted credential upsert.
            _native_update_once(before.project_id, token)
        finally:
            token = None
        after = _read_only_snapshot()
        _verify_postcondition(before, after)
        print("PASS one authorized encrypted in-place LOCAL inbound credential update")
        print("PASS same existing credential ID/project, receipt credential and workflow unchanged")
        print("NOT PROVEN: old token revoked in running n8n memory; no auth request sent")
        return 0
    except (RotationDenied, qa.FirstEventQaDenied, LocalN8nSecretUnavailable,
            OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
        print("BLOCKED LOCAL inbound credential rotation; no retry; reconcile read-only")
        return 2
    except Exception:
        print("BLOCKED LOCAL inbound credential rotation unavailable; no retry")
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
