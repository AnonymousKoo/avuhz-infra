#!/usr/bin/env python3
"""Source-only LOCAL Gate C replay probe; default READ-ONLY, never retries.

A future exact owner authorization may permit ONE native test-webhook POST of
the SAME pinned fictional event after its exact durable receipt already exists.
The existing first-delivery sender stays fail-closed on a nonempty receipt store.
This command never registers listeners, activates workflows, changes n8n
credentials, or accesses Supabase. Only the signed-in owner may run send mode.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from avuhz_worker.local_n8n_onepassword_credential import (
    LocalN8nOnePasswordCredential, LocalN8nSecretUnavailable,
)
from scripts import prepare_shared_n8n_receiver_v2_local as receiver
from scripts import prepare_shared_n8n_v2_local_first_event_qa as qa
from scripts import prepare_shared_n8n_v2_local_test_webhook_sender as first
from scripts import prepare_shared_n8n_receiver_v2_header_credential_local as inbound
from scripts import prepare_shared_n8n_v2_op_receipt_credential_local as receipt

TARGET = "LOCAL_DEVELOPMENT_N8N_5678"
PROJECT_ID = "axT3GLERZRiPXxnj"
INBOUND_ID = "6ece28c3-f72d-4021-942d-8d0eb072b711"
RECEIPT_ID = "154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2"
RECEIPT_ENDPOINT = "http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts"
FIXTURE_DIGEST = "5d6483c5d7d971a30f2416f03174c4e6ee480eeb00ead3667699b26ec22f4974"
EXPECTED_SOURCE_SHA256 = "sha256:fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f"


class ReplayDenied(RuntimeError):
    """Always emit sanitized fixed status text, not exception details."""


@dataclass(frozen=True)
class Evidence:
    runtime: qa.QaReadback
    credential_metadata: tuple[tuple, ...]
    event_digest: str


def _preflight() -> Evidence:
    """Strict read-only preflight for ONE previously committed fictional receipt."""
    try:
        if (
            first.SOURCE_SHA256 != EXPECTED_SOURCE_SHA256
            or qa.EXPECTED_RECEIVER_SHA256 != EXPECTED_SOURCE_SHA256.removeprefix("sha256:")
            or receiver.SOURCE_SHA256 != qa.EXPECTED_RECEIVER_SHA256
            or first.RECEIVER_ID != qa.RECEIVER_ID
            or first.TEST_URL != "http://127.0.0.1:5678/webhook-test/avuhz-events"
        ):
            raise ValueError
        runtime = qa.preflight(expect_one=True)
        if (
            runtime.endpoint != RECEIPT_ENDPOINT
            or runtime.stored_receipts != 1
            or runtime.saved_executions != 0
            or runtime.active_workflows != 0
            or runtime.visible_workflows != 6
            or runtime.archived_workflows != 1
        ):
            raise ValueError
        expected = (
            (INBOUND_ID, inbound.CREDENTIAL_NAME),
            (RECEIPT_ID, receipt.CREDENTIAL_NAME),
        )
        db_path = receiver._db_path()
        with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
            db.execute("PRAGMA query_only=ON")
            if db.execute(
                "SELECT id FROM project WHERE type=?", ("personal",)
            ).fetchall() != [(PROJECT_ID,)]:
                raise ValueError
            metadata = []
            for ident, name in expected:
                # No encrypted data value, n8n execution body, or token is read.
                rows = db.execute(
                    "SELECT id,name,type,createdAt,updatedAt,length(data) "
                    "FROM credentials_entity WHERE id=?", (ident,),
                ).fetchall()
                shares = db.execute(
                    "SELECT projectId,role FROM shared_credentials "
                    "WHERE credentialsId=?", (ident,),
                ).fetchall()
                if (
                    len(rows) != 1 or rows[0][0:3] != (ident, name, "httpHeaderAuth")
                    or not isinstance(rows[0][5], int) or rows[0][5] < 20
                    or shares != [(PROJECT_ID, "credential:owner")]
                ):
                    raise ValueError
                metadata.append(rows[0])
        event = qa.fictional_event()
        digest = qa._digest(event)
        if digest != FIXTURE_DIGEST:
            raise ValueError
        return Evidence(runtime, tuple(metadata), digest)
    except Exception:
        raise ReplayDenied("replay_preflight_denied") from None


def _approval_matches(args: argparse.Namespace, state: Evidence) -> bool:
    return (
        args.approved_receiver_id == first.RECEIVER_ID
        and args.approved_test_url == first.TEST_URL
        and args.approved_receipt_endpoint == RECEIPT_ENDPOINT
        and args.approved_source_sha256 == EXPECTED_SOURCE_SHA256
        and args.approved_event_digest == "sha256:" + state.event_digest
        and args.approved_source_commit == first._pinned_source_commit()
        and args.ui_listener_ready is True
        and isinstance(args.approved_secret_reference, str)
    )


def _send_one(args: argparse.Namespace) -> None:
    # Do not touch 1Password or any token unless all source/runtime gates pass.
    before = _preflight()
    if not _approval_matches(args, before):
        raise ReplayDenied("replay_approval_denied")
    provider = LocalN8nOnePasswordCredential(
        environment="LOCAL", approved_secret_reference=args.approved_secret_reference,
    )
    if _preflight() != before:
        raise ReplayDenied("replay_runtime_drift")
    token = provider()
    reader = writer = None
    try:
        # Same private anonymous FD convention as the positive-path sender.
        reader, writer = os.pipe()
        raw = token.encode("ascii")
        offset = 0
        while offset < len(raw):
            size = os.write(writer, raw[offset:])
            if size <= 0:
                raise ReplayDenied("private_fd_denied")
            offset += size
        os.close(writer)
        writer = None
        token = None
        token = first._read_inbound_from_fd(reader)
        reader = None
        # Fail closed if the receipt, execution count, credential metadata,
        # project, or private service boundary changes before the single POST.
        if _preflight() != before:
            raise ReplayDenied("replay_runtime_drift")
        if not first._post_one(event=qa.fictional_event(), token=token):
            raise ReplayDenied("replay_unverified")
        token = None
        # The exact same row MUST still exist, with no second receipt.
        after = _preflight_post_send()
        if (
            after.credential_metadata != before.credential_metadata
            or after.runtime.endpoint != before.runtime.endpoint
            or after.runtime.listener_pid != before.runtime.listener_pid
            or after.runtime.stored_receipts != 1
            or after.event_digest != before.event_digest
        ):
            raise ReplayDenied("replay_postcondition_denied")
        print("PASS one approved LOCAL fictional replay HTTP 202")
        print("PASS exact original durable receipt unchanged; count remains one")
        print("NOT CERTIFIED: real acquisition, n8n duplicate marker, negative auth or Work Item")
    finally:
        token = None
        if writer is not None:
            try:
                os.close(writer)
            except OSError:
                pass
        if reader is not None:
            try:
                os.close(reader)
            except OSError:
                pass


def _preflight_post_send() -> Evidence:
    """Post-send execution metadata may exist; the receipt must still be exact."""
    # The successful replay creates a soft-deleted manual execution, so only
    # relax the pre-send zero-executions check, never the receipt/tenant gate.
    state = qa.preflight(expect_one=True)
    if state.saved_executions > 1 or state.stored_receipts != 1:
        raise ReplayDenied("replay_postcondition_denied")
    # Credential metadata, owner and fixed source must still match.
    # Temporarily avoid calling _preflight() because it requires no executions.
    return _post_send_evidence(state)


def _post_send_evidence(state: qa.QaReadback) -> Evidence:
    """Recover credential metadata without reading credential values."""
    try:
        if state.endpoint != RECEIPT_ENDPOINT or state.active_workflows != 0:
            raise ValueError
        with sqlite3.connect(receiver._db_path().as_uri() + "?mode=ro", uri=True, timeout=5) as db:
            db.execute("PRAGMA query_only=ON")
            metadata = tuple(
                db.execute(
                    "SELECT id,name,type,createdAt,updatedAt,length(data) "
                    "FROM credentials_entity WHERE id=?", (ident,),
                ).fetchone()
                for ident in (INBOUND_ID, RECEIPT_ID)
            )
        return Evidence(state, metadata, qa._digest(qa.fictional_event()))
    except Exception:
        raise ReplayDenied("replay_postcondition_denied") from None


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--send-one-replay", action="store_true")
    parser.add_argument("--ui-listener-ready", action="store_true")
    parser.add_argument("--approved-receiver-id")
    parser.add_argument("--approved-test-url")
    parser.add_argument("--approved-receipt-endpoint")
    parser.add_argument("--approved-source-sha256")
    parser.add_argument("--approved-source-commit")
    parser.add_argument("--approved-event-digest")
    parser.add_argument("--approved-secret-reference")
    args = parser.parse_args(argv)
    if (
        args.target != TARGET or os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")
        or os.environ.get("AVUHZ_ENVIRONMENT") != "LOCAL"
    ):
        print("BLOCKED replay wrong LOCAL environment")
        return 2
    try:
        if not args.send_one_replay:
            if args.ui_listener_ready or any((
                args.approved_receiver_id, args.approved_test_url,
                args.approved_receipt_endpoint, args.approved_source_sha256,
                args.approved_source_commit, args.approved_event_digest,
                args.approved_secret_reference,
            )):
                raise ReplayDenied("read_only_approval_flags_denied")
            state = _preflight()
            print("PASS read-only exact LOCAL committed fictional receipt; no new delivery")
            print("PASS source-bound replay candidate; stored receipts=" + str(state.runtime.stored_receipts))
            print("NO 1Password read, POST, listener registration or resource change")
            return 0
        _send_one(args)
        return 0
    except (ReplayDenied, LocalN8nSecretUnavailable,
            first.TestWebhookSendDenied, OSError, ValueError, sqlite3.Error):
        print("BLOCKED one LOCAL replay; no retry; reconcile read-only")
        return 2
    except Exception:
        print("BLOCKED LOCAL replay unavailable; no retry")
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
