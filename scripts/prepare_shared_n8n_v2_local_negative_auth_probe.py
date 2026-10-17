#!/usr/bin/env python3
"""LOCAL-only shared n8n negative-auth probe. Read-only unless separately approved.

Uses exactly one random INVALID token with the reviewed fictional event.
Never reads a real credential, decrypts n8n credentials, registers a listener,
activates a workflow, retries, reads an HTTP response body, or contacts DATA.
Native installed n8n headerAuth rejects mismatched values with HTTP 403.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from scripts import prepare_shared_n8n_v2_op_replay_test_webhook_sender as replay
from scripts import prepare_shared_n8n_v2_local_test_webhook_sender as first
from scripts import prepare_shared_n8n_v2_local_first_event_qa as qa
from scripts import prepare_shared_n8n_receiver_v2_header_credential_local as inbound

TARGET = "LOCAL_DEVELOPMENT_N8N_5678"
EXPECTED_DENIAL_HTTP = 403


class NegativeAuthDenied(RuntimeError):
    """Only fixed sanitized classifications may be printed."""


def _preflight() -> replay.Evidence:
    """Requires exact one committed fictional receipt, zero saved executions."""
    try:
        state = replay._preflight()
        if (
            first.RECEIVER_ID != "0068feb4c96bdb5f"
            or first.TEST_URL != "http://127.0.0.1:5678/webhook-test/avuhz-events"
            or first.SOURCE_SHA256 != replay.EXPECTED_SOURCE_SHA256
            or state.event_digest != replay.FIXTURE_DIGEST
            or state.runtime.saved_executions != 0
            or state.runtime.stored_receipts != 1
        ):
            raise ValueError
        return state
    except Exception:
        raise NegativeAuthDenied("negative_auth_preflight_denied") from None


def _approved(args: argparse.Namespace, state: replay.Evidence) -> bool:
    return (
        args.approved_receiver_id == first.RECEIVER_ID
        and args.approved_test_url == first.TEST_URL
        and args.approved_receipt_endpoint == replay.RECEIPT_ENDPOINT
        and args.approved_source_sha256 == replay.EXPECTED_SOURCE_SHA256
        and args.approved_event_digest == "sha256:" + state.event_digest
        and args.approved_source_commit == first._pinned_source_commit()
        and args.ui_listener_ready is True
    )


def _post_invalid_one() -> int:
    """Exactly one loopback POST, no redirects, retries or response body reads."""
    event = qa.fictional_event()
    if qa._digest(event) != replay.FIXTURE_DIGEST:
        raise NegativeAuthDenied("invalid_fixture_drift")
    raw = json.dumps(
        event, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    if not 1 <= len(raw) <= 4096:
        raise NegativeAuthDenied("invalid_fixture_drift")
    # This is an ephemeral random deliberately WRONG header, never a credential.
    invalid = secrets.token_urlsafe(48)
    if not 32 <= len(invalid) <= 512:
        raise NegativeAuthDenied("invalid_test_token")
    conn = http.client.HTTPConnection("127.0.0.1", 5678, timeout=8)
    try:
        conn.request(
            "POST", "/webhook-test/avuhz-events", body=raw, headers={
                inbound.HEADER_NAME: invalid,
                "Content-Type": "application/json",
                "X-Avuhz-Delivery-Key": event["delivery_idempotency_key"],
                "Cache-Control": "no-store",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        # Never read rejected bodies or headers. HTTP 200/202 is a security failure.
        status = response.status
        if type(status) is not int or status < 100 or status > 599:
            raise NegativeAuthDenied("invalid_http_status")
        return status
    except (OSError, http.client.HTTPException, TimeoutError):
        raise NegativeAuthDenied("ambiguous_transport_no_retry") from None
    finally:
        invalid = None
        conn.close()


def _send_once(args: argparse.Namespace) -> None:
    before = _preflight()
    if not _approved(args, before):
        raise NegativeAuthDenied("exact_negative_auth_approval_required")
    if _preflight() != before:
        raise NegativeAuthDenied("negative_auth_preflight_drift")
    status = _post_invalid_one()
    # Even a successful denial must be followed by strict read-only reconciliation.
    after = _preflight()
    if after != before:
        raise NegativeAuthDenied("negative_auth_postcondition_drift")
    if status != EXPECTED_DENIAL_HTTP:
        raise NegativeAuthDenied("negative_auth_unexpected_status")
    print("PASS LOCAL n8n native header-auth HTTP 403 rejected one invalid token")
    print("PASS exactly one original fictional receipt retained; zero new executions")
    print("NOT CERTIFIED: production auth, real client admission or System 001 Work Item")


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--send-one-denied", action="store_true")
    parser.add_argument("--ui-listener-ready", action="store_true")
    parser.add_argument("--approved-receiver-id")
    parser.add_argument("--approved-test-url")
    parser.add_argument("--approved-receipt-endpoint")
    parser.add_argument("--approved-source-sha256")
    parser.add_argument("--approved-source-commit")
    parser.add_argument("--approved-event-digest")
    args = parser.parse_args(argv)
    if (
        args.target != TARGET or os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")
        or os.environ.get("AVUHZ_ENVIRONMENT") != "LOCAL"
    ):
        print("BLOCKED wrong LOCAL negative-auth boundary")
        return 2
    try:
        if not args.send_one_denied:
            if args.ui_listener_ready or any((
                args.approved_receiver_id, args.approved_test_url,
                args.approved_receipt_endpoint, args.approved_source_sha256,
                args.approved_source_commit, args.approved_event_digest,
            )):
                raise NegativeAuthDenied("readonly_mutation_flags_denied")
            _preflight()
            print("PASS LOCAL negative-auth read-only preflight; one receipt, zero executions")
            print("NO real credential, invalid POST, listener registration or resource mutation")
            return 0
        _send_once(args)
        return 0
    except (NegativeAuthDenied, ValueError, OSError, qa.FirstEventQaDenied):
        print("BLOCKED LOCAL negative-auth probe; no retry; reconcile read-only")
        return 2
    except Exception:
        print("BLOCKED LOCAL negative-auth unavailable; no retry")
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
