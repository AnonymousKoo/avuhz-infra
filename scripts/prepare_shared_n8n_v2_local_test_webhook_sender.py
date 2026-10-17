#!/usr/bin/env python3
"""Fail-closed LOCAL n8n test-webhook sender; DEFAULT IS READ ONLY.

Opt-in --send-one may send exactly ONE fictional, PII-free event to n8n's
native temporary TEST webhook, after separate approval and human UI listening
registration. It must be supplied the pre-existing inbound token through an
inherited anonymous pipe FD by an independently approved private issuer.
Never exports/decrypts an n8n credential, changes a workflow, or retries.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from scripts import prepare_shared_n8n_v2_local_first_event_qa as qa
from scripts import prepare_shared_n8n_receiver_v2_header_credential_local as inbound

TARGET = "LOCAL_DEVELOPMENT_N8N_5678"
RECEIVER_ID = "0068feb4c96bdb5f"
TEST_URL = "http://127.0.0.1:5678/webhook-test/avuhz-events"
SOURCE_SHA256 = "sha256:" + qa.EXPECTED_RECEIVER_SHA256
MAX_TOKEN_BYTES = 512
MAX_RESPONSE_BYTES = 512


class TestWebhookSendDenied(RuntimeError):
    """No dynamic subprocess, HTTP, or secret content permitted in errors."""


class TestWebhookHttpOutcome(TestWebhookSendDenied):
    """An allowlisted, sanitized HTTP outcome, never response body or headers."""

    _CATEGORIES = frozenset({
        "HTTP_400", "HTTP_401", "HTTP_403", "HTTP_404", "HTTP_405",
        "HTTP_409", "HTTP_415", "HTTP_422", "HTTP_429", "HTTP_500",
        "HTTP_502", "HTTP_503", "HTTP_504", "HTTP_OTHER_NON_202",
        "HTTP_202_INVALID_RESPONSE", "TRANSPORT_AMBIGUOUS",
    })

    def __init__(self, category: str) -> None:
        if category not in self._CATEGORIES:
            raise ValueError("invalid_safe_http_category")
        self.category = category
        super().__init__("sanitized_local_http_outcome")


def _one_readonly_preflight() -> tuple[qa.QaReadback, dict, str]:
    state = qa.preflight(expect_one=False)
    event = qa.fictional_event()
    event_digest = qa._digest(event)
    if state.stored_receipts != 0 or state.active_workflows != 0 or state.visible_workflows != 6:
        raise TestWebhookSendDenied("local_readback_mismatch")
    return state, event, event_digest


def _pinned_source_commit() -> str:
    p = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=5, text=True, check=False,
    )
    if p.returncode or len(p.stdout.strip()) != 40:
        raise ValueError
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=5, text=True, check=False,
    )
    if dirty.returncode or dirty.stdout.strip():
        raise ValueError
    return p.stdout.strip()


def _read_inbound_from_fd(fd: int) -> str:
    """Read at most one existing private issuer token from an approved FD."""
    if type(fd) is not int or fd < 3:
        raise TestWebhookSendDenied("private_token_fd_denied")
    data = bytearray()
    try:
        while len(data) <= MAX_TOKEN_BYTES:
            part = os.read(fd, MAX_TOKEN_BYTES + 1 - len(data))
            if not part:
                break
            data.extend(part)
            if len(data) > MAX_TOKEN_BYTES:
                break
    except OSError:
        raise TestWebhookSendDenied("private_token_fd_denied") from None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if (
        not 32 <= len(data) <= MAX_TOKEN_BYTES
        or any(byte < 33 or byte > 126 for byte in data)
    ):
        raise TestWebhookSendDenied("private_token_invalid")
    return data.decode("ascii")


def _post_one(*, event: dict, token: str) -> bool:
    """One loopback POST, no redirects, proxy, automatic retry or raw logging."""
    body = json.dumps(
        event, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("ascii")
    if len(body) > 4096 or not 32 <= len(token) <= MAX_TOKEN_BYTES:
        raise TestWebhookSendDenied("event_or_token_invalid")
    conn = http.client.HTTPConnection("127.0.0.1", 5678, timeout=8)
    try:
        conn.request(
            "POST", "/webhook-test/avuhz-events", body=body, headers={
                inbound.HEADER_NAME: token,
                "Content-Type": "application/json",
                "X-Avuhz-Delivery-Key": event["delivery_idempotency_key"],
                "Cache-Control": "no-store",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        # Classify only a fixed safe status code. Never read or print a
        # rejected response's possibly attacker-controlled body or headers.
        if response.status != 202:
            safe_category = "HTTP_" + str(response.status)
            if safe_category not in TestWebhookHttpOutcome._CATEGORIES:
                safe_category = "HTTP_OTHER_NON_202"
            raise TestWebhookHttpOutcome(safe_category)
        if response.getheader("Content-Length"):
            declared = response.getheader("Content-Length")
            if not declared.isdecimal() or int(declared) > MAX_RESPONSE_BYTES:
                raise TestWebhookHttpOutcome("HTTP_202_INVALID_RESPONSE")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise TestWebhookHttpOutcome("HTTP_202_INVALID_RESPONSE")
        try:
            obj = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise TestWebhookHttpOutcome("HTTP_202_INVALID_RESPONSE") from None
        if type(obj) is not dict or obj != {"accepted": True}:
            raise TestWebhookHttpOutcome("HTTP_202_INVALID_RESPONSE")
        return True
    except (OSError, http.client.HTTPException, TimeoutError):
        # The POST might already have committed; never retry.
        raise TestWebhookHttpOutcome("TRANSPORT_AMBIGUOUS") from None
    finally:
        conn.close()


def _send_once(args: argparse.Namespace) -> int:
    """One approval consumption only; perform no second POST even on ambiguity."""
    before, event, digest = _one_readonly_preflight()
    if (
        args.approved_receiver_id != RECEIVER_ID
        or args.approved_test_url != TEST_URL
        or args.approved_source_sha256 != SOURCE_SHA256
        or args.approved_receipt_endpoint != before.endpoint
        or args.approved_event_digest != "sha256:" + digest
        or not args.approved_source_commit
        or not isinstance(args.token_fd, int) or args.token_fd < 3
    ):
        raise TestWebhookSendDenied("exact_one_event_approval_required")
    if _pinned_source_commit() != args.approved_source_commit:
        raise TestWebhookSendDenied("exact_source_commit_mismatch")
    # Read-only drift check BEFORE touching the protected token pipe.
    next_state, next_event, next_digest = _one_readonly_preflight()
    if (before, event, digest) != (next_state, next_event, next_digest):
        raise TestWebhookSendDenied("runtime_or_fixture_drift")
    token = _read_inbound_from_fd(args.token_fd)
    try:
        ok = _post_one(event=event, token=token)
    finally:
        token = None
    if not ok:
        raise TestWebhookSendDenied("one_delivery_not_accepted_no_retry")
    # The postcheck never writes and verifies the exact digest/tenant/key/ID.
    result = qa.preflight(expect_one=True)
    if result.endpoint != before.endpoint or result.listener_pid != before.listener_pid:
        raise TestWebhookSendDenied("post_delivery_runtime_drift_no_retry")
    print("PASS exactly one native LOCAL test webhook delivery, HTTP 202 body accepted")
    print("PASS exact fictional PII-free QA receipt committed once to private SQLite")
    print("NOT CERTIFIED: live acquisition, business ownership, Work Item, replay or negative tests")
    return 0


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--send-one", action="store_true")
    parser.add_argument("--approved-receiver-id")
    parser.add_argument("--approved-test-url")
    parser.add_argument("--approved-receipt-endpoint")
    parser.add_argument("--approved-source-sha256")
    parser.add_argument("--approved-source-commit")
    parser.add_argument("--approved-event-digest")
    parser.add_argument("--token-fd", type=int)
    args = parser.parse_args(argv)
    if (
        args.target != TARGET or os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")
        or os.environ.get("AVUHZ_ENVIRONMENT", "LOCAL") != "LOCAL"
    ):
        print("BLOCKED wrong LOCAL test webhook environment")
        return 2
    try:
        if not args.send_one and any((
            args.approved_receiver_id, args.approved_test_url,
            args.approved_receipt_endpoint, args.approved_source_sha256,
            args.approved_source_commit, args.approved_event_digest,
            args.token_fd is not None,
        )):
            raise TestWebhookSendDenied("no_approval_flags_in_readonly_mode")
        if not args.send_one:
            state, _, digest = _one_readonly_preflight()
            print("PASS read-only bound LOCAL n8n receiver and empty private receipt store")
            print("PASS candidate native test-webhook target (not registered) " + TEST_URL)
            print("PASS fixed fictional event digest sha256:" + digest)
            print("PASS read-only: no credential access, registration, HTTP send or n8n modification")
            print("NEXT explicit UI test-listener and private sender-token approvals are required")
            return 0
        return _send_once(args)
    except TestWebhookHttpOutcome as failure:
        # Fixed allowlist is the ONLY dynamic HTTP diagnostic printed.
        print("BLOCKED LOCAL test webhook outcome=" + failure.category + "; no retry")
        return 2
    except (TestWebhookSendDenied, qa.FirstEventQaDenied, OSError, ValueError,
            subprocess.SubprocessError):
        print("BLOCKED one LOCAL test webhook operation; no retry; reconcile read-only")
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
