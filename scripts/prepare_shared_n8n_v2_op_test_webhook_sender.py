#!/usr/bin/env python3
"""LOCAL-only private 1Password -> one native n8n test-webhook sender bridge.

DEFAULT mode is read-only. Sending requires separate exact approval, a
registered short-lived LOCAL test webhook, and the original independently
approved inbound 1Password field. One secret read, one anonymous private FD,
at most one HTTP POST. No retries, credential export or n8n activation.
"""
from __future__ import annotations

import argparse
import os
import sys

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from avuhz_worker.local_n8n_onepassword_credential import (
    LocalN8nOnePasswordCredential, LocalN8nSecretUnavailable,
)
from scripts import prepare_shared_n8n_v2_local_test_webhook_sender as sender


class PrivateSenderDenied(RuntimeError):
    """Fixed error category only. Never includes a secret or its source."""


def _canonical_sender_argv(args: argparse.Namespace, read_fd: int) -> list[str]:
    return [
        "--target", sender.TARGET,
        "--send-one",
        "--approved-receiver-id", args.approved_receiver_id,
        "--approved-test-url", args.approved_test_url,
        "--approved-receipt-endpoint", args.approved_receipt_endpoint,
        "--approved-source-sha256", args.approved_source_sha256,
        "--approved-source-commit", args.approved_source_commit,
        "--approved-event-digest", args.approved_event_digest,
        "--token-fd", str(read_fd),
    ]


def _verify_approval_and_runtime(args: argparse.Namespace) -> None:
    """Never touch the secret until the exact source/runtime checks pass."""
    if (
        args.approved_receiver_id != sender.RECEIVER_ID
        or args.approved_test_url != sender.TEST_URL
        or args.approved_source_sha256 != sender.SOURCE_SHA256
        or not args.approved_source_commit
        or args.ui_listener_ready is not True
        or not isinstance(args.approved_secret_reference, str)
    ):
        raise PrivateSenderDenied("exact_private_sender_approval_missing")
    state, _event, digest = sender._one_readonly_preflight()
    if (
        args.approved_receipt_endpoint != state.endpoint
        or args.approved_event_digest != "sha256:" + digest
        or args.approved_source_commit != sender._pinned_source_commit()
    ):
        raise PrivateSenderDenied("private_sender_source_or_runtime_drift")


def _private_delivery_once(args: argparse.Namespace) -> int:
    """Reuse the canonical one-send gate without subprocess secret exposure."""
    _verify_approval_and_runtime(args)
    # Validation-only constructor; MUST not read or enumerate vaults.
    provider = LocalN8nOnePasswordCredential(
        environment="LOCAL",
        approved_secret_reference=args.approved_secret_reference,
    )
    # Recheck before the single vault field read; never fall back to another
    # credential if its approved item is absent or inaccessible.
    _verify_approval_and_runtime(args)
    token = provider()
    reader = None
    writer = None
    try:
        # This is an anonymous OS pipe: the token is never in a path, env,
        # command argument, shell history, stdout, stderr, or file.
        reader, writer = os.pipe()
        raw = token.encode("ascii")
        pos = 0
        while pos < len(raw):
            count = os.write(writer, raw[pos:])
            if count <= 0:
                raise OSError
            pos += count
        os.close(writer)
        writer = None
        token = None
        try:
            code = sender.run(_canonical_sender_argv(args, reader))
        finally:
            # Canonical sender closes it; this also handles a mocked or
            # abruptly failed sender without leaving a secret-bearing FD open.
            try:
                os.close(reader)
            except OSError:
                pass
            reader = None
        if code != 0:
            raise PrivateSenderDenied("one_private_delivery_unverified_no_retry")
        print("PASS one approved private 1Password field delivered through anonymous FD")
        print("PASS source-bound n8n sender verified HTTP 202 and exact QA receipt")
        return 0
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
    parser.add_argument("--approved-secret-reference")
    parser.add_argument("--ui-listener-ready", action="store_true")
    args = parser.parse_args(argv)
    if (
        args.target != sender.TARGET
        or os.environ.get("CI")
        or os.environ.get("GITHUB_ACTIONS")
        or os.environ.get("AVUHZ_ENVIRONMENT", "LOCAL") != "LOCAL"
    ):
        print("BLOCKED wrong LOCAL private sender boundary")
        return 2
    try:
        if not args.send_one:
            if (
                any((
                    args.approved_receiver_id,
                    args.approved_test_url,
                    args.approved_receipt_endpoint,
                    args.approved_source_sha256,
                    args.approved_source_commit,
                    args.approved_event_digest,
                    args.approved_secret_reference,
                ))
                or args.ui_listener_ready
            ):
                raise PrivateSenderDenied("read_only_cannot_claim_approval")
            state, _event, digest = sender._one_readonly_preflight()
            print("PASS source-bound LOCAL private one-event sender and bound inactive receiver")
            print("PASS private receipt endpoint " + state.endpoint)
            print("PASS fictional event digest sha256:" + digest)
            print("PASS read-only: no 1Password call, listener, n8n execution, HTTP send or storage write")
            print("NEXT approve and register LOCAL temporary UI test listener separately")
            return 0
        return _private_delivery_once(args)
    except (PrivateSenderDenied, LocalN8nSecretUnavailable,
            sender.TestWebhookSendDenied, OSError, ValueError):
        print("BLOCKED LOCAL private event sender, no retry; reconcile read-only")
        return 2
    except Exception:
        print("BLOCKED LOCAL private sender unavailable, no retry")
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
