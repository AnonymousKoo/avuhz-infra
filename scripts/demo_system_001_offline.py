#!/usr/bin/env python3
"""Show Avuhz System #001 using only synthetic LOCAL/TEST state.

No provider connections, customer records, n8n activation, durable SQL, or
credentials. Reuses the shared Work Intake reducer, schema-valid event
projection, and existing Avuhz outbox/n8n adapter with an injected stub.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.in_memory import MemoryStore
from avuhz_service.shared_work_intake_candidate import (
    SharedWorkIntakeCandidate, WorkIntakeCommand, WorkIntakeDenied,
)
from avuhz_service.shared_work_intake_lifecycle_projection import (
    project_test_work_intake_lifecycle_event,
)
from avuhz_worker.n8n_event_sink import N8nOutboxSink
from avuhz_worker.outbox import MemoryOutboxUnitOfWork, OutboxWorker, WorkerSettings

TENANT = "a4730000-0000-4000-8000-000000000001"
OTHER_TENANT = "a4730000-0000-4000-8000-000000000002"
ITEM = "a4730000-0000-4000-8000-000000000031"
CORRELATION = "a4730000-0000-4000-8000-000000000044"
EVENT_PREFIX = "f8000000-0000-4000-8000-0000000000"
EVENT_TIME = "2030-01-15T15:00:00Z"
CLOCK = datetime(2030, 1, 15, 15, 0, tzinfo=timezone.utc)
CAPABILITIES = frozenset((
    "work_intake:create", "work_intake:manage", "work_intake:accept",
    "work_intake:read",
))


def _human(principal: str, tenant: str) -> TrustedExecutionContext:
    return TrustedExecutionContext(
        authenticated=True,
        principal_id=principal,
        caller_type="HUMAN",
        tenant_id=tenant,
        organization_id=None,
        capabilities=CAPABILITIES,
        authority_roles=frozenset(),
        environment="DEVELOPMENT",  # Synthetic trusted resolver, not hosted AUTH.
        audience="avuhz-command-api",
        authentication_strength="STRONG",
        step_up_satisfied=False,
        authenticated_at="2026-01-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
    )


def _command(kind: str, version: int | None, key: str, *,
             recipient: str | None = None) -> WorkIntakeCommand:
    return WorkIntakeCommand(
        kind=kind, work_item_id=ITEM, idempotency_key=key,
        expected_record_version=version,
        source="web" if kind == "OPEN" else None,
        classification="service_request" if kind == "OPEN" else None,
        recipient=recipient,
    )


def run_demo() -> dict:
    """Return only non-sensitive synthetic operational evidence."""
    identity = {
        "sender": _human("worker.sender", TENANT),
        "receiver": _human("worker.receiver", TENANT),
        "outsider": _human("worker.outsider", OTHER_TENANT),
    }
    members = frozenset(("worker.sender", "worker.receiver"))
    engine = SharedWorkIntakeCandidate(
        lambda token: identity[token],
        resolve_tenant_member=lambda tenant, member: (
            member if tenant == TENANT and member in members else None
        ),
    )
    steps = (
        ("sender", "OPEN", None, "opened0001", None),
        ("sender", "OFFER_HANDOFF", 1, "offered001", "worker.receiver"),
        ("receiver", "ACCEPT_HANDOFF", 2, "accepted001", None),
        ("receiver", "BLOCK", 3, "blocked001", None),
        ("receiver", "RESUME", 4, "resumed001", None),
        ("receiver", "RESOLVE", 5, "resolved001", None),
    )
    history = []
    events = []
    replay_denied_duplicate_event = False
    outsider_denied = False
    previous_owner_denied = False

    for number, (actor, kind, version, key, recipient) in enumerate(steps, 1):
        issued = _command(kind, version, key, recipient=recipient)
        result = engine.apply(actor, issued)
        if number == 1:
            replay = engine.apply(actor, issued)
            replay_denied_duplicate_event = replay.replayed and replay.intent is None
            if not replay_denied_duplicate_event:
                raise RuntimeError("OFFLINE DEMO STOP: replay generated an event")
            try:
                engine.get("outsider", ITEM)
            except WorkIntakeDenied:
                outsider_denied = True
        if number == 3:
            try:
                engine.get("sender", ITEM)
            except WorkIntakeDenied:
                previous_owner_denied = True

        event = project_test_work_intake_lifecycle_event(
            result, environment="TEST",
            event_id=EVENT_PREFIX + f"{number:02d}",
            correlation_id=CORRELATION,
            idempotency_key=f"work-intake-demo-{number:02d}",
            occurred_at=EVENT_TIME,
        )
        events.append(event)
        history.append({
            "step": number,
            "action": kind,
            "state": result.item.state,
            "version": result.item.record_version,
            "owner": "creator" if result.item.owner_reference == "worker.sender" else "recipient",
            "event_type": event["event_type"],
        })

    if not (outsider_denied and previous_owner_denied):
        raise RuntimeError("OFFLINE DEMO STOP: unauthorized read succeeded")

    # This is a synthetic stand-in for an already committed shared outbox.
    # No durable work item, event, or outbox transaction is claimed.
    outbox_store = MemoryStore(
        events=copy.deepcopy(events),
        outbox=[{"event_id": e["event_id"], "status": "PENDING"} for e in events],
    )
    outbound = []

    def _stub_post(url, headers, body):
        # Injected transport makes a network call impossible.
        envelope = json.loads(body)
        if url != "https://n8n.example.invalid/webhook/avuhz-events":
            raise RuntimeError("unapproved synthetic endpoint")
        if not headers.get("X-Avuhz-Webhook-Token"):
            raise RuntimeError("missing synthetic placeholder")
        outbound.append({
            "event_type": envelope["event_type"],
            "version": envelope["authoritative_subject_version"],
        })
        return 202

    sink = N8nOutboxSink(
        environment="TEST", tenant_id=TENANT,
        endpoint="https://n8n.example.invalid/webhook/avuhz-events",
        expected_host="n8n.example.invalid",
        credential_provider=lambda: "x" * 24,  # LOCAL-only dummy, not a real credential.
        post=_stub_post,
    )
    worker = OutboxWorker(
        outbox_store, MemoryOutboxUnitOfWork, sink,
        TrustedExecutionContext(
            authenticated=True, principal_id="service.outbox-worker-local",
            caller_type="INTERNAL_SERVICE", tenant_id=TENANT,
            organization_id=None,
            capabilities=frozenset(("event:publish_internal",)),
            authority_roles=frozenset(), environment="TEST",
            audience="avuhz-command-api", authentication_strength="STRONG",
            step_up_satisfied=False, authenticated_at=EVENT_TIME,
            expires_at="2031-01-01T15:00:00Z",
        ),
        WorkerSettings(tenant_id=TENANT, batch_size=10),
        clock=lambda: CLOCK,
    )
    delivery = worker.run_once()
    duplicate_delivery = worker.run_once()
    if (delivery["published"] != 6 or len(outbound) != 6
        or duplicate_delivery["published"] != 0
        or any(row["status"] != "PUBLISHED" for row in outbox_store.outbox)
        or engine.get("receiver", ITEM).state != "RESOLVED"):
        raise RuntimeError("OFFLINE DEMO STOP: simulated outbox did not complete")

    return {
        "mode": "OFFLINE_SYNTHETIC_ONLY",
        "customer_data_used": False,
        "hosted_database_used": False,
        "live_n8n_used": False,
        "history": history,
        "security": {
            "cross_tenant_read_denied": outsider_denied,
            "former_owner_read_denied": previous_owner_denied,
            "duplicate_command_event_suppressed": replay_denied_duplicate_event,
        },
        "local_outbox": {
            "events_projected": len(events),
            "stub_deliveries": len(outbound),
            "second_run_published": duplicate_delivery["published"],
        },
        "limitations": "In-memory only; no hosted transactional work-item/event/outbox persistence or real n8n receipt.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit sanitized JSON")
    args = parser.parse_args()
    evidence = run_demo()
    if args.json:
        print(json.dumps(evidence, indent=2))
        return
    print("SYSTEM #001 | OFFLINE SYNTHETIC WALKTHROUGH")
    print("No customer data, hosted SQL, network requests or live n8n.")
    for row in evidence["history"]:
        print(
            f"{row['step']}. {row['action']:<15} "
            f"state={row['state']:<8} owner={row['owner']:<9} "
            f"version={row['version']} event={row['event_type']}"
        )
    print("SAFETY | cross-tenant read DENIED | previous owner read DENIED")
    print("REPLAY | duplicate command generated no new event")
    print("SHARED OUTBOX | 6/6 published to LOCAL stub; idle second run published 0")
    print("NOT PROVEN | Consumer-side deduplication or delivery exactly-once")
    print("LIMITATION | No hosted work-item persistence or actual n8n webhook")


if __name__ == "__main__":
    main()
