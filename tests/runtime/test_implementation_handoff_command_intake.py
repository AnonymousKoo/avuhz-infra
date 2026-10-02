from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.implementation_handoff import canonical_digest, handoff_reference
from avuhz_runtime.in_memory import Executor, MemoryStore, UnitOfWork
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator


class ImplementationHandoffCommandIntakeTests(unittest.TestCase):
    now = "2030-01-15T15:00:00Z"

    def setUp(self):
        fixture = json.loads(
            (ROOT / "contracts/fixtures/v1/phase5d-implementation-package.cases.json").read_text()
        )
        self.handoff = copy.deepcopy(fixture["positive"]["implementation_handoff"])
        self.store = MemoryStore()
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"),
            GuardPipeline(),
            self.store,
            clock=lambda: self.now,
            ids=lambda: "d5000000-0000-4000-8000-000000000099",
        )

    @property
    def tenant(self):
        return self.handoff["tenant_id"]

    def context(self, capabilities=None, tenant=None):
        effective_capabilities = (
            {"implementation_handoff:accept"} if capabilities is None else capabilities
        )
        return TrustedExecutionContext(
            True,
            "service.sekinfra-handoff-adapter",
            "PROVIDER_ADAPTER",
            tenant or self.tenant,
            None,
            frozenset(effective_capabilities),
            frozenset(),
            "TEST",
            "avuhz-command-api",
            "STRONG",
            False,
            "2030-01-15T14:00:00Z",
            "2030-01-15T16:00:00Z",
        )

    def raw(self, handoff=None, *, command_id=None, idempotency_key="handoff.accept.0001"):
        handoff = copy.deepcopy(handoff or self.handoff)
        return {
            "command_id": command_id or "d5000000-0000-4000-8000-000000000090",
            "command_type": "AcceptImplementationHandoff",
            "command_schema_version": 1,
            "tenant_id": handoff["tenant_id"],
            "subject_type": "IMPLEMENTATION_HANDOFF",
            "subject_id": handoff["implementation_handoff_id"],
            "requested_by": "service.sekinfra-handoff-adapter",
            "caller_type": "PROVIDER_ADAPTER",
            "caller_identity": {
                "subject": "service.sekinfra-handoff-adapter",
                "audience": "avuhz-command-api",
                "caller_type": "PROVIDER_ADAPTER",
                "tenant_ids": [handoff["tenant_id"]],
                "capabilities": ["implementation_handoff:accept"],
                "environment": "TEST",
                "authentication_strength": "STRONG",
                "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z",
                "expires_at": "2030-01-15T16:00:00Z",
            },
            "correlation_id": "d5000000-0000-4000-8000-000000000091",
            "idempotency_key": idempotency_key,
            "requested_at": self.now,
            "environment": "TEST",
            "payload_schema": (
                "urn:avuhz:schema:contracts:commands:"
                "accept-implementation-handoff-payload:v1"
            ),
            "payload_version": 1,
            "payload": handoff,
        }

    def test_accepts_exact_handoff_and_emits_sanitized_outbox_event(self):
        result = self.executor.execute(self.raw(), self.context())
        self.assertEqual(result["result"], "ACCEPTED")
        stored = UnitOfWork(self.store).implementation_handoffs.get_version(
            self.tenant, self.handoff["implementation_handoff_id"], 1
        )
        self.assertEqual(stored, self.handoff)

        event = self.store.events[-1]
        self.assertEqual(event["event_type"], "implementation_handoff.accepted")
        self.assertEqual(
            event["authoritative_subject_reference"],
            {
                "reference_type": "IMPLEMENTATION_HANDOFF",
                "reference_id": self.handoff["implementation_handoff_id"],
            },
        )
        self.assertEqual(
            event["sanitized_metadata"],
            {
                "implementation_handoff_id": self.handoff["implementation_handoff_id"],
                "handoff_version": 1,
                "state": "APPROVED",
            },
        )
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        validator = Draft202012Validator(
            registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"),
            format_checker=FormatChecker(),
        )
        self.assertEqual(list(validator.iter_errors(event)), [])
        self.assertEqual(
            self.store.outbox,
            [{"event_id": event["event_id"], "status": "PENDING"}],
        )

    def test_missing_capability_and_cross_tenant_context_fail_closed(self):
        missing = self.executor.execute(self.raw(), self.context(capabilities=set()))
        self.assertEqual(missing["result"], "REJECTED")
        self.assertEqual(self.store.implementation_handoffs, {})

        other_tenant = "d5000000-0000-4000-8000-000000000099"
        denied = self.executor.execute(
            self.raw(idempotency_key="handoff.accept.0002"),
            self.context(tenant=other_tenant),
        )
        self.assertEqual(denied["result"], "REJECTED")
        self.assertEqual(self.store.implementation_handoffs, {})

    def test_secret_material_is_rejected_without_side_effects(self):
        bad = copy.deepcopy(self.handoff)
        bad["constraints"].append("api_" + "key=fictional-but-prohibited")
        bad.pop("handoff_digest")
        bad["handoff_digest"] = canonical_digest(bad)
        result = self.executor.execute(self.raw(bad), self.context())
        self.assertEqual(result["result"], "REJECTED")
        self.assertEqual(self.store.implementation_handoffs, {})
        self.assertEqual(self.store.events, [])
        self.assertEqual(self.store.outbox, [])

    def test_exact_replay_is_duplicate_and_changed_meaning_conflicts(self):
        raw = self.raw()
        self.assertEqual(self.executor.execute(raw, self.context())["result"], "ACCEPTED")
        self.assertEqual(
            self.executor.execute(copy.deepcopy(raw), self.context())["result"],
            "DUPLICATE",
        )
        changed = copy.deepcopy(raw)
        changed["payload"]["constraints"].append("Bounded additional constraint.")
        changed["payload"].pop("handoff_digest")
        changed["payload"]["handoff_digest"] = canonical_digest(changed["payload"])
        self.assertEqual(self.executor.execute(changed, self.context())["result"], "CONFLICT")

    def test_revocation_is_versioned_and_emits_revoked_event(self):
        self.assertEqual(self.executor.execute(self.raw(), self.context())["result"], "ACCEPTED")
        revoked = copy.deepcopy(self.handoff)
        revoked.update(
            handoff_version=2,
            state="REVOKED",
            supersedes_handoff_reference=handoff_reference(self.handoff),
            revoked_at="2030-01-16T14:00:00Z",
            revocation_reason="Provider approval was withdrawn.",
        )
        revoked.pop("handoff_digest")
        revoked["handoff_digest"] = canonical_digest(revoked)
        raw = self.raw(
            revoked,
            command_id="d5000000-0000-4000-8000-000000000092",
            idempotency_key="handoff.accept.0002",
        )
        self.assertEqual(self.executor.execute(raw, self.context())["result"], "ACCEPTED")
        self.assertEqual(self.store.events[-1]["event_type"], "implementation_handoff.revoked")
        self.assertEqual(self.store.events[-1]["sanitized_metadata"]["handoff_version"], 2)
        versions = UnitOfWork(self.store).implementation_handoffs.list_versions(
            self.tenant, self.handoff["implementation_handoff_id"]
        )
        self.assertEqual(len(versions), 2)


if __name__ == "__main__":
    unittest.main()
