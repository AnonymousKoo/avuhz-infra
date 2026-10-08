"""Credential-free, local-only readiness proof for a fictional DEVELOPMENT handoff.

This is NOT a live AUTH login, provider command, DATA read, or client approval.
The IDs/timestamps below are reusable offline TEST inputs only. Never submit
this sample to the hosted command API or call it production authorization.
"""
from __future__ import annotations

import copy
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_runtime.in_memory import MemoryStore, UnitOfWork
from avuhz_runtime.models import ValidationSuccess
from avuhz_runtime.validation import CommandValidator
from avuhz_service.application import StaticTrustedIdentityResolver
from avuhz_service.composition import create_service_application
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY,
)

CANONICAL_DEVELOPMENT_TENANT = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
SAMPLE_HANDOFF_ID = "a6b00000-0000-4000-8000-000000000001"
SAMPLE_COMMAND_ID = "a6b00000-0000-4000-8000-000000000002"
SAMPLE_CORRELATION_ID = "a6b00000-0000-4000-8000-000000000003"
SAMPLE_EVENT_ID = "a6b00000-0000-4000-8000-000000000004"
NOW = "2026-10-08T19:12:00Z"


def fictional_handoff():
    fixture = json.loads(
        (ROOT / "contracts/fixtures/v1/phase5d-implementation-package.cases.json").read_text()
    )
    handoff = copy.deepcopy(fixture["positive"]["implementation_handoff"])
    handoff.update(
        implementation_handoff_id=SAMPLE_HANDOFF_ID,
        tenant_id=CANONICAL_DEVELOPMENT_TENANT,
        client_reference="client.fictional.local-handoff-certification",
        source_provider_reference="provider.fictional.local-certification",
        source_engagement_reference="a6b00000-0000-4000-8000-000000000005",
        approved_at="2026-10-08T19:10:00Z",
        created_at="2026-10-08T19:09:00Z",
        state="APPROVED",
        handoff_version=1,
    )
    handoff["upstream_approval_references"] = [
        {
            "approval_role": "CLIENT_APPROVER",
            "approval_reference": "approval.synthetic.client.offline-test",
            "approved_by": "human.synthetic.client-offline-test",
            "approved_at": "2026-10-08T19:09:30Z",
        },
        {
            "approval_role": "PROVIDER_APPROVER",
            "approval_reference": "approval.synthetic.provider.offline-test",
            "approved_by": "human.synthetic.provider-offline-test",
            "approved_at": "2026-10-08T19:10:00Z",
        },
    ]
    handoff.pop("handoff_digest")
    handoff["handoff_digest"] = canonical_digest(handoff)
    return handoff


def fictional_envelope(payload=None):
    handoff = fictional_handoff() if payload is None else copy.deepcopy(payload)
    principal = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY.principal_reference
    return {
        "command_id": SAMPLE_COMMAND_ID,
        "command_type": "AcceptImplementationHandoff",
        "command_schema_version": 1,
        "tenant_id": CANONICAL_DEVELOPMENT_TENANT,
        "subject_type": "IMPLEMENTATION_HANDOFF",
        "subject_id": SAMPLE_HANDOFF_ID,
        "requested_by": principal,
        "caller_type": "PROVIDER_ADAPTER",
        "caller_identity": {
            "subject": principal,
            "audience": "avuhz-command-api",
            "caller_type": "PROVIDER_ADAPTER",
            "tenant_ids": [CANONICAL_DEVELOPMENT_TENANT],
            "capabilities": ["implementation_handoff:accept"],
            "environment": "DEVELOPMENT",
            "authentication_strength": "STRONG",
            "step_up_performed": False,
            "authenticated_at": "2026-10-08T19:00:00Z",
            "expires_at": "2026-10-08T19:30:00Z",
        },
        "correlation_id": SAMPLE_CORRELATION_ID,
        "idempotency_key": "synthetic.handoff.offline-certification.0001",
        "requested_at": NOW,
        "environment": "DEVELOPMENT",
        "payload_schema": (
            "urn:avuhz:schema:contracts:commands:"
            "accept-implementation-handoff-payload:v1"
        ),
        "payload_version": 1,
        "payload": handoff,
    }


def trusted_offline_context(*, tenant=CANONICAL_DEVELOPMENT_TENANT, capabilities=None):
    entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
    return TrustedExecutionContext(
        authenticated=True,
        principal_id=entry.principal_reference,
        caller_type=entry.caller_type,
        tenant_id=tenant,
        organization_id=None,
        capabilities=(
            entry.capabilities if capabilities is None else frozenset(capabilities)
        ),
        authority_roles=frozenset(),
        environment="DEVELOPMENT",
        audience="avuhz-command-api",
        authentication_strength="STRONG",
        step_up_satisfied=False,
        authenticated_at="2026-10-08T19:00:00Z",
        expires_at="2026-10-08T19:30:00Z",
    )


def offline_app(store, context):
    # Trusted static resolver is TEST-ONLY: it does not authenticate a bearer JWT.
    return create_service_application(
        store=store,
        uow_factory=UnitOfWork,
        identity_resolver=StaticTrustedIdentityResolver(context),
        readiness_probes={"data": type("LocalProbe", (), {"ready": lambda self: True})()},
        clock=lambda: NOW,
        ids=lambda: SAMPLE_EVENT_ID,
    )


def offline_post(application, payload):
    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    env = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/v1/commands",
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(data)),
        "wsgi.input": io.BytesIO(data),
    }
    result = {}

    def start_response(status, _headers):
        result["status"] = int(status.split()[0])

    body = b"".join(application(env, start_response))
    return result["status"], json.loads(body)


class DevelopmentSyntheticHandoffOfflineCertificationTests(unittest.TestCase):
    def test_exact_dev_tenant_and_registered_envelope_are_schema_valid(self):
        entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
        self.assertEqual(entry.tenant_id, CANONICAL_DEVELOPMENT_TENANT)
        self.assertEqual(entry.caller_type, "PROVIDER_ADAPTER")
        self.assertEqual(entry.capabilities, frozenset({"implementation_handoff:accept"}))
        handoff = fictional_handoff()
        self.assertEqual(
            handoff["handoff_digest"],
            canonical_digest({k: v for k, v in handoff.items() if k != "handoff_digest"}),
        )
        self.assertEqual(
            {x["approval_role"] for x in handoff["upstream_approval_references"]},
            {"CLIENT_APPROVER", "PROVIDER_APPROVER"},
        )
        self.assertEqual(
            len({x["approval_reference"] for x in handoff["upstream_approval_references"]}), 2,
        )
        validator = CommandValidator(ROOT / "contracts/schemas/v1")
        self.assertIsInstance(validator.prepare(fictional_envelope(handoff)), ValidationSuccess)

    def test_one_fictional_acceptance_creates_sanitized_outbox_and_idempotency(self):
        store = MemoryStore()
        app = offline_app(store, trusted_offline_context())
        request = fictional_envelope()
        status, response = offline_post(app, request)
        self.assertEqual((status, response["result"]), (202, "ACCEPTED"))
        accepted = UnitOfWork(store).implementation_handoffs.get_version(
            CANONICAL_DEVELOPMENT_TENANT, SAMPLE_HANDOFF_ID, 1
        )
        self.assertEqual(accepted, request["payload"])
        self.assertEqual(len(store.implementation_handoffs), 1)
        self.assertEqual(len(store.events), 1)
        self.assertEqual(len(store.outbox), 1)
        self.assertEqual(len(store.idempotency), 1)
        self.assertEqual(store.events[0]["event_type"], "implementation_handoff.accepted")
        self.assertEqual(
            store.events[0]["sanitized_metadata"],
            {
                "implementation_handoff_id": SAMPLE_HANDOFF_ID,
                "handoff_version": 1,
                "state": "APPROVED",
            },
        )
        self.assertEqual(store.outbox[0], {"event_id": SAMPLE_EVENT_ID, "status": "PENDING"})
        self.assertEqual(offline_post(app, request)[0], 200)
        changed = copy.deepcopy(request)
        changed["payload"]["constraints"].append("Additional fictional local-only constraint.")
        changed["payload"].pop("handoff_digest")
        changed["payload"]["handoff_digest"] = canonical_digest(changed["payload"])
        self.assertEqual(offline_post(app, changed)[0], 409)
        self.assertEqual((len(store.events), len(store.implementation_handoffs)), (1, 1))

    def test_cross_tenant_and_missing_capability_fail_closed_without_writes(self):
        request = fictional_envelope()
        scenarios = (
            trusted_offline_context(tenant="a6b00000-0000-4000-8000-000000000099"),
            trusted_offline_context(capabilities=set()),
        )
        for identity in scenarios:
            with self.subTest(tenant=identity.tenant_id, capabilities=identity.capabilities):
                store = MemoryStore()
                status, response = offline_post(offline_app(store, identity), request)
                self.assertEqual((status, response["result"]), (403, "REJECTED"))
                self.assertEqual(
                    (len(store.implementation_handoffs), len(store.events), len(store.outbox)),
                    (0, 0, 0),
                )

    def test_secret_shaped_value_is_rejected_and_never_persisted(self):
        store = MemoryStore()
        request = fictional_envelope()
        request["payload"]["constraints"].append("api_" + "key=not-a-valid-input")
        request["payload"].pop("handoff_digest")
        request["payload"]["handoff_digest"] = canonical_digest(request["payload"])
        status, response = offline_post(offline_app(store, trusted_offline_context()), request)
        self.assertEqual((status, response["result"]), (403, "REJECTED"))
        self.assertEqual((store.implementation_handoffs, store.events, store.outbox), ({}, [], []))


if __name__ == "__main__":
    unittest.main()
