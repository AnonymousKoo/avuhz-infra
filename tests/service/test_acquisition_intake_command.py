"""Focused non-provider tests for the dormant shared intake writer candidate."""
from __future__ import annotations

import json
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.schema_registry import SchemaRegistry
from jsonschema import Draft202012Validator, FormatChecker
from avuhz_service.acquisition_intake_command import (
    AcquisitionIntakeUnavailable,
    ReceiveAcquisitionIntakeCandidate,
)

TENANT = "a4730000-0000-4000-8000-000000000001"
ORG = "a4730000-0000-4000-8000-000000000011"
REQUEST = "a4730000-0000-4000-8000-000000000021"
NOW = datetime(2026, 10, 10, 12, 1, tzinfo=timezone.utc)


def payload():
    return {
        "external_request_id": REQUEST,
        "source_system": "website.generic",
        "route_reference": "diagnostic.focused",
        "business_name": "Fictional Test Company",
        "contact_name": "Example Person",
        "contact_email": "example@example.invalid",
        "contact_phone": None,
        "preferred_contact_method": "EMAIL",
        "contact_requested": True,
        "diagnostic_summary": "Process delays impact customers.",
    }


def service_context():
    return TrustedExecutionContext(
        authenticated=True, principal_id="service.website-test",
        caller_type="INTERNAL_SERVICE", tenant_id=TENANT, organization_id=ORG,
        capabilities=frozenset({"acquisition_intake:receive"}),
        authority_roles=frozenset(), environment="DEVELOPMENT",
        audience="avuhz-command-api", authentication_strength="STRONG",
        step_up_satisfied=False,
        authenticated_at="2026-10-10T12:00:00Z",
        expires_at="2026-10-10T12:10:00Z",
    )


class Cursor:
    def __init__(self, row, rowcount=1):
        self.row = row
        self.rowcount = rowcount

    def fetchone(self):
        return self.row


class Connection:
    autocommit = False

    def __init__(self, *, authorized=True, existing=None, insert_error=False,
                 event_error=False, outbox_error=False, commit_error=False):
        self.authorized = authorized
        self.existing = existing
        self.insert_error = insert_error
        self.event_error = event_error
        self.outbox_error = outbox_error
        self.commit_error = commit_error
        self.calls = []
        self.rollbacks = 0
        self.commits = 0
        self.closes = 0

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if "set_config('avuhz.tenant_id'" in sql:
            return Cursor({"set_config": TENANT})
        if "from public.avuhz_tenant_organizations" in sql:
            return Cursor({"authorized": 1} if self.authorized else None)
        if "insert into public.avuhz_acquisition_intake_requests" in sql:
            if self.insert_error:
                raise RuntimeError("private fake database diagnostics")
            return Cursor(None if self.existing is not None else {"intake_id": params[0]})
        if "from public.avuhz_acquisition_intake_requests" in sql:
            return Cursor(self.existing)
        if "insert into public.avuhz_lifecycle_events" in sql:
            if self.event_error:
                raise RuntimeError("private fake event insert diagnostics")
            return Cursor(None)
        if "insert into public.avuhz_outbox_deliveries" in sql:
            if self.outbox_error:
                raise RuntimeError("private fake outbox insert diagnostics")
            return Cursor(None)
        raise AssertionError("unexpected SQL")

    def rollback(self):
        self.rollbacks += 1

    def commit(self):
        if self.commit_error:
            raise RuntimeError("private fake commit diagnostics")
        self.commits += 1

    def close(self):
        self.closes += 1


class Store:
    def __init__(self, connection):
        self.connection = connection

    def connection_factory(self):
        return self.connection


def existing_row():
    original = payload()
    return {
        "intake_id": "a4730000-0000-4000-8000-000000000031",
        **{key: value for key, value in original.items()
           if key not in {"external_request_id"}},
    }


class IntakeWriterCandidateTests(unittest.TestCase):
    def service(self, connection, limiter=None):
        self.limiter_calls = []
        def admit(tenant, principal):
            self.limiter_calls.append((tenant, principal))
            return True
        return ReceiveAcquisitionIntakeCandidate(
            Store(connection), limiter if limiter is not None else admit
        )

    def test_new_intake_is_one_scoped_transaction_with_no_client_authority(self):
        connection = Connection()
        receipt = self.service(connection).receive(
            payload(), service_context(), evaluated_at=NOW
        )
        self.assertFalse(receipt.duplicate)
        self.assertEqual(len(receipt.intake_id), 36)
        self.assertEqual(connection.commits, 1)
        self.assertEqual(connection.rollbacks, 0)
        self.assertEqual(connection.closes, 1)
        self.assertEqual(self.limiter_calls, [(TENANT, "service.website-test")])
        self.assertEqual(len(connection.calls), 5)
        self.assertIn("set_config('avuhz.tenant_id'", connection.calls[0][0])
        self.assertEqual(connection.calls[0][1], (TENANT,))
        self.assertIn("lifecycle_state='ACTIVE'", connection.calls[1][0])
        self.assertIn("membership_state='ACTIVE'", connection.calls[1][0])
        self.assertIn("verified_at is not null", connection.calls[1][0])
        self.assertIn("join public.avuhz_tenant_owner_memberships", connection.calls[1][0])
        self.assertIn("limit 1 for share of org, member", connection.calls[1][0])
        self.assertEqual(connection.calls[1][1], (TENANT, ORG))
        self.assertIn("on conflict (tenant_id,external_request_id) do nothing",
                      connection.calls[2][0])
        self.assertEqual(connection.calls[2][1][1:4], (TENANT, ORG, REQUEST))
        self.assertIn("insert into public.avuhz_lifecycle_events", connection.calls[3][0])
        event_parameters = connection.calls[3][1]
        self.assertEqual(event_parameters[1], TENANT)
        self.assertEqual(event_parameters[3], "acquisition.intake.received")
        self.assertEqual(event_parameters[5], "ACQUISITION_INTAKE")
        self.assertEqual(event_parameters[6], receipt.intake_id)
        self.assertEqual(event_parameters[7], 1)
        self.assertEqual(event_parameters[13], "INTEGRATION_INTERNAL")
        self.assertEqual(json.loads(event_parameters[-1]), {
            "intake_id": receipt.intake_id, "intake_state": "RECEIVED",
        })
        self.assertIn("insert into public.avuhz_outbox_deliveries", connection.calls[4][0])
        self.assertEqual(connection.calls[4][1], (
            event_parameters[0], "PENDING", "outbox-delivery:" + event_parameters[0],
            event_parameters[0],
        ))
        self.assertNotIn("tenant_id", payload())
        self.assertNotIn("organization_id", payload())

    def test_rate_limit_identity_does_not_depend_on_client_request_uuid(self):
        connection = Connection()
        seen = []
        service = self.service(
            connection, limiter=lambda tenant, principal: seen.append(
                (tenant, principal)
            ) or True
        )
        first = payload()
        second = payload()
        second["external_request_id"] = "a4730000-0000-4000-8000-000000000099"
        service.receive(first, service_context(), evaluated_at=NOW)
        service.receive(second, service_context(), evaluated_at=NOW)
        self.assertEqual(
            seen,
            [(TENANT, "service.website-test"), (TENANT, "service.website-test")],
        )

    def test_exact_replay_returns_same_receipt_without_duplicate_insert(self):
        connection = Connection(existing=existing_row())
        receipt = self.service(connection).receive(
            payload(), service_context(), evaluated_at=NOW
        )
        self.assertTrue(receipt.duplicate)
        self.assertEqual(receipt.intake_id, existing_row()["intake_id"])
        self.assertEqual(connection.commits, 1)
        self.assertIn("for share", connection.calls[-1][0].lower())
        self.assertNotIn("for update", connection.calls[-1][0].lower())
        self.assertEqual(connection.calls[-1][1], (TENANT, ORG, REQUEST))
        self.assertFalse(any(
            "insert into public.avuhz_lifecycle_events" in sql
            or "insert into public.avuhz_outbox_deliveries" in sql
            for sql, _ in connection.calls
        ))

    def test_conflicting_replay_is_rejected_without_committing(self):
        changed = existing_row()
        changed["contact_name"] = "Different Fictional Person"
        connection = Connection(existing=changed)
        with self.assertRaisesRegex(ValueError, "^acquisition_intake_conflict$"):
            self.service(connection).receive(
                payload(), service_context(), evaluated_at=NOW
            )
        self.assertEqual(connection.commits, 0)
        self.assertEqual(connection.rollbacks, 1)
        self.assertEqual(connection.closes, 1)

    def test_nonactive_owner_or_tenant_is_denied_before_insert(self):
        connection = Connection(authorized=False)
        with self.assertRaisesRegex(PermissionError, "^acquisition_intake_not_authorized$"):
            self.service(connection).receive(
                payload(), service_context(), evaluated_at=NOW
            )
        self.assertEqual(connection.commits, 0)
        self.assertEqual(connection.rollbacks, 1)
        self.assertFalse(any("insert into" in sql for sql, _ in connection.calls))

    def test_absent_or_wrong_service_authority_never_opens_db(self):
        variants = [
            replace(service_context(), authenticated=False),
            replace(service_context(), caller_type="HUMAN"),
            replace(service_context(), environment="PRODUCTION"),
            replace(service_context(), audience="browser"),
            replace(service_context(), principal_id=""),
            replace(service_context(), tenant_id=None),
            replace(service_context(), tenant_id="not-a-uuid"),
            replace(service_context(), organization_id=None),
            replace(service_context(), capabilities=frozenset({"engagement:read"})),
            replace(service_context(), authenticated_at="2026-10-10T11:30:00Z"),
            replace(service_context(), expires_at="2026-10-10T12:00:00Z"),
        ]
        for context in variants:
            with self.subTest(context=context.caller_type):
                connection = Connection()
                with self.assertRaisesRegex(PermissionError, "^acquisition_intake_not_authorized$"):
                    self.service(connection).receive(payload(), context, evaluated_at=NOW)
                self.assertEqual(connection.calls, [])

    def test_rejects_client_forged_tenant_and_ownership_without_db_access(self):
        for forbidden in ("tenant_id", "organization_id", "verified_owner", "intake_id"):
            with self.subTest(forbidden=forbidden):
                connection = Connection()
                body = payload()
                body[forbidden] = TENANT
                with self.assertRaisesRegex(ValueError, "^invalid_acquisition_intake$"):
                    self.service(connection).receive(
                        body, service_context(), evaluated_at=NOW
                    )
                self.assertEqual(connection.calls, [])

    def test_exact_true_consent_required_before_write(self):
        connection = Connection()
        body = payload()
        body["contact_requested"] = "true"
        with self.assertRaisesRegex(ValueError, "^invalid_acquisition_intake$"):
            self.service(connection).receive(
                body, service_context(), evaluated_at=NOW
            )
        self.assertEqual(connection.calls, [])

    def test_missing_or_failing_limiter_denies_before_db(self):
        for gate in (lambda *_: False, lambda *_: 1,
                     lambda *_: (_ for _ in ()).throw(RuntimeError("internal"))):
            connection = Connection()
            with self.subTest(gate=gate):
                with self.assertRaisesRegex(PermissionError, "^acquisition_intake_not_authorized$"):
                    self.service(connection, limiter=gate).receive(
                        payload(), service_context(), evaluated_at=NOW
                    )
                self.assertEqual(connection.calls, [])

    def test_db_failure_is_sanitized_and_rolled_back(self):
        connection = Connection(insert_error=True)
        with self.assertRaisesRegex(AcquisitionIntakeUnavailable,
                                    "^acquisition_intake_unavailable$") as raised:
            self.service(connection).receive(
                payload(), service_context(), evaluated_at=NOW
            )
        self.assertEqual(connection.rollbacks, 1)
        self.assertEqual(connection.closes, 1)
        self.assertNotIn("private fake database diagnostics", str(raised.exception))
        self.assertNotIn(payload()["contact_email"], str(raised.exception))

    def test_lifecycle_event_matches_canonical_schema_without_any_prospect_pii(self):
        connection = Connection()
        receipt = self.service(connection).receive(payload(), service_context(),
                                                   evaluated_at=NOW)
        params = connection.calls[3][1]
        event = {
            "event_id": params[0],
            "tenant_id": params[1],
            "event_type": params[3],
            "event_schema_version": params[4],
            "authoritative_subject_reference": {
                "reference_type": params[5], "reference_id": params[6],
            },
            "authoritative_subject_version": params[7],
            "occurred_at": params[8],
            "producer_reference": params[9],
            "correlation_id": params[10],
            "idempotency_key": params[12],
            "visibility": params[13],
            "sanitized_metadata": json.loads(params[14]),
        }
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        validator = Draft202012Validator(
            registry.expanded(
                "urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"
            ), format_checker=FormatChecker(),
        )
        self.assertEqual(list(validator.iter_errors(event)), [])
        self.assertEqual(event["authoritative_subject_reference"]["reference_id"],
                         receipt.intake_id)
        for secret in (
            payload()["contact_email"], payload()["contact_name"],
            payload()["business_name"], payload()["diagnostic_summary"],
        ):
            self.assertNotIn(secret, json.dumps(event))
        self.assertNotIn("engagement_id", event)

    def test_event_outbox_and_commit_failure_each_rollback_single_intake(self):
        for stage in ("event_error", "outbox_error", "commit_error"):
            with self.subTest(stage=stage):
                connection = Connection(**{stage: True})
                with self.assertRaisesRegex(
                    AcquisitionIntakeUnavailable,
                    "^acquisition_intake_unavailable$",
                ) as error:
                    self.service(connection).receive(payload(), service_context(),
                                                     evaluated_at=NOW)
                self.assertEqual(connection.commits, 0)
                self.assertEqual(connection.rollbacks, 1)
                self.assertEqual(connection.closes, 1)
                self.assertEqual(sum(
                    "insert into public.avuhz_acquisition_intake_requests" in sql
                    for sql, _ in connection.calls
                ), 1)
                self.assertNotIn(payload()["contact_email"], str(error.exception))
                self.assertNotIn("private fake", str(error.exception))
                if stage == "event_error":
                    self.assertFalse(any(
                        "insert into public.avuhz_outbox_deliveries" in sql
                        for sql, _ in connection.calls
                    ))

    def test_no_web_route_registry_grants_or_secret_material_added(self):
        code = (ROOT / "src/avuhz_service/acquisition_intake_command.py").read_text()
        self.assertNotIn("service_role", code)
        self.assertNotIn("CREATE ROLE", code)
        self.assertNotIn("GRANT ", code)
        self.assertNotIn("application._route", code)
        self.assertNotIn("COMMANDS[", code)
        self.assertNotIn("sekinfra", code.lower())


if __name__ == "__main__":
    unittest.main()
