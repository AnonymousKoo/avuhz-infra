"""Source-only System #001 composition: no event-derived business authority."""
from __future__ import annotations

from dataclasses import replace
import unittest
from unittest.mock import patch

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_service.shared_acquisition_metadata_lookup import (
    SharedAcquisitionMetadataLookup, VerifiedAcquisitionMetadata,
)
from avuhz_service.shared_acquisition_work_handoff import (
    GovernedAcquisitionWorkPlan, GovernedAcquisitionHandoffDenied,
    SharedAcquisitionWorkHandoff,
)
from avuhz_service.shared_work_intake_candidate import WorkIntakeCommand
from avuhz_service.shared_work_intake_postgres_candidate import (
    SharedWorkIntakePostgresCandidate, DurableWorkReceipt,
)

TENANT = "a4730000-0000-4000-8000-000000000001"
ORG = "a4730000-0000-4000-8000-000000000011"
OTHER = "a4730000-0000-4000-8000-000000000002"
INTAKE = "a4730000-0000-4000-8000-000000000021"
DUE = "2099-01-01T00:10:00Z"


class GovernedHandoffTests(unittest.TestCase):
    def setUp(self):
        # Patch ONLY source-controlled concrete interfaces in tests; synthetic
        # resolver and planner MUST NOT be mounted in any hosted environment.
        self.reader = object.__new__(SharedAcquisitionMetadataLookup)
        self.writer = object.__new__(SharedWorkIntakePostgresCandidate)
        self.metadata = VerifiedAcquisitionMetadata(
            TENANT, INTAKE, ORG, "RECEIVED", 7
        )
        self.plan = GovernedAcquisitionWorkPlan(
            TENANT, ORG, INTAKE, 7, INTAKE, "web", "service_request", DUE
        )
        self.receipt = DurableWorkReceipt(INTAKE, 1, False, "event.qa.1")
        self.identity = "private-signed-identity-evidence"
        self.lookup_calls = []
        self.plan_calls = []
        self.writer_calls = []
        self.read_error = None
        self.plan_error = None
        self.write_error = None

        def lookup(_obj, evidence, intake):
            self.lookup_calls.append((evidence, intake))
            if self.read_error is not None:
                raise RuntimeError(self.read_error)
            return self.metadata

        def execute(_obj, evidence, cmd, *, acquisition_admission=None):
            self.writer_calls.append((evidence, cmd, acquisition_admission))
            if self.write_error is not None:
                raise RuntimeError(self.write_error)
            return self.receipt

        self.read_patch = patch.object(SharedAcquisitionMetadataLookup, "lookup", lookup)
        self.write_patch = patch.object(SharedWorkIntakePostgresCandidate, "execute", execute)
        self.read_patch.start()
        self.write_patch.start()
        self.addCleanup(self.read_patch.stop)
        self.addCleanup(self.write_patch.stop)
        self.handoff = SharedAcquisitionWorkHandoff(
            self.reader, self.writer, resolve_governed_plan=self.planner
        )

    def planner(self, metadata):
        self.plan_calls.append(metadata)
        if self.plan_error is not None:
            raise RuntimeError(self.plan_error)
        return self.plan

    def denied(self, intake=INTAKE, identity=None):
        with self.assertRaisesRegex(
            GovernedAcquisitionHandoffDenied, "^acquisition handoff unavailable$"
        ):
            self.handoff.open(
                self.identity if identity is None else identity, intake
            )

    def test_success_requires_separate_plan_and_same_identity_for_writer(self):
        result = self.handoff.open(self.identity, INTAKE)
        self.assertIs(result, self.receipt)
        self.assertEqual(self.lookup_calls, [(self.identity, INTAKE)])
        self.assertEqual(self.plan_calls, [self.metadata])
        self.assertEqual(len(self.writer_calls), 1)
        evidence, cmd, admission = self.writer_calls[0]
        self.assertEqual(admission, self.metadata)
        self.assertEqual(evidence, self.identity)
        self.assertIs(type(cmd), WorkIntakeCommand)
        self.assertEqual(cmd.kind, "OPEN")
        self.assertEqual(cmd.work_item_id, INTAKE)
        self.assertEqual(cmd.idempotency_key, "Acq" + INTAKE.replace("-", ""))
        self.assertEqual(cmd.source, "web")
        self.assertEqual(cmd.classification, "service_request")
        self.assertEqual(cmd.next_action_due_at, DUE)
        self.assertIsNone(cmd.expected_record_version)
        self.assertIsNone(cmd.recipient)

    def test_replay_stable_command_without_new_plan_authority(self):
        self.handoff.open(self.identity, INTAKE)
        self.receipt = DurableWorkReceipt(INTAKE, 1, True, None)
        replay = self.handoff.open(self.identity, INTAKE)
        self.assertTrue(replay.replayed)
        self.assertEqual(self.writer_calls[0][1], self.writer_calls[1][1])
        self.assertEqual(len(self.plan_calls), 2)

    def test_untrusted_intake_or_opaque_identity_rejected_before_read(self):
        for invalid in ("", "not-a-uuid", INTAKE.upper(), 5, None, True):
            with self.subTest(invalid=invalid):
                self.denied(invalid)
        context = TrustedExecutionContext(
            True, "person.qa", "HUMAN", TENANT, ORG,
            frozenset({"work_intake:create"}), frozenset(),
            "DEVELOPMENT", "avuhz-command-api", "STRONG",
            False, "2026-10-16T00:00:00Z", "2099-01-01T00:00:00Z"
        )
        self.denied(identity=context)
        self.assertEqual(self.lookup_calls, [])
        self.assertEqual(self.plan_calls, [])
        self.assertEqual(self.writer_calls, [])

    def test_read_denial_does_not_call_plan_or_writer(self):
        self.read_error = "secret JWT / SQL exception"
        self.denied()
        self.assertEqual(self.plan_calls, [])
        self.assertEqual(self.writer_calls, [])

    def test_wrong_or_ineligible_metadata_denied(self):
        variants = (
            None, {}, True,
            replace(self.metadata, intake_id=OTHER),
            replace(self.metadata, tenant_id=OTHER),
            replace(self.metadata, organization_id="not-a-uuid"),
            replace(self.metadata, intake_state="REJECTED"),
            replace(self.metadata, record_version=0),
            replace(self.metadata, record_version=True),
        )
        for candidate in variants:
            with self.subTest(case=repr(type(candidate))):
                self.metadata = candidate
                self.denied()
        # A trusted reader may return a structurally valid different tenant.
        # The plan runs, but the mismatch MUST NOT reach the writer.
        self.assertEqual(self.writer_calls, [])

    def test_policy_unavailable_denied(self):
        self.plan_error = "no independent business authorization"
        self.denied()
        self.assertEqual(self.writer_calls, [])

    def test_plan_must_be_exact_trusted_type(self):
        for invalid in (None, {}, "receipt", WorkIntakeCommand("OPEN", INTAKE, "a_long_key")):
            with self.subTest(invalid=type(invalid).__name__):
                self.plan = invalid
                self.denied()
        self.assertEqual(self.writer_calls, [])

    def test_wrong_tenant_org_intake_and_revision_deny(self):
        for modified in (
            {"tenant_id": OTHER}, {"organization_id": OTHER},
            {"intake_id": OTHER}, {"work_item_id": OTHER},
            {"intake_record_version": 8}, {"intake_record_version": True},
        ):
            with self.subTest(modified=modified):
                self.plan = replace(GovernedAcquisitionWorkPlan(
                    TENANT, ORG, INTAKE, 7, INTAKE,
                    "web", "service_request", DUE
                ), **modified)
                self.denied()
        self.assertEqual(self.writer_calls, [])

    def test_missing_or_unapproved_business_deadline_denied(self):
        for due in (None, "later", "2030-09-01", "2030-11-01T01:22:31+00:00", "2026-13-01T00:10:00Z"):
            with self.subTest(due=due):
                self.plan = replace(self.plan, next_action_due_at=due)
                self.denied()
        self.assertEqual(self.writer_calls, [])

    def test_source_and_classification_never_inferred_from_intake(self):
        for attrs in (
            {"source": None}, {"source": "unknown-vertical"},
            {"classification": None}, {"classification": "pay_now"},
        ):
            with self.subTest(attrs=attrs):
                self.plan = replace(
                    GovernedAcquisitionWorkPlan(
                        TENANT, ORG, INTAKE, 7, INTAKE,
                        "web", "service_request", DUE
                    ), **attrs,
                )
                self.denied()
        self.assertEqual(self.writer_calls, [])

    def test_writer_authorization_fail_closed(self):
        self.write_error = "owner revoked, SQL DSN, secret"
        self.denied()
        self.assertEqual(len(self.writer_calls), 1)

    def test_response_cannot_be_substituted(self):
        for wrong in (None, {}, True, DurableWorkReceipt(OTHER, 1, False, None),
                      DurableWorkReceipt(INTAKE, 0, False, None),
                      DurableWorkReceipt(INTAKE, True, False, None)):
            with self.subTest(wrong=type(wrong).__name__):
                self.receipt = wrong
                self.denied()

    def test_constructor_requires_existing_shared_components(self):
        for args in (
            (None, self.writer, self.planner),
            (self.reader, None, self.planner),
            (self.reader, self.writer, None),
        ):
            with self.subTest(args=args[0] is None):
                with self.assertRaises(ValueError):
                    SharedAcquisitionWorkHandoff(
                        args[0], args[1], resolve_governed_plan=args[2]
                    )


if __name__ == "__main__":
    unittest.main()
