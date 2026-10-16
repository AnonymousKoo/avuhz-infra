"""Real LOCAL PostgreSQL certification for the merged shared acquisition handoff.

Explicitly disposable PG17 and synthetic test identities only. The LIVE local
n8n v2 receipt path is separately certified; this test does NOT run n8n or
claim that a self-signed fixture is a genuine owner. No hosted DATA/AUTH,
tenant registration, workflow activation, credential or customer data.
"""
from __future__ import annotations

import dataclasses
import unittest
from datetime import datetime, timedelta, timezone

from tests.integration import test_shared_work_intake_postgres_candidate as fixture

if fixture.DRIVER:
    from avuhz_service.shared_acquisition_metadata_lookup import (
        SharedAcquisitionMetadataLookup, AcquisitionMetadataDenied,
    )
    from avuhz_service.shared_acquisition_work_handoff import (
        SharedAcquisitionWorkHandoff, GovernedAcquisitionHandoffDenied,
        GovernedAcquisitionWorkPlan,
    )
    from avuhz_service.shared_work_intake_candidate import (
        WorkIntakeCommand, WorkIntakeDenied,
    )
    from avuhz_service.shared_revenue_followup_review import FollowupReviewPolicy
    from avuhz_service.shared_due_work_reader_candidate import SharedDueWorkReadCandidate

TENANT = fixture.TENANT_A
OUTSIDE_TENANT = fixture.TENANT_B
ORG = "a4730000-0000-4000-8000-000000000011"
OTHER_ORG = "a4730000-0000-4000-8000-000000000012"
INTAKE = "a4730000-0000-4000-8000-000000000021"
OTHER_INTAKE = "a4730000-0000-4000-8000-000000000022"

# Only the exact five metadata fields, no acquisition customer PII or row locks.
# This independent disposable fixture mirrors tested RLS and column ACLs.
_LOCAL_ACQUISITION_FIXTURE = """
DO $roles$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='avuhz_acquisition_service_dev')
 THEN CREATE ROLE avuhz_acquisition_service_dev NOLOGIN; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon')
 THEN CREATE ROLE anon NOLOGIN; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated')
 THEN CREATE ROLE authenticated NOLOGIN; END IF;
END $roles$;
CREATE TABLE public.avuhz_acquisition_intake_requests (
 intake_id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
 organization_id uuid NOT NULL, intake_state text NOT NULL,
 record_version integer NOT NULL
);
ALTER TABLE public.avuhz_acquisition_intake_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.avuhz_acquisition_intake_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY avuhz_command_service_tenant_isolation
 ON public.avuhz_acquisition_intake_requests FOR ALL TO avuhz_command_service
 USING (tenant_id = nullif(current_setting('avuhz.tenant_id'::text,true),''::text)::uuid)
 WITH CHECK (tenant_id = nullif(current_setting('avuhz.tenant_id'::text,true),''::text)::uuid);
GRANT SELECT (intake_id,tenant_id,organization_id,intake_state,record_version)
 ON public.avuhz_acquisition_intake_requests TO avuhz_command_service;
INSERT INTO public.avuhz_acquisition_intake_requests
 (intake_id,tenant_id,organization_id,intake_state,record_version)
 VALUES
 ('a4730000-0000-4000-8000-000000000021','a4730000-0000-4000-8000-000000000001',
  'a4730000-0000-4000-8000-000000000011','RECEIVED',1),
 ('a4730000-0000-4000-8000-000000000022','a4730000-0000-4000-8000-000000000002',
  'a4730000-0000-4000-8000-000000000012','RECEIVED',1);
"""


@unittest.skipUnless(fixture.DRIVER and fixture.DSN and fixture.CONTAINER,
                     "disposable PG17, pinned psycopg and local DSN required")
class SharedAcquisitionFullLocalPostgresJourney(unittest.TestCase):
    """Tests new composite WITHOUT browser/n8n-generated owner assertions."""

    def setUp(self):
        self.case = fixture.SharedDurableWorkIntakePostgresTests(
            methodName="test_complete_six_transition_database_event_outbox_and_idempotency_journey"
        )
        self.case.setUp()
        self.addCleanup(self.case.tearDown)
        self.case.docker(
            "psql", "-X", "-v", "ON_ERROR_STOP=1", "-At",
            "-U", "postgres", "-d", fixture.DATABASE,
            source=_LOCAL_ACQUISITION_FIXTURE,
        )
        # Independent synthetic "AUTH" fixture is LOCAL ONLY and may never be
        # registered or presented as a provider-authenticated owner.
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.due = now + timedelta(hours=1)
        self.due_text = self.due.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.case.evidence["sender"] = dataclasses.replace(
            self.case.evidence["sender"],
            organization_id=ORG,
            authenticated_at=(now-timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires_at=(now+timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        self.case.evidence["outside"] = dataclasses.replace(
            self.case.evidence["outside"],
            organization_id=OTHER_ORG,
            authenticated_at=(now-timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires_at=(now+timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        self.reader = SharedAcquisitionMetadataLookup(
            self.case.store,
            resolve_identity=self.case.resolve_identity,
            resolve_tenant_member=self.case.resolve_tenant_member,
        )
        self.plan_calls = []
        def server_owned_local_plan(metadata):
            self.plan_calls.append(metadata)
            # The plan is chosen independently of the n8n receipt or form:
            # one fictional LOCAL tenant, one tested source/cls/due policy.
            return GovernedAcquisitionWorkPlan(
                TENANT, ORG, INTAKE, 1, INTAKE, "web", "service_request",
                self.due_text,
            )
        self.handoff = SharedAcquisitionWorkHandoff(
            self.reader, self.case.writer,
            resolve_governed_plan=server_owned_local_plan,
        )

    def assert_one_work_event(self):
        for table in (
            "avuhz_work_items", "avuhz_idempotency_records",
            "avuhz_lifecycle_events", "avuhz_outbox_deliveries"
        ):
            self.assertEqual(len(self.case.table(table)), 1, table)

    def test_complete_shared_acquisition_to_due_replay_and_handoff(self):
        # Client/event tenant and user claims cannot supply authority:
        # the independent reader applies the actual scoped PG RLS.
        with self.assertRaises(GovernedAcquisitionHandoffDenied):
            self.handoff.open("outside", INTAKE)
        with self.assertRaises(GovernedAcquisitionHandoffDenied):
            self.handoff.open("sender", OTHER_INTAKE)
        self.assertEqual(len(self.plan_calls), 0)
        self.assertEqual(self.case.table("avuhz_work_items"), [])

        created = self.handoff.open("sender", INTAKE)
        replay = self.handoff.open("sender", INTAKE)
        self.assertEqual((created.accepted_version, created.replayed), (1, False))
        self.assertEqual((replay.accepted_version, replay.replayed), (1, True))
        self.assertEqual(len(self.plan_calls), 2)
        self.assert_one_work_event()
        row = self.case.table("avuhz_work_items")[0]
        self.assertEqual(str(row["tenant_id"]), TENANT)
        self.assertEqual(str(row["work_item_id"]), INTAKE)
        self.assertEqual(row["owner_reference"], "worker.sender")
        self.assertEqual(row["state"], "OPEN")
        self.assertEqual(
            row["next_action_due_at"].strftime("%Y-%m-%dT%H:%M:%SZ"),
            self.due_text,
        )

        review = SharedDueWorkReadCandidate(
            self.case.store,
            resolve_identity=self.case.resolve_identity,
            resolve_tenant_member=self.case.resolve_tenant_member,
        )
        policy = FollowupReviewPolicy(escalation_after_minutes=15)
        before = review.review_owned_due(
            "sender", policy=policy, now=self.due-timedelta(minutes=1))
        due = review.review_owned_due(
            "sender", policy=policy, now=self.due+timedelta(minutes=5))
        escalation = review.review_owned_due(
            "sender", policy=policy, now=self.due+timedelta(minutes=21))
        other = review.review_owned_due(
            "outside", policy=policy, now=self.due+timedelta(minutes=21))
        self.assertEqual(before, ())
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0].kind, "FOLLOWUP_DUE")
        self.assertEqual(len(escalation), 1)
        self.assertEqual(
            escalation[0].kind, "FOLLOWUP_ESCALATION_REVIEW_REQUIRED"
        )
        self.assertEqual(other, ())

        # Work handoff uses original shared writer; never n8n identity.
        self.case.writer.execute(
            "sender", WorkIntakeCommand(
                "OFFER_HANDOFF", INTAKE, "qa-shared-offer-001",
                expected_record_version=1, recipient="worker.receiver",
            )
        )
        self.case.writer.execute(
            "receiver", WorkIntakeCommand(
                "ACCEPT_HANDOFF", INTAKE, "qa-shared-accept-001",
                expected_record_version=2,
            )
        )
        self.case.writer.execute(
            "receiver", WorkIntakeCommand(
                "RESOLVE", INTAKE, "qa-shared-resolve-001",
                expected_record_version=3,
            )
        )
        item = self.case.table("avuhz_work_items")[0]
        self.assertEqual((item["state"], item["record_version"]), ("RESOLVED", 4))
        self.assertEqual(item["owner_reference"], "worker.receiver")
        self.assertEqual(len(self.case.table("avuhz_lifecycle_events")), 4)
        self.assertEqual(len(self.case.table("avuhz_outbox_deliveries")), 4)
        with self.assertRaises(GovernedAcquisitionHandoffDenied):
            self.handoff.open("sender", INTAKE)
        self.assertEqual(len(self.case.table("avuhz_lifecycle_events")), 4)

    def test_stale_admission_denies_without_writer_side_effect(self):
        with self.case.owner() as con:
            con.execute(
                "UPDATE public.avuhz_acquisition_intake_requests "
                "SET record_version=2 WHERE intake_id=%s", (INTAKE,),
            )
        # The independently read version and the governed local plan
        # must match; no stale intake may become a new Work Item.
        with self.assertRaises(GovernedAcquisitionHandoffDenied):
            self.handoff.open("sender", INTAKE)
        self.assertEqual(self.case.table("avuhz_work_items"), [])
        self.assertEqual(self.case.table("avuhz_lifecycle_events"), [])
        self.assertEqual(self.case.table("avuhz_idempotency_records"), [])

    def test_privilege_drift_denies_before_any_work_write(self):
        with self.case.owner() as con:
            con.execute(
                "GRANT UPDATE(intake_state) ON "
                "public.avuhz_acquisition_intake_requests "
                "TO avuhz_acquisition_service_dev"
            )
        with self.assertRaises(GovernedAcquisitionHandoffDenied):
            self.handoff.open("sender", INTAKE)
        self.assertEqual(self.case.table("avuhz_work_items"), [])
        self.assertEqual(self.case.table("avuhz_lifecycle_events"), [])


if __name__ == "__main__":
    unittest.main()
