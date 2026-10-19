"""Client-neutral LOCAL V1 acceptance evidence.

The opt-in PostgreSQL cases prove one causal journey from authorized fictional
acquisition through the canonical Work Item transaction and its committed
``work_intake.opened`` event to a durable local n8n receipt plus deterministic
communications and usage effects. No Work Item-to-Engagement transition exists.

Normal discovery may skip the three PostgreSQL cases accurately. A release
certification invocation must set ``AVUHZ_REQUIRE_UNIFIED_LOCAL_ACCEPTANCE=1``;
that opt-in fails instead of producing a false green when the disposable PG17
fixture or explicit PostgreSQL run flag is absent. No provider or live service
is contacted.
"""
from __future__ import annotations

import copy
import os
import unittest
from datetime import datetime, timezone

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.in_memory import MemoryStore
from avuhz_runtime.postgres import PostgresUnitOfWork
from avuhz_worker.outbox import (
    DeliveryRejected,
    MemoryOutboxUnitOfWork,
    OutboxWorker,
    WorkerSettings,
)
from avuhz_worker.shared_communications_local import (
    DeterministicLocalCommunicationsFake,
)
from avuhz_worker.shared_engagement_delivery_local import (
    SharedLifecycleDeliveryLocalFanout,
)
from avuhz_worker.shared_usage_billing_local import (
    DeterministicLocalUsageBillingFake,
)
from tests.integration import test_shared_governed_work_local_proof as governed_work
from tests.service import test_shared_client_onboarding_local_proof as onboarding


TENANT = "a3000000-0000-4000-8000-000000000002"
OTHER_TENANT = "a3000000-0000-4000-8000-000000000099"
WORK_ITEM = "a3000000-0000-4000-8000-000000000021"
EVENT_ID = "a3000000-0000-4000-8000-000000000051"
CORRELATION_ID = "a3000000-0000-4000-8000-000000000052"
NOW = datetime(2030, 1, 15, 15, 0, tzinfo=timezone.utc)
PG_AVAILABLE = bool(
    governed_work.acquisition.fixture.DRIVER
    and governed_work.acquisition.fixture.DSN
    and governed_work.acquisition.fixture.CONTAINER
)
PG_RUN_REQUESTED = os.environ.get("AVUHZ_RUN_UNIFIED_LOCAL_ACCEPTANCE_PG") == "1"
CERTIFICATION_REQUIRED = (
    os.environ.get("AVUHZ_REQUIRE_UNIFIED_LOCAL_ACCEPTANCE") == "1"
)
PG_CERTIFICATION = PG_AVAILABLE and PG_RUN_REQUESTED
PG_SKIP = (
    "FULL CERTIFICATION NOT RUN: set AVUHZ_RUN_UNIFIED_LOCAL_ACCEPTANCE_PG=1 "
    "with the approved disposable PG17 fixture"
)


def _worker_context(tenant: str = TENANT) -> TrustedExecutionContext:
    return TrustedExecutionContext(
        True, "service.outbox-worker-local", "INTERNAL_SERVICE", tenant, None,
        frozenset({"event:publish_internal"}), frozenset(), "TEST",
        "avuhz-command-api", "STRONG", False, "2030-01-15T15:00:00Z",
        "2099-01-01T00:00:00Z", human_authority_role=None,
    )


def _work_event(*, tenant: str = TENANT) -> dict:
    """Exact shape emitted by SharedWorkIntakePostgresCandidate for OPEN."""
    return {
        "event_id": EVENT_ID,
        "event_type": "work_intake.opened",
        "event_schema_version": 1,
        "tenant_id": tenant,
        "authoritative_subject_reference": {
            "reference_type": "WORK_ITEM",
            "reference_id": WORK_ITEM,
        },
        "authoritative_subject_version": 1,
        "occurred_at": "2030-01-15T15:00:00Z",
        "producer_reference": "command.service-01",
        "correlation_id": CORRELATION_ID,
        "idempotency_key": "work-item:" + EVENT_ID,
        "visibility": "TENANT_OPERATIONAL",
        "sanitized_metadata": {"work_item_id": WORK_ITEM, "state": "OPEN"},
    }


def _fakes(*, tenant: str = TENANT, communication_outcomes=()):
    trusted = _worker_context(tenant)
    communications = DeterministicLocalCommunicationsFake(
        tenant_id=tenant,
        environment="TEST",
        trusted_context=trusted,
        outcomes=communication_outcomes,
    )
    usage = DeterministicLocalUsageBillingFake(
        tenant_id=tenant, environment="TEST", trusted_context=trusted,
    )
    return trusted, communications, usage


class _DurableReceiptAndLocalEffects:
    """One sink composition behind one canonical worker claim."""

    def __init__(self, durable_receipt, local_effects) -> None:
        self._durable_receipt = durable_receipt
        self._local_effects = local_effects
        self.delivered_events = []

    def deliver(self, idempotency_key: str, event: dict, delivered_at: str):
        # Terminal local rejection is known before the durable receipt or either
        # local effect. Retryable failures remain safe because all three sinks
        # deduplicate the same canonical outbox delivery identity.
        self._local_effects.validate(idempotency_key, event, delivered_at)
        receipt = self._durable_receipt.deliver(
            idempotency_key, event, delivered_at,
        )
        effects = self._local_effects.deliver(
            idempotency_key, event, delivered_at,
        )
        self.delivered_events.append(copy.deepcopy(event))
        return receipt, effects


class LocalV1OnboardingAcceptance(unittest.TestCase):
    def setUp(self):
        self.case = onboarding.SharedClientOnboardingLocalProofTests()
        self.case.setUp()

    def test_01_verified_owner_moves_pending_to_active_without_live_authority(self):
        bearer = self.case.token()
        pending = self.case.register(bearer)
        self.assertEqual(pending.state, "PENDING_VERIFICATION")
        proof = self.case.activate(pending, bearer)
        self.assertEqual(proof.state, "ACTIVE")
        self.assertEqual(proof.evidence_class, "LOCAL_TEST_ONLY")
        self.assertFalse(proof.live_identity_authorized)
        self.assertFalse(hasattr(proof, "trusted_context"))
        self.assertEqual(len(self.case.store.rows), 1)
        row = self.case.store.rows[pending.tenant_id]
        self.assertEqual(
            (row["lifecycle_state"], row["membership_state"]), ("ACTIVE", "ACTIVE")
        )

    def test_02_forged_stale_revoked_and_caller_authority_fail_closed(self):
        self.case.owner_signature_valid = False
        with self.assertRaises(PermissionError):
            self.case.register(self.case.token())
        self.assertEqual(self.case.store.rows, {})

        self.case.setUp()
        with self.assertRaises(PermissionError):
            self.case.register(None)
        self.case.setUp()
        with self.assertRaises(PermissionError):
            self.case.register(self.case.token(totp_age=301))
        self.case.session_active = False
        with self.assertRaises(PermissionError):
            self.case.register(self.case.token())
        self.assertEqual(self.case.store.rows, {})

        self.case.setUp()
        bearer = self.case.token()
        pending = self.case.register(bearer)
        forged = onboarding.PendingTenantRegistration(
            pending.tenant_id, "b6010000-0000-4000-8000-000000000099",
        )
        with self.assertRaises(PermissionError):
            self.case.activate(forged, bearer)
        self.assertEqual(
            self.case.store.rows[pending.tenant_id]["lifecycle_state"],
            "PENDING_VERIFICATION",
        )
        with self.assertRaises(TypeError):
            self.case.harness.activate_and_bind(
                pending=pending,
                untrusted_bearer=bearer,
                business_reference=onboarding.BUSINESS,
                identity_resolver=object(),
            )

        self.case.setUp()
        bearer = self.case.token()
        pending = self.case.register(bearer)
        self.case.activate(pending, bearer)
        before_revocation = copy.deepcopy(self.case.store.rows)
        self.case.store.membership_boundary_ok = False
        with self.assertRaises(PermissionError):
            self.case.activate(pending, bearer)
        self.assertEqual(self.case.store.rows, before_revocation)


class LocalV1CertificationEntrypoint(unittest.TestCase):
    def test_postgres_certification_opt_in_cannot_false_green(self):
        if CERTIFICATION_REQUIRED and not PG_CERTIFICATION:
            self.fail(
                "unified LOCAL V1 certification requires the explicit PostgreSQL "
                "run flag and approved disposable PG17 fixture"
            )


@unittest.skipUnless(PG_CERTIFICATION, PG_SKIP)
class LocalV1AuthoritativePostgresAcceptance(unittest.TestCase):
    """Required real Work Item composition; never replaced by a mock."""

    def _new_case(self):
        case = governed_work.SharedGovernedWorkRealLocalPostgresTests(
            "test_one_atomic_work_and_durable_post_commit_receipt_with_exact_replay"
        )
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case

    def _run_existing_proof(self, method_name: str) -> None:
        case = governed_work.SharedGovernedWorkRealLocalPostgresTests(method_name)
        try:
            case.setUp()
            getattr(case, method_name)()
        finally:
            case.doCleanups()

    def test_03_same_committed_work_event_reaches_receipt_and_both_local_effects(self):
        case = self._new_case()
        created = case.journey.handoff.open(
            "sender", governed_work.acquisition.INTAKE,
        )
        self.assertFalse(created.replayed)
        self.assertIsNotNone(created.event_id)
        for table in (
            "avuhz_work_items", "avuhz_idempotency_records",
            "avuhz_lifecycle_events", "avuhz_outbox_deliveries",
        ):
            self.assertEqual(len(case.journey.case.table(table)), 1, table)

        tenant = governed_work.acquisition.TENANT
        trusted, communications, usage = _fakes(tenant=tenant)
        effects = SharedLifecycleDeliveryLocalFanout(communications, usage)
        sink = _DurableReceiptAndLocalEffects(case.sink, effects)
        worker = OutboxWorker(
            case.journey.case.store,
            PostgresUnitOfWork,
            sink,
            trusted,
            WorkerSettings(tenant_id=tenant),
            clock=lambda: NOW,
        )
        self.assertEqual(worker.run_once()["published"], 1)
        self.assertEqual(case.receiver.count(), 1)
        self.assertEqual((len(communications.receipts), len(usage.records)), (1, 1))

        delivered = sink.delivered_events[0]
        self.assertEqual(delivered["event_id"], created.event_id)
        self.assertEqual(delivered["event_type"], "work_intake.opened")
        self.assertEqual(
            delivered["authoritative_subject_reference"],
            {
                "reference_type": "WORK_ITEM",
                "reference_id": governed_work.acquisition.INTAKE,
            },
        )
        self.assertEqual(
            delivered["sanitized_metadata"],
            {"work_item_id": governed_work.acquisition.INTAKE, "state": "OPEN"},
        )
        self.assertEqual(communications.receipts[0].event_id, created.event_id)
        self.assertEqual(usage.records[0].event_id, created.event_id)
        self.assertEqual(usage.records[0].metric, "work_item_opened")
        self.assertNotIn("email", str(delivered).lower())

        before = {
            table: case.journey.case.table(table)
            for table in (
                "avuhz_work_items", "avuhz_idempotency_records",
                "avuhz_lifecycle_events", "avuhz_outbox_deliveries",
            )
        }
        replay = case.journey.handoff.open(
            "sender", governed_work.acquisition.INTAKE,
        )
        self.assertTrue(replay.replayed)
        self.assertIsNone(replay.event_id)
        self.assertEqual(worker.run_once()["claimed"], 0)
        for table, rows in before.items():
            self.assertEqual(case.journey.case.table(table), rows, table)
        self.assertEqual(case.receiver.count(), 1)
        self.assertEqual((len(communications.receipts), len(usage.records)), (1, 1))

    def test_04_denials_and_injected_failure_leave_no_authoritative_effect(self):
        self._run_existing_proof(
            "test_all_authority_denials_and_stale_intake_have_zero_side_effects"
        )
        self._run_existing_proof(
            "test_transaction_failure_rolls_back_and_prevents_receipt"
        )

    def test_05_forged_delivery_cannot_mutate_authoritative_tables(self):
        self._run_existing_proof(
            "test_forged_event_or_receipt_cannot_mutate_authoritative_tables"
        )


class LocalV1DeliveryAcceptance(unittest.TestCase):
    def test_06_canonical_work_event_fans_out_exactly_once(self):
        source = _work_event()
        store = MemoryStore(
            events=[copy.deepcopy(source)],
            outbox=[{"event_id": source["event_id"], "status": "PENDING"}],
        )
        trusted, communications, usage = _fakes()
        worker = OutboxWorker(
            store,
            MemoryOutboxUnitOfWork,
            SharedLifecycleDeliveryLocalFanout(communications, usage),
            trusted,
            WorkerSettings(tenant_id=TENANT),
            clock=lambda: NOW,
        )
        self.assertEqual(worker.run_once()["published"], 1)
        self.assertEqual(worker.run_once()["claimed"], 0)
        self.assertEqual((len(communications.receipts), len(usage.records)), (1, 1))
        self.assertEqual(usage.records[0].metric, "work_item_opened")
        self.assertEqual(set(source["sanitized_metadata"]), {"work_item_id", "state"})

    def test_07_first_sink_transient_retry_and_cross_tenant_are_safe(self):
        source = _work_event()
        store = MemoryStore(
            events=[copy.deepcopy(source)],
            outbox=[{"event_id": source["event_id"], "status": "PENDING"}],
        )
        trusted, communications, usage = _fakes(
            communication_outcomes=("DELIVERY_UNAVAILABLE", "PUBLISHED")
        )
        fanout = SharedLifecycleDeliveryLocalFanout(communications, usage)
        worker = OutboxWorker(
            store,
            MemoryOutboxUnitOfWork,
            fanout,
            trusted,
            WorkerSettings(tenant_id=TENANT, lease_seconds=5, base_backoff_seconds=1),
            clock=lambda: NOW,
        )
        self.assertEqual(worker.run_once()["retry_scheduled"], 1)
        self.assertEqual((len(communications.receipts), len(usage.records)), (0, 0))
        self.assertEqual(store.outbox[0]["last_safe_error_code"], "DELIVERY_UNAVAILABLE")
        store.outbox[0]["next_attempt_at"] = "2030-01-15T14:59:59Z"
        self.assertEqual(worker.run_once()["published"], 1)
        self.assertEqual((len(communications.receipts), len(usage.records)), (1, 1))

        foreign = _work_event(tenant=OTHER_TENANT)
        with self.assertRaises(DeliveryRejected):
            fanout.deliver(
                "outbox-delivery:" + foreign["event_id"],
                foreign,
                "2030-01-15T15:00:00Z",
            )
        self.assertEqual((len(communications.receipts), len(usage.records)), (1, 1))

    def test_08_second_sink_terminal_preflight_prevents_first_effect_and_pii(self):
        source = _work_event()
        key = "outbox-delivery:" + source["event_id"]
        _trusted, communications, usage = _fakes()
        usage.deliver(key, source, "2030-01-15T15:00:00Z")
        fanout = SharedLifecycleDeliveryLocalFanout(communications, usage)
        changed = copy.deepcopy(source)
        changed["authoritative_subject_version"] = 2
        with self.assertRaisesRegex(DeliveryRejected, "^USAGE_IDENTITY_COLLISION$"):
            fanout.deliver(key, changed, "2030-01-15T15:00:00Z")
        self.assertEqual(communications.receipts, ())
        self.assertEqual(len(usage.records), 1)

        pii = copy.deepcopy(source)
        pii["event_id"] = "a3000000-0000-4000-8000-000000000061"
        pii["sanitized_metadata"]["contact_email"] = "person@example.invalid"
        with self.assertRaises(DeliveryRejected):
            fanout.deliver(
                "outbox-delivery:" + pii["event_id"],
                pii,
                "2030-01-15T15:00:00Z",
            )
        self.assertEqual(communications.receipts, ())
        self.assertEqual(len(usage.records), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
