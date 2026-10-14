"""LOCAL/TEST proof of shared, tenant-aware, non-authoritative follow-up rules."""
from __future__ import annotations

import dataclasses
import unittest
from datetime import datetime, timezone, timedelta

from avuhz_service.shared_revenue_followup_review import (
    FollowupObservation, FollowupReviewDenied, FollowupReviewPolicy,
    review_followup_due,
)
from avuhz_service.shared_work_intake_candidate import WorkItem

TENANT = "e7000000-0000-4000-8000-000000000001"
OTHER = "e7000000-0000-4000-8000-000000000002"
ITEM = "e7000000-0000-4000-8000-000000000005"
NOW = datetime(2030, 1, 15, 16, 0, 0, tzinfo=timezone.utc)
POLICY = FollowupReviewPolicy(escalation_after_minutes=30)


def observation(*, due="2030-01-15T15:45:00Z", **changes):
    value = WorkItem(
        tenant_id=TENANT, work_item_id=ITEM, owner_reference="worker.owner",
        state="OPEN", record_version=2, source="web",
        classification="service_request",
    )
    return FollowupObservation(dataclasses.replace(value, **changes), due)


def run(*items, tenant=TENANT, clock=NOW, policy=POLICY):
    return review_followup_due(tuple(items), trusted_tenant_id=tenant, now=clock, policy=policy)


class RevenueFollowupReviewTests(unittest.TestCase):
    def test_active_due_returns_one_bounded_review_only(self):
        result = run(observation())
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].kind, "FOLLOWUP_DUE")
        self.assertEqual(result[0].work_item_id, ITEM)
        self.assertEqual(result[0].record_version, 2)
        self.assertEqual(result[0].owner_reference, "worker.owner")
        self.assertFalse(hasattr(result[0], "tenant_id"))
        self.assertFalse(hasattr(result[0], "phone"))
        self.assertFalse(hasattr(result[0], "email"))

    def test_due_boundary_exact_and_policy_bounds(self):
        due = run(observation(due="2030-01-15T16:00:00Z"))
        self.assertEqual(due[0].kind, "FOLLOWUP_DUE")
        self.assertEqual(FollowupReviewPolicy(15).escalation_after_minutes, 15)
        self.assertEqual(FollowupReviewPolicy(10080).escalation_after_minutes, 10080)

    def test_exact_100_trusted_items_allowed(self):
        batch = tuple(observation(work_item_id=f"e7000000-0000-4000-8000-{i:012d}")
                      for i in range(1, 101))
        self.assertEqual(len(run(*batch)), 100)

    def test_malformed_work_item_fields_never_raise_unexpected_type_error(self):
        for bad in (
            observation(work_item_id="not_uuid"),
            observation(state=[]),
            observation(source={"payload": "PII"}),
            observation(classification=[]),
        ):
            with self.subTest(bad=type(bad.item.state)), self.assertRaises(FollowupReviewDenied):
                run(bad)

    def test_overdue_escalation_is_only_an_operator_review(self):
        a = run(observation(due="2030-01-15T15:30:00Z"))
        self.assertEqual(a[0].kind, "FOLLOWUP_ESCALATION_REVIEW_REQUIRED")
        b = run(observation(due="2030-01-15T15:31:00Z"))
        self.assertEqual(b[0].kind, "FOLLOWUP_DUE")

    def test_future_and_resolved_are_silent(self):
        self.assertEqual(run(observation(due="2030-01-15T16:01:00Z")), ())
        self.assertEqual(run(observation(state="RESOLVED")), ())

    def test_blocked_returns_distinct_review_not_message(self):
        result = run(observation(state="BLOCKED", due="2030-01-15T15:45:00Z"))
        self.assertEqual(result[0].kind, "BLOCKED_OWNER_REVIEW_REQUIRED")

    def test_mixed_batch_is_deterministic_and_suppresses_future(self):
        a = observation(due="2030-01-15T15:00:00Z")
        b = observation(work_item_id="e7000000-0000-4000-8000-000000000006",
                        due="2030-01-15T16:10:00Z")
        c = observation(work_item_id="e7000000-0000-4000-8000-000000000007",
                        due="2030-01-15T15:55:00Z")
        before = (a, b, c)
        result = run(*before)
        self.assertEqual([x.work_item_id for x in result], [ITEM, c.item.work_item_id])
        self.assertEqual(result, run(*before))

    def test_cross_tenant_and_duplicate_work_items_abort_entire_batch(self):
        valid = observation()
        forged = observation(work_item_id="e7000000-0000-4000-8000-000000000099", tenant_id=OTHER)
        for batch in ((valid, forged), (valid, valid)):
            with self.subTest(batch=batch), self.assertRaisesRegex(FollowupReviewDenied, "invalid follow-up snapshot"):
                run(*batch)

    def test_invalid_owner_or_state_and_fake_type_denied(self):
        cases = [
            observation(owner_reference="contact@example.invalid"),
            observation(owner_reference=""),
            observation(record_version=True),
            observation(state="UNKNOWN"),
            observation(source="from-prospect text"),
            observation(classification="anything"),
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(FollowupReviewDenied):
                run(case)
        with self.assertRaises(FollowupReviewDenied):
            run({"tenant_id": TENANT})

    def test_malformed_times_rejected_before_any_output(self):
        for due in (
            "2030-02-30T15:00:00Z", "2030-01-15T15:45:00-05:00",
            "2030-01-15T15:45:00.0000000Z", "2030-01-15T15:45:00Z"+"x"*20000,
            "2030-01-15T25:00:00Z",
        ):
            with self.subTest(due=due[:28]), self.assertRaisesRegex(FollowupReviewDenied, "invalid follow-up snapshot"):
                run(observation(due=due))

    def test_requires_utc_trusted_clock_and_valid_nonempty_batch(self):
        for clock in (NOW.replace(tzinfo=None), NOW.replace(tzinfo=timezone(timedelta(hours=-5))), "2030"):
            with self.subTest(clock=clock), self.assertRaises(FollowupReviewDenied):
                run(observation(), clock=clock)
        for batch in ((), [observation()], (observation(),)*101):
            with self.subTest(length=len(batch)), self.assertRaises(FollowupReviewDenied):
                review_followup_due(batch, trusted_tenant_id=TENANT, now=NOW, policy=POLICY)
        with self.assertRaises(FollowupReviewDenied):
            run(observation(), tenant=OTHER)

    def test_policy_must_be_strict_server_owned_value(self):
        for value in (0, 10081, "30", True, None):
            with self.subTest(value=value), self.assertRaises(FollowupReviewDenied):
                FollowupReviewPolicy(escalation_after_minutes=value)


if __name__ == "__main__":
    unittest.main()
