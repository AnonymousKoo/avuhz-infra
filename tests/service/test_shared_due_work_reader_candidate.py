"""Fail-closed unit tests for read-only shared due Work Item projection."""
from datetime import datetime, timezone, timedelta
import unittest

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_service.shared_due_work_reader_candidate import (
    SharedDueWorkReadCandidate, SharedFollowupReadUnavailable,
)
from avuhz_service.shared_revenue_followup_review import FollowupReviewPolicy
from avuhz_service.shared_work_intake_candidate import WorkIntakeDenied

TENANT = "d4720000-0000-4000-8000-000000000001"
ITEM = "d4720000-0000-4000-8000-000000000002"
NOW = datetime(2030, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


def context(*, tenant=TENANT, actor="worker.owner", caps=None, auth=True):
    return TrustedExecutionContext(
        auth, actor, "HUMAN", tenant, None,
        frozenset({"work_intake:read"}) if caps is None else caps,
        frozenset(), "DEVELOPMENT", "avuhz-command-api", "STRONG", False,
        "2026-10-14T00:00:00Z", "2099-01-01T00:00:00Z",
    )


def row(**changed):
    val = {
        "tenant_id": TENANT, "work_item_id": ITEM,
        "owner_reference": "worker.owner", "state": "OPEN",
        "record_version": 1, "source": "web",
        "classification": "service_request", "pending_recipient_reference": None,
        "next_action_due_at": NOW-timedelta(minutes=20),
    }
    val.update(changed)
    return val


class FakeCursor:
    def __init__(self, row_value=None, rows=None):
        self.value, self.rows = row_value, rows

    def fetchone(self):
        return self.value

    def fetchall(self):
        return self.rows


class FakeConnection:
    autocommit = False

    def __init__(self, *, allowed=True, rows=None, error=False):
        self.allowed, self.rows, self.error = allowed, rows or [], error
        self.calls, self.rollbacks, self.closed = [], 0, False

    def execute(self, statement, args=()):
        self.calls.append((statement, args))
        if "set_config" in statement:
            return FakeCursor({"set_config": "ok"})
        if self.error:
            raise RuntimeError("provider payload must never escape")
        if " as bounded" in statement:
            return FakeCursor({"bounded": self.allowed})
        if "from public.avuhz_work_items" in statement:
            return FakeCursor(rows=self.rows)
        raise AssertionError("unexpected statement")

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


class FakeStore:
    def __init__(self, con):
        self.connection_factory = lambda: con


class SharedDueWorkReaderTests(unittest.TestCase):
    def setUp(self):
        self.con = FakeConnection(rows=[row()])
        self.identities = {"owner": context(), "other": context(actor="worker.other")}
        self.members = {TENANT: {"worker.owner"}}
        self.reader = SharedDueWorkReadCandidate(
            FakeStore(self.con), resolve_identity=lambda x: self.identities[x],
            resolve_tenant_member=lambda _con, tenant, actor: (
                actor if actor in self.members.get(tenant, ()) else None
            ),
        )
        self.policy = FollowupReviewPolicy(escalation_after_minutes=15)

    def test_current_owner_due_returns_review_only(self):
        result = self.reader.review_owned_due("owner", policy=self.policy, now=NOW)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].kind, "FOLLOWUP_ESCALATION_REVIEW_REQUIRED")
        self.assertEqual(result[0].work_item_id, ITEM)
        self.assertFalse(hasattr(result[0], "message_sent"))
        self.assertTrue(self.con.closed)
        self.assertEqual(self.con.rollbacks, 1)
        statements = [str(x[0]) for x in self.con.calls]
        self.assertTrue(any("tenant_id=%s and owner_reference=%s" in s for s in statements))
        self.assertTrue(any("1742b76d0dd8d99c26eafc15fe3c8f705a6fa58341b43a7c6fab669091df9e88" in s for s in statements))
        self.assertTrue(any("next_action_due_at <= %s" in s for s in statements))
        args = self.con.calls[-1][1]
        self.assertEqual(args, (TENANT, "worker.owner", NOW, 100))

    def test_bounded_empty_and_not_due(self):
        self.con.rows = []
        self.assertEqual(self.reader.review_owned_due("owner", policy=self.policy, now=NOW), ())

    def test_wrong_tenant_and_owner_readback_denied(self):
        for changed in ({"tenant_id": "d4720000-0000-4000-8000-000000000009"},
                        {"owner_reference": "worker.other"}):
            with self.subTest(changed=changed):
                self.con = FakeConnection(rows=[row(**changed)])
                self.reader._store = FakeStore(self.con)
                with self.assertRaises(SharedFollowupReadUnavailable):
                    self.reader.review_owned_due("owner", policy=self.policy, now=NOW)
                self.assertTrue(self.con.closed)
                self.assertEqual(self.con.rollbacks, 1)

    def test_nonmember_denied_before_read(self):
        with self.assertRaises(WorkIntakeDenied):
            self.reader.review_owned_due("other", policy=self.policy, now=NOW)
        self.assertTrue(self.con.closed)
        self.assertFalse(any("from public.avuhz_work_items" in s for s, _ in self.con.calls))

    def test_caller_missing_capability_denied(self):
        self.identities["owner"] = context(caps=frozenset())
        with self.assertRaises(WorkIntakeDenied):
            self.reader.review_owned_due("owner", policy=self.policy, now=NOW)
        self.assertEqual(self.con.calls, [])

    def test_role_and_column_preflight_fail_closed(self):
        self.con.allowed = False
        with self.assertRaises(SharedFollowupReadUnavailable):
            self.reader.review_owned_due("owner", policy=self.policy, now=NOW)
        self.assertTrue(self.con.closed)
        self.assertEqual(self.con.rollbacks, 1)

    def test_database_exception_never_echoed(self):
        self.con.error = True
        with self.assertRaisesRegex(SharedFollowupReadUnavailable, "^shared follow-up read unavailable$"):
            self.reader.review_owned_due("owner", policy=self.policy, now=NOW)
        self.assertTrue(self.con.closed)

    def test_clock_limit_and_policy_reject_untrusted_values(self):
        for values in (
            {"limit": 0}, {"limit": 101}, {"limit": True},
            {"now": NOW.replace(tzinfo=None)},
            {"now": NOW.replace(tzinfo=timezone(timedelta(hours=-4)))},
            {"policy": "user supplied"},
        ):
            with self.subTest(values=values), self.assertRaises(SharedFollowupReadUnavailable):
                self.reader.review_owned_due(
                    "owner", policy=values.get("policy", self.policy),
                    now=values.get("now", NOW), limit=values.get("limit", 100),
                )
        self.assertFalse(self.con.calls)

    def test_fractional_deadline_rejected_and_closed(self):
        self.con.rows = [row(next_action_due_at=NOW-timedelta(minutes=20, microseconds=1))]
        with self.assertRaises(SharedFollowupReadUnavailable):
            self.reader.review_owned_due("owner", policy=self.policy, now=NOW)
        self.assertTrue(self.con.closed)

    def test_no_data_writes_or_personal_payloads(self):
        self.reader.review_owned_due("owner", policy=self.policy, now=NOW, limit=7)
        sql = " ".join(query for query, _ in self.con.calls).lower()
        for word in ("insert into", "update public", "delete from", "email", "phone",
                     "service_role", "raw_payload"):
            # SQL includes a named service_role string only if guard explicitly does;
            # this reader never queries or uses its credential.
            self.assertNotIn(word, sql)


if __name__ == "__main__":
    unittest.main()
