"""LOCAL/TEST contract: untrusted booking preferences cannot reserve slots."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from dataclasses import asdict

from avuhz_service.shared_booking_candidate import (
    BookingPolicy, BookingPreferenceDenied, ValidatedBookingPreference,
    next_action_is_due, validate_booking_preference,
)

NOW = datetime(2030, 1, 15, 12, 0, tzinfo=timezone.utc)
POLICY = BookingPolicy(
    allowed_booking_types=frozenset({"consultation", "service_visit"}),
    min_notice_minutes=60,
    max_duration_minutes=180,
    max_horizon_days=90,
    max_followup_hours=24,
)
REQUEST = {
    "booking_type": "consultation",
    "start_at": "2030-01-16T14:00:00Z",
    "end_at": "2030-01-16T15:00:00Z",
    "next_action_due_at": "2030-01-15T16:00:00Z",
}


class BookingPreferenceTests(unittest.TestCase):
    def test_valid_preference_is_not_reservation_or_receipt(self):
        accepted = validate_booking_preference(dict(REQUEST), policy=POLICY, now=NOW)
        self.assertIs(type(accepted), ValidatedBookingPreference)
        self.assertEqual(accepted.booking_type, "consultation")
        self.assertEqual(set(asdict(accepted)), set(REQUEST))
        self.assertFalse(any("confirm" in key for key in asdict(accepted)))

    def test_untrusted_tenant_owner_contact_and_status_rejected(self):
        for forbidden in ("tenant_id", "organization_id", "owner_reference",
                          "work_item_id", "email", "phone", "notes", "confirmed",
                          "calendar_token", "role"):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(BookingPreferenceDenied):
                    validate_booking_preference({**REQUEST, forbidden: "fake"},
                                                policy=POLICY, now=NOW)

    def test_required_fields_only(self):
        for field in REQUEST:
            with self.subTest(field=field), self.assertRaises(BookingPreferenceDenied):
                untrusted = dict(REQUEST)
                del untrusted[field]
                validate_booking_preference(untrusted, policy=POLICY, now=NOW)
        for candidate in (None, "hello", [], True):
            with self.assertRaises(BookingPreferenceDenied):
                validate_booking_preference(candidate, policy=POLICY, now=NOW)

    def test_approved_booking_types_only(self):
        with self.assertRaises(BookingPreferenceDenied):
            validate_booking_preference({**REQUEST, "booking_type": "other"},
                                        policy=POLICY, now=NOW)

    def test_utc_z_precision_required(self):
        for timestamp in ("2030-01-16T14:00:00+00:00", "2030-01-16T14:00Z",
                          "2030-02-31T14:00:00Z", "2030-01-16 14:00:00Z"):
            with self.subTest(timestamp=timestamp), self.assertRaises(BookingPreferenceDenied):
                validate_booking_preference({**REQUEST, "start_at": timestamp},
                                            policy=POLICY, now=NOW)

    def test_bad_window_and_max_duration_denied(self):
        for start, end in (
            ("2030-01-16T15:00:00Z", "2030-01-16T14:00:00Z"),
            ("2030-01-16T14:00:00Z", "2030-01-16T19:00:00Z"),
            ("2030-06-16T14:00:00Z", "2030-06-16T15:00:00Z"),
            ("2029-01-16T14:00:00Z", "2029-01-16T15:00:00Z"),
        ):
            with self.subTest(start=start, end=end), self.assertRaises(BookingPreferenceDenied):
                validate_booking_preference({**REQUEST, "start_at": start, "end_at": end},
                                            policy=POLICY, now=NOW)

    def test_followup_is_required_strictly_before_start_with_bounded_sla(self):
        for deadline in ("2030-01-15T12:00:00Z", "2030-01-16T14:00:00Z",
                         "2030-01-17T12:00:00Z", "2030-01-15T11:59:59Z"):
            with self.subTest(deadline=deadline), self.assertRaises(BookingPreferenceDenied):
                validate_booking_preference({**REQUEST, "next_action_due_at": deadline},
                                            policy=POLICY, now=NOW)

    def test_safely_reports_only_deadline_predicate(self):
        preference = validate_booking_preference(dict(REQUEST), policy=POLICY, now=NOW)
        self.assertFalse(next_action_is_due(preference, now=NOW))
        self.assertTrue(next_action_is_due(
            preference, now=datetime(2030, 1, 15, 16, 0, tzinfo=timezone.utc)))

    def test_no_untrusted_policy_or_naive_clock(self):
        with self.assertRaises(BookingPreferenceDenied):
            validate_booking_preference(REQUEST, policy=asdict(POLICY), now=NOW)
        with self.assertRaises(BookingPreferenceDenied):
            validate_booking_preference(REQUEST, policy=POLICY, now=NOW.replace(tzinfo=None))

    def test_policy_rejects_fake_code_and_unbounded_sla(self):
        for kwargs in (
            {"allowed_booking_types": frozenset({"Name With Space"})},
            {"max_followup_hours": 10000},
            {"max_duration_minutes": 0},
            {"min_notice_minutes": True},
        ):
            values = {
                "allowed_booking_types": frozenset({"consultation"}),
                "min_notice_minutes": 60, "max_duration_minutes": 180,
                "max_horizon_days": 90, "max_followup_hours": 24,
            }
            values.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(BookingPreferenceDenied):
                BookingPolicy(**values)

    def test_no_network_or_calendar_confirmation_functions_exposed(self):
        from avuhz_service import shared_booking_candidate as domain
        for forbidden in ("confirm_appointment", "record_no_show",
                          "send_reminder", "book_slot", "issue_token"):
            self.assertFalse(hasattr(domain, forbidden))


if __name__ == "__main__":
    unittest.main()
