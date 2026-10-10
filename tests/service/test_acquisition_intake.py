"""Website intake validator tests: no provider connections, no real PII."""
from __future__ import annotations

import dataclasses
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.acquisition_intake import (
    ValidatedAcquisitionIntake,
    validate_acquisition_intake,
)


def fictional_request():
    return {
        "external_request_id": "a4730000-0000-4000-8000-000000000021",
        "source_system": "website.generic",
        "route_reference": "diagnostic.focused",
        "business_name": "Fictional Test Company",
        "contact_name": "Example Person",
        "contact_email": "  SAMPLE@EXAMPLE.INVALID  ",
        "contact_phone": "+1 (555) 010-2000",
        "preferred_contact_method": "PHONE",
        "contact_requested": True,
        "diagnostic_summary": "Recurring process delays affect customers.",
    }


class AcquisitionIntakeValidationTests(unittest.TestCase):
    def test_valid_content_normalizes_without_creating_tenant_authority(self):
        value = validate_acquisition_intake(fictional_request())
        self.assertIsInstance(value, ValidatedAcquisitionIntake)
        self.assertEqual(value.source_system, "website.generic")
        self.assertEqual(value.route_reference, "diagnostic.focused")
        self.assertEqual(value.contact_email, "sample@example.invalid")
        self.assertEqual(value.contact_requested, True)
        self.assertNotIn("tenant_id", dataclasses.fields(value)[0].name)
        self.assertFalse(hasattr(value, "tenant_id"))
        self.assertFalse(hasattr(value, "organization_id"))
        self.assertFalse(hasattr(value, "intake_state"))
        self.assertFalse(hasattr(value, "created_at"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            value.contact_email = "changed@example.invalid"

    def test_optional_phone_requires_email_preference(self):
        payload = fictional_request()
        payload.pop("contact_phone")
        payload["preferred_contact_method"] = "EMAIL"
        self.assertIsNone(validate_acquisition_intake(payload).contact_phone)
        payload["preferred_contact_method"] = "PHONE"
        self._denied(payload)

    def _denied(self, candidate):
        with self.assertRaises(ValueError) as caught:
            validate_acquisition_intake(candidate)
        self.assertEqual(str(caught.exception), "invalid_acquisition_intake")

    def test_rejects_all_client_supplied_authority_and_database_state(self):
        for forbidden in (
            "tenant_id", "organization_id", "intake_id", "intake_state",
            "consent_recorded_at", "received_at", "verified_owner",
            "registration_authorized", "implementation_authorized",
            "authority", "record_version", "idempotency_confirmed",
        ):
            with self.subTest(forbidden=forbidden):
                data = fictional_request()
                data[forbidden] = "any"
                self._denied(data)

    def test_required_fields_and_extra_data_fail_closed(self):
        for key in fictional_request():
            if key == "contact_phone":
                continue
            with self.subTest(missing=key):
                data = fictional_request()
                del data[key]
                self._denied(data)
        for invalid in (None, {}, [], "", True, [fictional_request()]):
            with self.subTest(value_type=type(invalid).__name__):
                self._denied(invalid)

    def test_consent_must_be_exact_explicit_true(self):
        for invalid in (False, None, 1, 0, "true", "yes", [], {}):
            with self.subTest(consent=repr(invalid)):
                data = fictional_request()
                data["contact_requested"] = invalid
                self._denied(data)

    def test_rejects_untrusted_id_route_and_source(self):
        for field, bad in (
            ("external_request_id", "not-uuid"),
            ("external_request_id", "A4730000-0000-4000-8000-000000000021"),
            ("external_request_id", "  a4730000-0000-4000-8000-000000000021"),
            ("source_system", "SEKINFRA_WEBSITE"),
            ("source_system", "web/site"),
            ("source_system", "x"),
            ("route_reference", "CLIENT_APPROVED"),
            ("route_reference", ".injection"),
            ("route_reference", "a" * 129),
            ("route_reference", "route\ninjected"),
        ):
            with self.subTest(field=field, bad=bad):
                payload = fictional_request()
                payload[field] = bad
                self._denied(payload)

    def test_contact_length_invalid_email_phone_and_controls_are_rejected(self):
        for field, bad in (
            ("business_name", "x"),
            ("business_name", "x" * 161),
            ("business_name", "Example\nInjected"),
            ("contact_name", "x"),
            ("contact_name", "x" * 121),
            ("contact_name", "Name\x00Injected"),
            ("contact_email", "not-an-email"),
            ("contact_email", "sample@invalid"),
            ("contact_email", "x" * 255),
            ("contact_phone", "123"),
            ("contact_phone", "+1-555-010-0000x9999"),
            ("contact_phone", "1" * 31),
            ("preferred_contact_method", "SMS"),
            ("diagnostic_summary", ""),
            ("diagnostic_summary", "x" * 501),
            ("diagnostic_summary", "Danger\nrepro"),
        ):
            with self.subTest(field=field):
                payload = fictional_request()
                payload[field] = bad
                self._denied(payload)

    def test_diagnostic_does_not_accept_credential_or_authenticated_url(self):
        for phrase in (
            "Bearer opaque-would-be-secret",
            "password:sample-not-real",
            "access_token=sample-not-real",
            "https://sample:invalid@example.invalid/private",
        ):
            with self.subTest(phrase_type=phrase.split(":")[0]):
                payload = fictional_request()
                payload["diagnostic_summary"] = phrase
                self._denied(payload)

    def test_repr_and_error_messages_never_expose_pii(self):
        payload = fictional_request()
        result = validate_acquisition_intake(payload)
        visible = repr(result)
        for sensitive in (
            "Fictional Test Company", "Example Person", "sample@example.invalid",
            "+1 (555) 010-2000", "Recurring process delays",
        ):
            self.assertNotIn(sensitive, visible)
        invalid = fictional_request()
        invalid["contact_email"] = "person@invalid"
        with self.assertRaises(ValueError) as error:
            validate_acquisition_intake(invalid)
        self.assertEqual(str(error.exception), "invalid_acquisition_intake")
        self.assertNotIn("person@invalid", str(error.exception))


if __name__ == "__main__":
    unittest.main()
