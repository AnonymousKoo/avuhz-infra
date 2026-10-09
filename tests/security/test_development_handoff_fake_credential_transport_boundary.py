"""Repository-only fake credential transport gates for the first DEVELOPMENT handoff.

All callbacks are injected, provider-free, and use intentionally fictional test
values. This does NOT attest an actual GitHub protected environment, issue a
hosted database login, validate TLS, or authorize a live handoff. Local SQLite
claims in this test are not cross-run authorization consumption.
"""
from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/security"), str(ROOT / "tests/service")]

from test_development_handoff_trusted_one_shot_executor import TrustedOneShotExecutorTests
from test_development_source_bound_handoff_lifecycle import ADMIN

from avuhz_engineering.development_handoff_owner_trust_anchor import ENV_FINGERPRINT
from avuhz_engineering.development_handoff_trusted_github_invocation import (
    verify_trusted_github_invocation,
)
from avuhz_engineering.development_handoff_trusted_one_shot_executor import (
    SignedStageProof, TrustedOneShotStop,
)


class FakeCredentialTransportBoundaryTests(unittest.TestCase):
    def setUp(self):
        # Reuse the existing disposable source/approval/signature fixture. Its
        # test-only public-key override never edits a GitHub environment.
        self.fixture = TrustedOneShotExecutorTests(
            methodName="test_four_exact_signed_stage_claims_precede_single_send_and_logout"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_offline_invocation_receipt_does_not_authorize_credentials(self):
        fixture = self.fixture
        result = verify_trusted_github_invocation(
            fixture.env, fixture.event,
            observed_checkout_sha=fixture.source.canonical_main_sha,
            observed_remote_main_sha=fixture.source.canonical_main_sha,
            observed_git_origin="https://github.com/AnonymousKoo/avuhz-infra",
        )
        self.assertTrue(result.invocation_source_verified)
        self.assertFalse(result.owner_approval_verified)
        self.assertFalse(result.authorization_set_verified)
        self.assertFalse(result.distributed_authorization_consumed)
        self.assertFalse(result.credential_resolution_authorized)
        self.assertFalse(result.live_command_authorized)
        self.assertFalse(result.provider_contact_attempted)

    def test_fake_suppliers_resolve_only_after_all_four_offline_claims(self):
        fixture = self.fixture
        events = []

        def fake_admin_supplier():
            # Important ordering requirement: never resolve even a fictional
            # credential before all stage approvals are atomically claimed.
            with sqlite3.connect(fixture.f.ledger) as db:
                claimed = db.execute(
                    "select count(*) from avuhz_offline_handoff_stage_claim"
                ).fetchone()[0]
            self.assertEqual(claimed, 4)
            events.append(("fake_supplier_checked",))
            return ADMIN

        with patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")), \
             patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
            outcome, credential, session = fixture.run_once(
                events, admin_secret_supplier=fake_admin_supplier
            )

        self.assertEqual(outcome.claimed_stage_count, 4)
        self.assertEqual(events[0], ("fake_supplier_checked",))
        self.assertEqual([e[0] for e in events].count("send"), 1)
        self.assertEqual([e[0] for e in events].count("logout"), 1)
        self.assertFalse(outcome.retry_authorized)
        self.assertFalse(outcome.data_readback_verified)
        self.assertFalse(outcome.temporary_credential_retirement_verified)
        self.assertFalse(outcome.owner_key_enrollment_verified_by_runner)
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)
        self.assertNotIn(ADMIN, repr(outcome))
        self.assertNotIn(ADMIN, repr(events))

    def test_source_and_protected_job_claim_drift_never_resolves_secret(self):
        fixture = self.fixture
        for field, value in (
            ("GITHUB_ACTOR_ID", "9999"),
            ("GITHUB_REF", "refs/heads/untrusted"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_WORKFLOW_REF", "AnonymousKoo/other/.github/workflows/other.yml@refs/heads/main"),
            ("AVUHZ_ENVIRONMENT", "production"),
        ):
            with self.subTest(field=field):
                calls = []
                bad = {**fixture.env, field: value}

                def never_resolve():
                    calls.append("bad")
                    raise AssertionError("fake credential accessed before trust gate")

                with self.assertRaisesRegex(
                    TrustedOneShotStop, "HANDOFF_TRUSTED_GITHUB_INVOCATION_DENIED"
                ):
                    fixture.run_once(
                        [], github_environment=bad,
                        admin_secret_supplier=never_resolve,
                    )
                self.assertEqual(calls, [])
                self.assertEqual(fixture.ledger_rows(), [])

        calls = []

        def never_resolve():
            calls.append("bad")
            raise AssertionError("fake credential accessed before trust gate")

        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_TRUSTED_GITHUB_INVOCATION_DENIED"
        ):
            fixture.run_once(
                [], observed_remote_main_sha="f" * 40,
                admin_secret_supplier=never_resolve,
            )
        self.assertEqual(calls, [])
        self.assertEqual(fixture.ledger_rows(), [])

    def test_bad_owner_pin_and_forged_stage_never_resolve_secret(self):
        fixture = self.fixture
        calls = []

        def never_resolve():
            calls.append("bad")
            raise AssertionError("fake credential accessed before signed trust gate")

        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_OWNER_SIGNING_PIN_UNVERIFIED"
        ):
            fixture.run_once(
                [], github_environment={**fixture.env, ENV_FINGERPRINT: "sha256:" + "0" * 64},
                admin_secret_supplier=never_resolve,
            )
        proof = fixture.signed_proofs["DATA_COMMAND"]
        forged = dict(fixture.signed_proofs)
        forged["DATA_COMMAND"] = SignedStageProof(claims=proof.claims, signature=b"0" * 64)
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_STAGE_OWNER_SIGNATURE_UNVERIFIED"
        ):
            fixture.run_once(
                [], signed_proofs=forged,
                admin_secret_supplier=never_resolve,
            )
        self.assertEqual(calls, [])
        self.assertEqual(fixture.ledger_rows(), [])

    def test_fake_secret_supplier_exception_is_sanitized_and_claim_is_terminal(self):
        events = []
        canary = "fictional_sensitive_material_must_never_leave_supplier"
        resolutions = []

        def failing_supplier():
            resolutions.append("one_attempt")
            raise RuntimeError(canary)

        with patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")):
            outcome, credential, session = self.fixture.run_once(
                events, admin_secret_supplier=failing_supplier
            )
        self.assertEqual(resolutions, ["one_attempt"])
        self.assertEqual(len(self.fixture.ledger_rows()), 4)
        self.assertEqual(outcome.lifecycle.classification, "SYNTHETIC_HANDOFF_UNVERIFIED")
        self.assertEqual(outcome.lifecycle.safe_error_code, "HANDOFF_LIFECYCLE_UNVERIFIED")
        self.assertFalse(outcome.retry_authorized)
        self.assertNotIn("send", [e[0] for e in events])
        self.assertNotIn(canary, repr(outcome))
        self.assertNotIn(canary, repr(events))
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_LIFECYCLE_ALREADY_CLAIMED"
        ):
            self.fixture.run_once([], admin_secret_supplier=failing_supplier)
        self.assertEqual(resolutions, ["one_attempt"])
        # Supplier stopped before generation; no credential or session from
        # the fixture was ever handed to a provider callback.
        self.assertNotIn("generate", [e[0] for e in events])
        self.assertNotIn("verify", [e[0] for e in events])


if __name__ == "__main__":
    unittest.main()
