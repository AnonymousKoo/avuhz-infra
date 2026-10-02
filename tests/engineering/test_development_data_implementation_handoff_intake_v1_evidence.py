from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "contracts/plans/v1/development-data-implementation-handoff-intake-v1-success.evidence.json"
MIGRATION = ROOT / "supabase/migrations/20261002213000_enable_implementation_handoff_command_intake.sql"


class DevelopmentDataImplementationHandoffIntakeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(EVIDENCE.read_text())
        cls.migration = MIGRATION.read_text()

    def test_exact_environment_resource_and_outcome(self):
        self.assertEqual(self.evidence["environment"], "DEVELOPMENT")
        self.assertEqual(self.evidence["responsibility"], "DATA")
        self.assertEqual(self.evidence["project_reference"], "gnuqaefotwgkwurjpyik")
        self.assertEqual(self.evidence["outcome"], "SUCCEEDED_VERIFIED")
        self.assertEqual(
            self.evidence["resource_reference"],
            "supabase/migrations/20261002213000_enable_implementation_handoff_command_intake.sql",
        )
        self.assertEqual(
            self.evidence["provider_observation"]["applied_migration_name"],
            "enable_implementation_handoff_command_intake",
        )
        self.assertEqual(
            self.evidence["provider_observation"]["applied_migration_version"],
            "20261002215206",
        )

    def test_security_postconditions_are_sealed(self):
        observed = self.evidence["provider_observation"]
        verified = self.evidence["verification_observation"]
        security = self.evidence["security_state"]
        self.assertEqual(observed["avuhz_table_count"], 16)
        self.assertEqual(observed["rls_enabled_count"], 16)
        self.assertEqual(observed["migration_owned_table_count"], 16)
        self.assertEqual(observed["tenant_policy_count"], 16)
        self.assertEqual(observed["exposed_role_table_grant_count"], 0)
        self.assertEqual(observed["provider_admin_noset_edge_count"], 1)
        self.assertEqual(observed["explicit_postgres_set_edge_count"], 0)
        self.assertFalse(observed["postgres_can_set_migration_role"])
        self.assertEqual(observed["security_advisor_finding_count"], 0)
        self.assertTrue(verified["temporary_set_edge_restored"])
        self.assertTrue(verified["tenant_isolation_preserved"])
        self.assertTrue(verified["migration_owner_preserved"])
        self.assertTrue(verified["rls_preserved"])
        self.assertFalse(verified["exposed_grants_added"])
        self.assertFalse(security["persistent_role_membership_added"])
        self.assertFalse(security["auth_resource_touched"])
        self.assertFalse(security["render_resource_touched"])
        self.assertFalse(security["n8n_resource_touched"])
        self.assertFalse(security["production_resource_touched"])

    def test_failed_closed_attempt_and_single_committed_wrapper_are_recorded(self):
        verified = self.evidence["verification_observation"]
        self.assertEqual(verified["provider_mutation_attempts"], 2)
        self.assertTrue(verified["first_attempt_failed_closed"])
        self.assertFalse(verified["first_attempt_committed"])
        self.assertEqual(verified["first_attempt_error_code"], "42501")
        self.assertTrue(verified["atomic_owner_wrapper_attempted_once"])
        self.assertTrue(verified["atomic_owner_wrapper_committed"])

    def test_exact_migration_vocabulary_is_bound(self):
        observed = self.evidence["provider_observation"]
        self.assertTrue(observed["accept_implementation_handoff_command_vocab_present"])
        self.assertTrue(observed["implementation_handoff_idempotency_subject_vocab_present"])
        self.assertTrue(observed["implementation_handoff_event_vocab_present"])
        self.assertTrue(observed["implementation_handoff_event_subject_vocab_present"])
        for token in (
            "AcceptImplementationHandoff",
            "IMPLEMENTATION_HANDOFF",
            "implementation_handoff.accepted",
            "implementation_handoff.revoked",
        ):
            self.assertIn(token, self.migration)


if __name__ == "__main__":
    unittest.main()
