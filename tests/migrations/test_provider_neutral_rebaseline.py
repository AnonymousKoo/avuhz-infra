"""Static invariants for the clean provider-neutral local migration baseline."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATION_ROOT = ROOT / "supabase/migrations"
EXPECTED_TABLES = {
    "avuhz_acquisition_handoffs", "avuhz_engagements", "avuhz_implementation_handoffs",
    "avuhz_human_approvals", "avuhz_idempotency_records", "avuhz_lifecycle_events",
    "avuhz_outbox_deliveries", "avuhz_implementation_briefs",
    "avuhz_implementation_authorizations", "avuhz_codex_build_packages",
    "avuhz_build_execution_results", "avuhz_qa_results", "avuhz_client_acceptances",
    "avuhz_deployment_authorizations",
}
FORBIDDEN = (
    "sekinfra", "oia_", "oia.", "diagnostic_", "assessment_", "finding_",
    "ongoing_", "agreement_", "payment_", "conversion_", "offboarding_",
)


class ProviderNeutralMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = sorted(MIGRATION_ROOT.glob("*.sql"))
        cls.sql = cls.paths[0].read_text() if len(cls.paths) == 1 else ""
        cls.lower = cls.sql.lower()

    def test_one_current_tree_baseline(self):
        self.assertEqual([path.name for path in self.paths], [
            "20260831120000_rebaseline_provider_neutral_avuhz.sql"
        ])
        self.assertIn("local/disposable current-tree rebaseline", self.lower)
        self.assertIn("never applied remotely", self.lower)

    def test_exact_provider_neutral_table_surface(self):
        tables = set(re.findall(r"create table public\.([a-z0-9_]+)", self.lower))
        self.assertEqual(tables, EXPECTED_TABLES)
        for term in FORBIDDEN:
            self.assertNotIn(term, self.lower)

    def test_current_repositories_have_migration_tables(self):
        source = "\n".join(path.read_text() for path in (ROOT / "src/avuhz_runtime").glob("postgres*.py"))
        repository_tables = set(re.findall(r"public\.(avuhz_[a-z0-9_]+)", source))
        repository_tables.update(re.findall(r'table\s*=\s*["\'](avuhz_[a-z0-9_]+)', source))
        self.assertLessEqual(repository_tables, EXPECTED_TABLES)

    def test_canonical_command_and_event_vocabularies_are_representable(self):
        envelope = json.loads((ROOT / "contracts/schemas/v1/commands/command-envelope.schema.json").read_text())
        events = json.loads((ROOT / "contracts/schemas/v1/orchestration/lifecycle-event.schema.json").read_text())
        for command in envelope["$defs"]["commandType"]["enum"]:
            self.assertIn("'" + command.lower() + "'", self.lower)
        for event in events["properties"]["event_type"]["enum"]:
            self.assertIn("'" + event.lower() + "'", self.lower)

    def test_rls_service_identity_and_security_negatives(self):
        for table in EXPECTED_TABLES:
            self.assertIn("alter table public." + table + " enable row level security", self.lower)
        self.assertIn("avuhz_command_service", self.lower)
        self.assertIn("revoke all on table", self.lower)
        self.assertIn("from public", self.lower)
        self.assertIn("'anon','authenticated'", self.lower)
        self.assertIn("current_setting('avuhz.tenant_id',true)", self.lower)
        self.assertNotRegex(self.lower, r"grant\s+(?:all|insert|update|delete).*\b(?:anon|authenticated)\b")

    def test_exact_handoff_and_phase5d_bindings(self):
        for field in (
            "implementation_handoff_id", "handoff_version", "handoff_digest",
            "implementation_brief_digest", "implementation_authority_digest",
            "package_digest", "execution_digest", "qa_digest", "client_acceptance_digest",
            "deployment_authority_digest",
        ):
            self.assertIn(field, self.lower)
        self.assertIn("immutable avuhz history cannot be rewritten", self.lower)
        self.assertIn("invalid idempotency transition", self.lower)


if __name__ == "__main__":
    unittest.main()
