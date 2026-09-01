"""Static invariants for the canonical provider-neutral migration lineage."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATION_ROOT = ROOT / "supabase/migrations"
INITIAL_MIGRATION_NAME = "20260831120000_rebaseline_provider_neutral_avuhz.sql"
EXPECTED_TABLES = {
    "avuhz_acquisition_handoffs", "avuhz_engagements", "avuhz_implementation_handoffs",
    "avuhz_human_approvals", "avuhz_idempotency_records", "avuhz_lifecycle_events",
    "avuhz_outbox_deliveries", "avuhz_implementation_briefs",
    "avuhz_implementation_authorizations", "avuhz_codex_build_packages",
    "avuhz_build_execution_results", "avuhz_qa_results", "avuhz_client_acceptances",
    "avuhz_deployment_authorizations", "avuhz_deployment_executions",
    "avuhz_deployment_verifications",
}
FORBIDDEN = (
    "sekinfra", "oia_", "oia.", "diagnostic_", "assessment_", "finding_",
    "ongoing_", "agreement_", "payment_", "conversion_", "offboarding_",
)


class ProviderNeutralMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = sorted(MIGRATION_ROOT.glob("*.sql"))
        cls.initial_path = MIGRATION_ROOT / INITIAL_MIGRATION_NAME
        cls.initial_sql = cls.initial_path.read_text() if cls.initial_path in cls.paths else ""
        cls.initial_lower = cls.initial_sql.lower()
        cls.sql = "\n".join(path.read_text() for path in cls.paths)
        cls.lower = cls.sql.lower()

    def test_canonical_initial_migration_starts_strict_ordered_lineage(self):
        self.assertTrue(self.paths)
        self.assertEqual(self.paths[0].name, INITIAL_MIGRATION_NAME)
        names = [path.name for path in self.paths]
        self.assertEqual(names, sorted(names))
        timestamps = []
        for path in self.paths:
            match = re.fullmatch(r"([0-9]{14})_[A-Za-z0-9][A-Za-z0-9_-]*\.sql", path.name)
            self.assertIsNotNone(match, path.name)
            timestamps.append(match.group(1))
            migration = path.read_text().strip().lower()
            self.assertEqual(len(re.findall(r"(?m)^begin;$", migration)), 1, path.name)
            self.assertTrue(migration.endswith("commit;"), path.name)
            self.assertIn("remote application is unauthorized by default", migration, path.name)
        self.assertEqual(len(timestamps), len(set(timestamps)))
        self.assertIn("candidate canonical initial migration", self.initial_lower)
        self.assertIn("separate owner authorization", self.initial_lower)

    def test_initial_migration_has_fail_closed_preflight_and_rollback_boundary(self):
        for phrase in (
            "avuhz_initial_preflight",
            "requires the public schema",
            "lacks required public schema privileges",
            "requires built-in gen_random_uuid support",
            "refuses unexpected pre-existing avuhz schema state",
            "pre-existing avuhz_command_service role violates the least-privilege contract",
            "lacks authority to create the command-service role",
            "successful initial-schema rollback is intentionally",
            "destructive schema/data rollback requires separate authority",
        ):
            self.assertIn(phrase, self.initial_lower)
        self.assertLess(
            self.initial_lower.index("avuhz_initial_preflight"),
            self.initial_lower.index("create table"),
        )
        self.assertNotIn("create extension", self.initial_lower)
        self.assertIn("service_role.rolconfig is not null", self.initial_lower)
        self.assertIn("pg_auth_members", self.initial_lower)

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
        self.assertIn("'anon','authenticated','service_role'", self.lower)
        self.assertIn("revoke all on function", self.lower)
        self.assertIn("current_setting('avuhz.tenant_id',true)", self.lower)
        self.assertNotRegex(
            self.lower,
            r"grant\s+(?:all|select|insert|update|delete|execute).*\b(?:anon|authenticated|service_role)\b",
        )
        for attribute in (
            "nologin", "nosuperuser", "nobypassrls", "nocreatedb", "nocreaterole",
            "noinherit", "noreplication",
        ):
            self.assertIn(attribute, self.lower)

    def test_exact_handoff_and_phase5d_bindings(self):
        for field in (
            "implementation_handoff_id", "handoff_version", "handoff_digest",
            "implementation_brief_digest", "implementation_authority_digest",
            "package_digest", "execution_digest", "qa_digest", "client_acceptance_digest",
            "deployment_authority_digest", "deployment_execution_digest",
            "verification_digest",
        ):
            self.assertIn(field, self.lower)
        self.assertIn("immutable avuhz history cannot be rewritten", self.lower)
        self.assertIn("invalid idempotency transition", self.lower)


if __name__ == "__main__":
    unittest.main()
