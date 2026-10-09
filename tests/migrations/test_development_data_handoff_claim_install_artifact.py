"""Prove the proposed DEVELOPMENT DATA SQL artifact matches the certified local candidate.

Static-only tests; no Supabase, migration, role or workflow mutation.
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / (
    "supabase/provider-artifacts/development-data/current/"
    "development_data_handoff_claim_ledger_install_v1.sql"
)
SOURCE = ROOT / (
    "tests/integration/development_handoff_claim_installation_candidate.py"
)
MARKER = "-- MIGRATION_API_STATEMENTS_BEGIN\n"


class DevelopmentHandoffClaimSqlArtifactTests(unittest.TestCase):
    def sql_parts(self) -> tuple[str, str]:
        source_tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        assignments = [
            node for node in source_tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "INSTALLATION_CANDIDATE_SQL"
        ]
        self.assertEqual(len(assignments), 1)
        tested_sql = ast.literal_eval(assignments[0].value).strip()
        artifact_text = ARTIFACT.read_text(encoding="utf-8")
        self.assertEqual(artifact_text.count(MARKER), 1)
        artifact_sql = artifact_text.split(MARKER, 1)[1].strip()
        return tested_sql, artifact_sql

    def test_artifact_byte_matches_disposable_postgres_certified_sql(self) -> None:
        tested_sql, artifact_sql = self.sql_parts()
        self.assertTrue(tested_sql.startswith("BEGIN;"))
        self.assertTrue(tested_sql.endswith("COMMIT;"))
        expected_api_sql = tested_sql[len("BEGIN;"):-len("COMMIT;")].strip()
        self.assertEqual(artifact_sql, expected_api_sql)

    def test_transactional_tenant_rls_and_replay_invariants(self) -> None:
        _, sql = self.sql_parts()
        self.assertFalse(sql.startswith("BEGIN;"))
        self.assertFalse(sql.endswith("COMMIT;"))
        self.assertNotIn("\nBEGIN;", sql)
        self.assertNotIn("\nCOMMIT;", sql)
        self.assertIn("FORCE ROW LEVEL SECURITY;", sql)
        self.assertIn("ENABLE ROW LEVEL SECURITY;", sql)
        self.assertIn("NOBYPASSRLS NOINHERIT", sql)
        self.assertIn("NOLOGIN", sql)
        self.assertIn("UNIQUE (approval_digest)", sql)
        self.assertIn("UNIQUE (tenant_id, authorization_set_digest, stage)", sql)
        self.assertIn("UNIQUE (tenant_id, command_digest, stage)", sql)
        self.assertIn("current_setting('avuhz.handoff_claim_tenant', TRUE)", sql)
        self.assertIn("HANDOFF_CLAIM_PREEXISTING_RESOURCE_STOP", sql)
        self.assertIn("avuhz_handoff_claim_writer", sql)
        self.assertIn("gnuqaefotwgkwurjpyik", sql)
        self.assertIn("pwlhruwutoitnieactol", sql)

    def test_artifact_remains_nonautomatic_provider_only(self) -> None:
        self.assertIn("provider-artifacts/development-data/current", ARTIFACT.as_posix())
        self.assertFalse(
            any(
                p.is_file() and "handoff_claim_ledger_install" in p.name
                for p in (ROOT / "supabase/migrations").glob("*.sql")
            )
        )
        text = ARTIFACT.read_text(encoding="utf-8")
        self.assertIn("Remote application requires fresh, exact owner authorization", text)
        self.assertIn("DEVELOPMENT AUTH", text)
        self.assertIn("Supabase apply_migration transaction", text)
        self.assertIn("Never submit as raw SQL", text)


if __name__ == "__main__":
    unittest.main()
