"""Static certification for a REVIEW-ONLY DEVELOPMENT DATA writer SET grant.

No Supabase provider call, DDL, credential, workflow or signing material.
The grant remains separately unauthorised for remote execution.
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/integration/development_handoff_runner_role_candidate.py"
ARTIFACT = ROOT / (
    "supabase/provider-artifacts/development-data/current/"
    "development_data_handoff_claim_runner_writer_set_grant_v1.sql"
)
MARKER = "-- RUNNER_WRITER_SET_API_STATEMENTS_BEGIN\n"


class DevelopmentDataRunnerWriterSetGrantArtifactTests(unittest.TestCase):
    def source_and_artifact(self) -> tuple[str, str, str]:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        assignments = [
            node for node in tree.body if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "GRANT_WRITER_SET_CANDIDATE_SQL"
        ]
        self.assertEqual(len(assignments), 1)
        source = ast.literal_eval(assignments[0].value).strip()
        full = ARTIFACT.read_text(encoding="utf-8")
        self.assertEqual(full.count(MARKER), 1)
        body = full.split(MARKER, 1)[1].strip()
        return source, body, full

    def test_artifact_identical_to_certified_grant_body(self) -> None:
        source, body, _ = self.source_and_artifact()
        self.assertTrue(source.startswith("BEGIN;"))
        self.assertTrue(source.endswith("COMMIT;"))
        self.assertEqual(body, source[len("BEGIN;"):-len("COMMIT;")].strip())

    def test_only_membership_not_login_or_credentials(self) -> None:
        _, sql, full = self.source_and_artifact()
        self.assertFalse(sql.startswith("BEGIN;"))
        self.assertFalse(sql.endswith("COMMIT;"))
        self.assertEqual(
            sql.count(
                "GRANT avuhz_handoff_claim_writer TO avuhz_handoff_claim_runner_dev"
            ), 1,
        )
        self.assertIn("WITH ADMIN FALSE, INHERIT FALSE, SET TRUE", sql)
        self.assertIn("HANDOFF_RUNNER_MEMBERSHIP_PREEXISTING_STOP", sql)
        self.assertIn("HANDOFF_RUNNER_SET_MEMBERSHIP_UNVERIFIED", sql)
        self.assertIn("relrowsecurity AND relforcerowsecurity", sql)
        self.assertNotRegex(sql, r"(?im)^\s*CREATE\s+(ROLE|USER|TABLE)")
        self.assertNotRegex(sql, r"(?im)^\s*ALTER\s+(ROLE|USER|TABLE)")
        self.assertNotRegex(sql, r"(?im)^\s*REVOKE\s+")
        self.assertNotRegex(sql, r"(?im)^\s*GRANT\s+(USAGE|INSERT|SELECT)")
        self.assertIn("DEVELOPMENT DATA gnuqaefotwgkwurjpyik", full)
        self.assertIn("DEVELOPMENT AUTH pwlhruwutoitnieactol", full)
        self.assertIn("DO NOT APPLY THIS GRANT", full)
        self.assertIn("caller-settable tenant GUC", full)
        self.assertNotIn("PASSWORD NULL", sql)
        self.assertNotIn("CONNECTION LIMIT", sql)

    def test_not_in_automatic_migration_chain_or_runtime(self) -> None:
        _, _, full = self.source_and_artifact()
        self.assertIn("REVIEW ONLY", full)
        self.assertIn("Supabase apply_migration", full)
        self.assertIn("/provider-artifacts/development-data/current/", ARTIFACT.as_posix())
        self.assertFalse(
            any(
                p.is_file() and "handoff_claim_runner_writer_set_grant" in p.name
                for p in (ROOT / "supabase/migrations").glob("*.sql")
            )
        )


if __name__ == "__main__":
    unittest.main()
