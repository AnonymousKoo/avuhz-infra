"""Static parity and least-privilege boundaries for DATA runner role artifact.

No hosted SQL, no roles, no credentials, no workflow dispatch.
Actual SQL fixture is certified separately on disposable PostgreSQL 17.
"""
from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/integration/development_handoff_runner_role_candidate.py"
ARTIFACT = ROOT / (
    "supabase/provider-artifacts/development-data/current/"
    "development_data_handoff_claim_runner_role_create_v1.sql"
)
MARKER = "-- RUNNER_CREATE_API_STATEMENTS_BEGIN\n"


class DevelopmentDataHandoffRunnerRoleCreateArtifactTests(unittest.TestCase):
    def sql_parts(self) -> tuple[str, str, str]:
        module = ast.parse(SOURCE.read_text(encoding="utf-8"))
        assignments = [
            statement for statement in module.body
            if isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and statement.targets[0].id == "CREATE_RUNNER_CANDIDATE_SQL"
        ]
        self.assertEqual(len(assignments), 1)
        wrapped_sql = ast.literal_eval(assignments[0].value).strip()
        full = ARTIFACT.read_text(encoding="utf-8")
        self.assertEqual(full.count(MARKER), 1)
        body = full.split(MARKER, 1)[1].strip()
        return wrapped_sql, body, full

    def test_api_sql_is_exact_disposable_certified_create_body(self) -> None:
        wrapped, body, _ = self.sql_parts()
        self.assertTrue(wrapped.startswith("BEGIN;"))
        self.assertTrue(wrapped.endswith("COMMIT;"))
        expected = wrapped[len("BEGIN;"):-len("COMMIT;")].strip()
        self.assertEqual(body, expected)

    def test_role_only_no_grant_password_or_credential_binding(self) -> None:
        _, body, full = self.sql_parts()
        self.assertFalse(body.startswith("BEGIN;"))
        self.assertFalse(body.endswith("COMMIT;"))
        self.assertNotRegex(body, r"(?im)^\s*GRANT\s")
        self.assertNotRegex(body, r"(?im)^\s*ALTER\s+ROLE\s")
        self.assertIn("CREATE ROLE avuhz_handoff_claim_runner_dev", body)
        self.assertIn("LOGIN PASSWORD NULL CONNECTION LIMIT 1", body)
        self.assertIn("NOINHERIT NOSUPERUSER NOBYPASSRLS", body)
        self.assertIn("NOCREATEDB NOCREATEROLE NOREPLICATION", body)
        self.assertIn("HANDOFF_RUNNER_PREEXISTING_ROLE_STOP", body)
        self.assertIn("HANDOFF_RUNNER_MEMBERSHIP_UNTRUSTED", body)
        self.assertIn("HANDOFF_RUNNER_UNEXPECTED_DIRECT_ACL", body)
        self.assertIn("DEVELOPMENT DATA gnuqaefotwgkwurjpyik", full)
        self.assertIn("DEVELOPMENT AUTH pwlhruwutoitnieactol", full)
        self.assertIn("not executable provider authority", full)
        self.assertIn("does NOT guarantee all external auth methods", full)
        self.assertNotRegex(body, r"(?i)password\s+'[^']+'")

    def test_role_grant_candidate_remains_separate_and_nonautomatic(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("GRANT_WRITER_SET_CANDIDATE_SQL", source)
        _, body, _ = self.sql_parts()
        self.assertNotIn(
            "GRANT avuhz_handoff_claim_writer TO avuhz_handoff_claim_runner_dev",
            body,
        )
        self.assertIn("/provider-artifacts/development-data/current/", ARTIFACT.as_posix())
        self.assertFalse(
            any(
                path.is_file() and "handoff_claim_runner_role_create" in path.name
                for path in (ROOT / "supabase/migrations").glob("*.sql")
            )
        )


if __name__ == "__main__":
    unittest.main()
