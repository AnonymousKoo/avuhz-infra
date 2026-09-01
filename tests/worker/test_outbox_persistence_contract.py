"""Static local persistence and canonical schema checks for outbox delivery."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "contracts/schemas/v1/orchestration/outbox-delivery.schema.json"
MIGRATION = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
POSTGRES = ROOT / "src/avuhz_runtime/postgres.py"


class OutboxPersistenceContractTests(unittest.TestCase):
    def test_schema_is_valid_and_bounded(self):
        schema = json.loads(SCHEMA.read_text())
        Draft202012Validator.check_schema(schema)
        self.assertEqual(schema["properties"]["attempt_history"]["maxItems"], 32)
        self.assertEqual(schema["properties"]["status"]["enum"], ["PENDING", "PUBLISHING", "PUBLISHED", "FAILED_RETRYABLE", "FAILED_TERMINAL"])
        self.assertIn("lease_token", schema["properties"])
        self.assertNotIn("provider_payload", schema["properties"])

    def test_migration_has_transition_guard_rls_and_bounded_columns(self):
        sql = MIGRATION.read_text().lower()
        for phrase in (
            "lease_owner_reference text", "lease_token uuid", "lease_expires_at timestamptz",
            "jsonb_array_length(attempt_history)<=32", "invalid outbox delivery transition",
            "avuhz_guard_outbox_transition", "outbox attempt history cannot be rewritten",
            "grant update (destination_reference,status,attempt_count",
            "alter table public.avuhz_outbox_deliveries enable row level security",
            "current_setting('avuhz.tenant_id',true)",
        ):
            self.assertIn(phrase, sql)
        self.assertNotRegex(sql, r"grant\s+(?:all|insert|update|delete).*(?:anon|authenticated)")

    def test_postgres_claim_is_atomic_skip_locked_and_lease_guarded(self):
        source = POSTGRES.read_text().lower()
        self.assertIn("for update skip locked limit 1", source)
        self.assertIn("outbox delivery transition conflict", source)
        self.assertIn("lease_token", source)
        self.assertNotIn("requests.", source)
        self.assertNotIn("httpx.", source)


if __name__ == "__main__":
    unittest.main()
