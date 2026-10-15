#!/usr/bin/env python3
"""Single-purpose, fail-closed LOCAL/TEST System #001 due-work certification.

Only runs a known test in an isolated disposable PostgreSQL 17 container.
Requires an explicit localhost DSN and a synthetic strong-identity resolver.
Does not fetch provider credentials, contact AUTH/DATA, deploy, or invoke n8n.
"""
from __future__ import annotations

import json
import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
PROOF = (
    "tests.integration.test_shared_work_intake_postgres_candidate."
    "SharedDurableWorkIntakePostgresTests."
    "test_synthetic_authenticated_open_deadline_due_review_with_handoff"
)


def main() -> int:
    # Never allow implicit hosted connectivity, a silently skipped proof, or
    # environmental fallback to credentials sourced from AVUHZ_POSTGRES_DSN.
    label = os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER", "")
    raw_dsn = os.environ.get("AVUHZ_WORK_ITEM_TEST_LOCAL_DSN", "")
    if not re.fullmatch(r"avuhz-system001-due-journey-local-[a-zA-Z0-9-]{4,30}", label):
        print("LOCAL_TEST_BOUNDARY_DENIED: expected named disposable container", file=sys.stderr)
        return 2
    if not raw_dsn or "://" in raw_dsn:
        print("LOCAL_TEST_BOUNDARY_DENIED: explicit localhost DSN required", file=sys.stderr)
        return 2
    try:
        from psycopg.conninfo import conninfo_to_dict
        params = conninfo_to_dict(raw_dsn)
    except (ImportError, ValueError):
        print("LOCAL_TEST_BOUNDARY_DENIED: pinned psycopg and safe DSN required", file=sys.stderr)
        return 2
    if (
        params.get("host") != "127.0.0.1"
        or params.get("user") != "postgres"
        or params.get("dbname") != "avuhz_system001_durable_writer_test"
        or "password" in params
        or not str(params.get("port", "")).isdigit()
        or params.get("port") != "65447"
        or any(p in params for p in ("sslcert", "sslkey", "service", "hostaddr"))
    ):
        print("LOCAL_TEST_BOUNDARY_DENIED: hosted or elevated database target", file=sys.stderr)
        return 2

    suite = unittest.defaultTestLoader.loadTestsFromName(PROOF)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if (
        not result.wasSuccessful() or result.testsRun != 1
        or result.skipped or result.expectedFailures or result.unexpectedSuccesses
    ):
        print("LOCAL_SYSTEM001_DUE_JOURNEY_NOT_CERTIFIED", file=sys.stderr)
        return 1
    print(json.dumps({
        "verification": "LOCAL_SYSTEM001_DUE_JOURNEY",
        "status": "PASS",
        "tests_executed": result.testsRun,
        "identity": "SYNTHETIC_TRUSTED_CONTEXT_ONLY",
        "database": "DISPOSABLE_LOCAL_POSTGRES_17",
        "verified": [
            "denied_unauthenticated_open",
            "authorized_atomic_deadline_open",
            "idempotent_replay",
            "tenant_and_current_owner_isolation",
            "due_and_escalation_review",
            "handoff_and_membership_revocation",
            "no_message_delivery_or_hosted_provider_side_effects",
        ],
        "hosted_auth_certified": False,
        "hosted_workflow_activated": False,
    }, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
