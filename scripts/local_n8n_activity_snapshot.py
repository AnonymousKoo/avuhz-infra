#!/usr/bin/env python3
"""Read ONLY bounded, PII-free aggregates from an existing LOCAL n8n SQLite DB.

This is an owner-invoked LOCAL/TEST diagnostic, NOT a remote Command Center
connection, daemon, policy engine, workflow execution, or auth adapter.

Never print workflow names, execution data, customer records, database path,
provider response bodies, environment variables, credentials, tokens or SQL
errors. SQLite is opened mode=ro + query_only. Fail closed on any mismatch.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

EXPECTED_SOURCE = "LOCAL_N8N_OWNER_MACHINE"
KNOWN_EXECUTION_STATES = ("success", "error", "waiting", "running", "canceled", "crashed", "new")


def snapshot(database: Path) -> dict[str, object]:
    if not database.is_absolute() or database.is_symlink() or not database.is_file():
        raise ValueError("unapproved_input")
    # Path.as_uri() escapes spaces safely; sqlite URI flags guarantee no create/write.
    uri = database.as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=2) as db:
        db.execute("PRAGMA query_only=ON")
        required = {
            "workflow_entity": {"id", "name", "active"},
            "execution_entity": {"id", "status"},
        }
        for table, expected in required.items():
            columns = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
            if not expected.issubset(columns):
                raise ValueError("unsupported_schema")
        workflows, active = db.execute(
            "SELECT count(*), coalesce(sum(CASE WHEN active = 1 THEN 1 ELSE 0 END),0)"
            " FROM workflow_entity"
        ).fetchone()
        executions = db.execute("SELECT count(*) FROM execution_entity").fetchone()[0]
        # Name prefix is only a LOCAL candidate detector. Never use it to
        # authorize System #001 or infer the template has passed certification.
        system_matches, system_active = db.execute(
            "SELECT count(*), coalesce(sum(CASE WHEN active = 1 THEN 1 ELSE 0 END),0)"
            " FROM workflow_entity WHERE name LIKE ?",
            ("Avuhz System #001 Revenue Intake%",),
        ).fetchone()
        states = dict.fromkeys(KNOWN_EXECUTION_STATES, 0)
        other = 0
        for raw, count in db.execute(
            "SELECT status, count(*) FROM execution_entity GROUP BY status"
        ):
            if raw in states:
                states[raw] = count
            else:
                other += count
        return {
            "schema_version": 1,
            "source": EXPECTED_SOURCE,
            "connection_to_command_center": False,
            "read_only": True,
            "workflows": {
                "stored": workflows,
                "active": active,
                "inactive": workflows - active,
            },
            "executions": {
                "total": executions,
                "statuses": states,
                "other": other,
            },
            "system_001": {
                "matching_candidate_workflows": system_matches,
                "active_candidates": system_active,
                "runtime_certified": False,
            },
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only, aggregate LOCAL n8n inventory. No external uploads."
    )
    parser.add_argument("--database", required=True, type=Path,
                        help="Absolute path to existing LOCAL n8n SQLite DB; never logged.")
    args = parser.parse_args(argv)
    try:
        evidence = snapshot(args.database)
    except (ValueError, sqlite3.Error, OSError):
        # Only a static error code. No SQL, path, PII or exception text.
        print(json.dumps({"source": EXPECTED_SOURCE, "state": "unavailable"}))
        return 2
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
