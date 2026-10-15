"""Synthetic proof: LOCAL n8n diagnostic never writes or leaks names/PII."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/local_n8n_activity_snapshot.py"


def db_fixture(path: Path, valid: bool = True) -> None:
    with sqlite3.connect(path) as db:
        db.executescript("""
CREATE TABLE workflow_entity (
  id varchar(36), name varchar(128), active boolean,
  nodes TEXT, connections TEXT, settings TEXT
);
CREATE TABLE execution_entity (
  id INTEGER, workflowId varchar(36), status varchar, data TEXT
);
""")
        db.execute(
            "INSERT INTO workflow_entity VALUES (?,?,?,?,?,?)",
            ("private-workflow-id", "Avuhz System #001 Revenue Intake — INACTIVE Child Candidate v1",
             0, "SECRET_PII_IN_NODES", "SECRET_PII_IN_CONNECTIONS", "SECRET_PII_IN_SETTINGS"),
        )
        db.execute(
            "INSERT INTO workflow_entity VALUES (?,?,?,?,?,?)",
            ("private-marketing-id", "Sensitive Customer Name and email@example.invalid",
             1, "PRIVATE_NODES", "PRIVATE_CONNECTIONS", "PRIVATE_SETTINGS"),
        )
        db.execute(
            "INSERT INTO execution_entity VALUES (?,?,?,?)",
            (1, "private-workflow-id", "success", "CUSTOMER_PHONE_5551234567"),
        )
        db.execute(
            "INSERT INTO execution_entity VALUES (?,?,?,?)",
            (2, "private-workflow-id", "error", "SHOULD_NOT_APPEAR"),
        )
        db.execute(
            "INSERT INTO execution_entity VALUES (?,?,?,?)",
            (3, "private-marketing-id", "leak@example.invalid", "ALSO_HIDDEN"),
        )
        db.commit()


def invoke(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--database", str(path)],
        capture_output=True, text=True, timeout=5,
    )


def digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


class LocalN8nActivitySnapshotTests(unittest.TestCase):
    def test_bounded_aggregate_no_pii_no_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "database.sqlite"
            db_fixture(path)
            before = digest(path)
            run = invoke(path)
            self.assertEqual(run.returncode, 0, run.stdout)
            self.assertEqual(run.stderr, "")
            self.assertEqual(before, digest(path))
            d = json.loads(run.stdout)
            self.assertEqual(d["source"], "LOCAL_N8N_OWNER_MACHINE")
            self.assertFalse(d["connection_to_command_center"])
            self.assertTrue(d["read_only"])
            self.assertEqual(d["workflows"], {"stored": 2, "active": 1, "inactive": 1})
            self.assertEqual(d["executions"]["total"], 3)
            self.assertEqual(d["executions"]["statuses"]["success"], 1)
            self.assertEqual(d["executions"]["statuses"]["error"], 1)
            self.assertEqual(d["executions"]["other"], 1)
            self.assertEqual(d["system_001"]["matching_candidate_workflows"], 1)
            self.assertEqual(d["system_001"]["active_candidates"], 0)
            self.assertFalse(d["system_001"]["runtime_certified"])
            for sensitive in (
                "private-workflow-id", "email@example.invalid", "SECRET_PII_IN_NODES",
                "CUSTOMER_PHONE", "SHOULD_NOT_APPEAR", str(path), "leak@example.invalid",
                "Sensitive Customer Name",
            ):
                self.assertNotIn(sensitive, run.stdout)

    def test_absent_database_fails_closed_without_creating_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "does-not-exist.sqlite"
            run = invoke(path)
            self.assertEqual(run.returncode, 2)
            self.assertFalse(path.exists())
            self.assertEqual(json.loads(run.stdout), {
                "source": "LOCAL_N8N_OWNER_MACHINE", "state": "unavailable"})

    def test_symlink_database_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "real.sqlite"
            alias = Path(directory) / "database-link.sqlite"
            db_fixture(db)
            alias.symlink_to(db)
            run = invoke(alias)
            self.assertEqual(run.returncode, 2)
            self.assertNotIn(str(db), run.stdout)
            self.assertNotIn(str(alias), run.stdout)
            self.assertEqual(json.loads(run.stdout)["state"], "unavailable")

    def test_schema_drift_fails_closed_without_exception_leaks(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "empty.sqlite"
            sqlite3.connect(db).close()
            run = invoke(db)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(json.loads(run.stdout)["state"], "unavailable")
            self.assertEqual(run.stderr, "")

    def test_empty_database_reports_zero_and_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "empty.sqlite"
            with sqlite3.connect(db) as c:
                c.execute("CREATE TABLE workflow_entity (id varchar(36),name varchar(128),active boolean)")
                c.execute("CREATE TABLE execution_entity (id INTEGER,status varchar)")
            before = digest(db)
            run = invoke(db)
            self.assertEqual(run.returncode, 0)
            self.assertEqual(before, digest(db))
            obj = json.loads(run.stdout)
            self.assertEqual(obj["workflows"]["stored"], 0)
            self.assertEqual(obj["executions"]["total"], 0)
            self.assertEqual(obj["system_001"]["matching_candidate_workflows"], 0)


if __name__ == "__main__":
    unittest.main()
