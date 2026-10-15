"""Read-only LOCAL/TEST System #001 n8n execution-boundary evidence.

This is NOT workflow activation, provider authority, service credential setup,
tenant ownership certification, or proof of n8n execution.
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

from avuhz_worker.local_n8n_receipt_dev_runner import inspect_private_local_n8n


class LocalN8nPreflightDenied(RuntimeError):
    pass


def examine_installed_workflow(connection: sqlite3.Connection, source: dict, qa: dict) -> dict:
    """Check the existing installed v2 child without modifying a database."""
    try:
        if (
            source.get("active") is not False
            or len(source["nodes"]) != 5
            or len(source["connections"]) != 4
            or qa["fixture_type"] != "LOCAL_TEST_ONLY_FICTIONAL_CLIENT"
            or qa["fixture_name"] != "Avuhz QA Tenant 001"
            or qa["owner_is_real_or_verified"] is not False
            or qa["hosted_data_insert_authorized"] is not False
            or qa["production_allowed"] is not False
            or not qa["request"]["contact_email"].endswith(".invalid")
            or "sekinfra" in json.dumps(qa).lower()
        ):
            raise ValueError
        installed = connection.execute(
            "SELECT id,active,nodes,connections,settings FROM workflow_entity WHERE name=?",
            (source["name"],),
        ).fetchall()
        if len(installed) != 1:
            raise ValueError
        workflow_id, active, nodes_json, edges_json, _settings_json = installed[0]
        if type(active) not in (int, bool) or bool(active):
            raise ValueError
        nodes = json.loads(nodes_json)
        if not isinstance(nodes, list) or len(nodes) != 5:
            raise ValueError
        src_nodes = source["nodes"]
        # Compare execution-bearing nodes, credentials and parameters by exact
        # source ID/name/type, not DB-generated metadata or UI positions.
        if any(
            (node["id"], node["name"], node["type"], node["parameters"])
            != (original["id"], original["name"], original["type"], original["parameters"])
            for node, original in zip(nodes, src_nodes)
        ):
            raise ValueError
        if json.loads(edges_json) != source["connections"]:
            raise ValueError
        if any("credentials" in node for node in nodes):
            raise ValueError
        if nodes[2]["parameters"]["url"] != (
            "http://127.0.0.1:1/v1/avuhz/local-n8n-receipts"
        ):
            raise ValueError
        if nodes[0]["parameters"].get("inputSource") != "passthrough":
            raise ValueError
        assigned = connection.execute(
            "SELECT COUNT(*) FROM shared_workflow WHERE workflowId=?",
            (workflow_id,),
        ).fetchone()[0]
        if assigned != 1:
            raise ValueError
        total = connection.execute("SELECT COUNT(*) FROM workflow_entity").fetchone()[0]
        active_total = connection.execute(
            "SELECT COUNT(*) FROM workflow_entity WHERE active=1"
        ).fetchone()[0]
        executions = connection.execute("SELECT COUNT(*) FROM execution_entity").fetchone()[0]
        if total < 1 or active_total != 0 or executions != 0:
            raise ValueError
        return {
            "installed_v2_count": 1,
            "installed_node_count": 5,
            "all_workflows_inactive": True,
            "existing_execution_rows": 0,
            "qa_fixture_is_fictional": True,
            "receipt_endpoint_configured": False,
            "credential_bound": False,
            "shared_receiver_bound": False,
            "owner_lookup_connected": False,
            "real_n8n_execution_certified": False,
        }
    except (KeyError, TypeError, ValueError, IndexError, sqlite3.Error, json.JSONDecodeError):
        raise LocalN8nPreflightDenied("local_system001_n8n_preflight_denied") from None


def preflight(
    *,
    root: Path,
    docker_output=subprocess.check_output,
    inspect_network=inspect_private_local_n8n,
) -> dict:
    """Exact n8n container and read-only SQLite; no provider/API interaction."""
    try:
        inspect_network()  # verify 127.0.0.1:5678 and private Docker bridge
        mount = docker_output(
            ["docker", "inspect", "-f",
             "{{range .Mounts}}{{if eq .Destination \"/home/node/.n8n\"}}{{.Source}}{{end}}{{end}}",
             "n8n"],
            text=True, timeout=8, stderr=subprocess.DEVNULL,
        ).strip()
        path = Path(mount)
        if not path.is_absolute() or not path.is_dir() or path.is_symlink():
            raise ValueError
        database = path / "database.sqlite"
        if not database.is_file() or database.is_symlink():
            raise ValueError
        source = json.loads((root / "contracts/templates/n8n/avuhz-system-001-revenue-receipt-gated-inactive-v2.json").read_text())
        qa = json.loads((root / "tests/fixtures/system001_qa_tenant_local_v1.json").read_text())
        # SQLite URI read-only; never attempt WAL checkpoint, PRAGMA mutation,
        # credential inspection or outbox/workflow execution.
        with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as db:
            return examine_installed_workflow(db, source, qa)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, sqlite3.Error, json.JSONDecodeError, LocalN8nPreflightDenied):
        raise LocalN8nPreflightDenied("local_system001_n8n_preflight_denied") from None
