#!/usr/bin/env python3
"""Read-only, fail-closed Gate D LOCAL ingress preflight.

This command never provisions ingress, resolves public DNS, opens a TLS
connection, sends HTTP, reads credential ciphertext, executes n8n, or changes
host/provider state.  It reconciles safe installed n8n metadata and local host
facts.  A positive decision additionally requires independently established
TLS and exact-route evidence supplied to :func:`evaluate_preflight`; the CLI
does not manufacture that evidence from a hostname or listening socket.
"""
from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path
import sqlite3
import sys
from typing import Callable
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from avuhz_worker.local_n8n_receipt_dev_runner import (  # noqa: E402
    PrivateDockerBoundary,
    inspect_private_local_n8n,
)
from scripts import prepare_shared_n8n_receiver_v2_local as receiver  # noqa: E402
from scripts import (  # noqa: E402
    prepare_shared_n8n_receiver_v2_header_credential_local as inbound,
)
from scripts import (  # noqa: E402
    prepare_shared_n8n_v2_op_receipt_credential_local as receipt,
)


TARGET = "SYSTEM001_GATE_D_LOCAL_INGRESS_PREFLIGHT"
ENVIRONMENTS = frozenset({"LOCAL", "TEST"})
PROJECT_ID = "axT3GLERZRiPXxnj"
RECEIVER_ID = "0068feb4c96bdb5f"
INBOUND_CREDENTIAL_ID = "6ece28c3-f72d-4021-942d-8d0eb072b711"
RECEIPT_CREDENTIAL_ID = "154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2"
CANDIDATE_HOSTNAME = "avuhz-gate-d.test"
INGRESS_ADDRESS = "127.0.0.1"
INGRESS_PORT = 443
N8N_ADDRESS = "127.0.0.1"
N8N_PORT = 5678
WEBHOOK_ROUTE = "/webhook/avuhz-events"
EXACT_EXPOSED_ROUTES = (("POST", WEBHOOK_ROUTE),)
RECEIPT_ROUTE = "/v1/avuhz/local-n8n-receipts"


class GateDPreflightDenied(RuntimeError):
    """A sanitized failure category; raw local/provider data is never exposed."""


@dataclass(frozen=True, slots=True)
class WorkflowObservation:
    project_id: str
    receiver_id: str
    receiver_active: bool
    active_workflows: int
    persisted_executions: int
    webhook_method: str
    webhook_route: str
    metadata_verified: bool


@dataclass(frozen=True, slots=True)
class IngressObservation:
    hostname: str
    resolved_addresses: tuple[str, ...]
    listener_bindings: tuple[str, ...]
    tls_chain_verified: bool
    tls_hostname_verified: bool
    tls_minimum_version: str | None
    upstream: tuple[str, int] | None
    exposed_routes: tuple[tuple[str, str], ...]
    admin_routes_denied: bool
    proof_independently_established: bool


@dataclass(frozen=True, slots=True)
class PreflightResult:
    status: str
    blockers: tuple[str, ...]


def _safe_environment(environment: dict[str, str] | None = None) -> bool:
    values = os.environ if environment is None else environment
    return (
        values.get("AVUHZ_ENVIRONMENT") in ENVIRONMENTS
        and not values.get("CI")
        and not values.get("GITHUB_ACTIONS")
    )


def _credential_metadata(
    db: sqlite3.Connection, credential_id: str, name: str,
) -> tuple[str, str, str]:
    # The encrypted data column is intentionally never selected or inspected.
    rows = db.execute(
        "SELECT id,name,type "
        "FROM credentials_entity WHERE id=? AND name=?",
        (credential_id, name),
    ).fetchall()
    if len(rows) != 1:
        raise ValueError
    row = rows[0]
    if row[2] != "httpHeaderAuth":
        raise ValueError
    return row


def _bound_nodes(
    raw: str, source: dict, boundary: PrivateDockerBoundary,
) -> list[dict]:
    nodes = json.loads(raw)
    if not isinstance(nodes, list) or len(nodes) != 5:
        raise ValueError
    expected = copy.deepcopy(source["nodes"])
    expected[0]["credentials"] = {
        inbound.CREDENTIAL_TYPE: {
            "id": INBOUND_CREDENTIAL_ID,
            "name": inbound.CREDENTIAL_NAME,
        }
    }
    receipt_url = nodes[2].get("parameters", {}).get("url")
    parsed = urlsplit(receipt_url) if isinstance(receipt_url, str) else None
    if (
        parsed is None or parsed.scheme != "http"
        or parsed.hostname != boundary.gateway
        or parsed.path != RECEIPT_ROUTE or parsed.query or parsed.fragment
        or parsed.port is None or not 1024 <= parsed.port <= 65535
    ):
        raise ValueError
    expected[2]["parameters"]["url"] = receipt_url
    expected[2]["credentials"] = {
        receipt.CREDENTIAL_TYPE: {
            "id": RECEIPT_CREDENTIAL_ID,
            "name": receipt.CREDENTIAL_NAME,
        }
    }
    if nodes != expected:
        raise ValueError
    return nodes


def collect_workflow_observation() -> WorkflowObservation:
    """Query allowlisted n8n metadata only, using existing LOCAL helpers."""
    try:
        boundary = inspect_private_local_n8n()
        source = receiver._source()
        database = receiver._db_path()
        with sqlite3.connect(
            database.as_uri() + "?mode=ro", uri=True, timeout=5,
        ) as db:
            db.execute("PRAGMA query_only=ON")
            projects = db.execute(
                "SELECT id FROM project WHERE type='personal'"
            ).fetchall()
            rows = db.execute(
                "SELECT id,name,active,isArchived,nodes,connections,settings,"
                "staticData,pinData FROM workflow_entity WHERE id=?",
                (RECEIVER_ID,),
            ).fetchall()
            active = db.execute(
                "SELECT COUNT(*) FROM workflow_entity WHERE active=1"
            ).fetchone()[0]
            executions = db.execute(
                "SELECT COUNT(*) FROM execution_entity"
            ).fetchone()[0]
            registered_webhooks = db.execute(
                "SELECT COUNT(*) FROM webhook_entity"
            ).fetchone()[0]
            if len(projects) != 1 or projects[0][0] != PROJECT_ID or len(rows) != 1:
                raise ValueError
            row = rows[0]
            nodes = _bound_nodes(row[4], source, boundary)
            incoming = _credential_metadata(
                db, INBOUND_CREDENTIAL_ID, inbound.CREDENTIAL_NAME,
            )
            outbound = _credential_metadata(
                db, RECEIPT_CREDENTIAL_ID, receipt.CREDENTIAL_NAME,
            )
            workflow_shares = db.execute(
                "SELECT projectId,role FROM shared_workflow WHERE workflowId=?",
                (RECEIVER_ID,),
            ).fetchall()
            incoming_shares = db.execute(
                "SELECT projectId,role FROM shared_credentials WHERE credentialsId=?",
                (incoming[0],),
            ).fetchall()
            outbound_shares = db.execute(
                "SELECT projectId,role FROM shared_credentials WHERE credentialsId=?",
                (outbound[0],),
            ).fetchall()
            webhook = nodes[0]["parameters"]
            if (
                row[1] != source["name"] or bool(row[2]) or row[3] != 0
                or row[7:] != (None, None)
                or json.loads(row[5]) != source["connections"]
                or json.loads(row[6]) != source["settings"]
                or active != 0 or executions != 0 or registered_webhooks != 0
                or workflow_shares != [(PROJECT_ID, "workflow:owner")]
                or incoming_shares != [(PROJECT_ID, "credential:owner")]
                or outbound_shares != [(PROJECT_ID, "credential:owner")]
                or webhook.get("httpMethod") != "POST"
                or webhook.get("path") != "avuhz-events"
                or webhook.get("authentication") != "headerAuth"
                or webhook.get("responseMode") != "responseNode"
                or sum(node.get("type") == "n8n-nodes-base.webhook" for node in nodes) != 1
            ):
                raise ValueError
        return WorkflowObservation(
            project_id=PROJECT_ID,
            receiver_id=RECEIVER_ID,
            receiver_active=False,
            active_workflows=0,
            persisted_executions=0,
            webhook_method="POST",
            webhook_route=WEBHOOK_ROUTE,
            metadata_verified=True,
        )
    except Exception:
        raise GateDPreflightDenied("workflow_metadata_unverified") from None


def _linux_listener_bindings(
    tcp_path: Path, tcp6_path: Path, port: int,
) -> tuple[str, ...]:
    """Inspect both Linux listener tables without opening a socket."""
    bindings: set[str] = set()
    for path, version in ((tcp_path, 4), (tcp6_path, 6)):
        try:
            lines = path.read_text(encoding="ascii").splitlines()[1:]
        except (OSError, UnicodeError):
            raise GateDPreflightDenied("host_listener_state_unavailable") from None
        try:
            for line in lines:
                fields = line.split()
                if len(fields) < 4:
                    raise ValueError
                encoded_address, encoded_port = fields[1].rsplit(":", 1)
                if fields[3] != "0A" or int(encoded_port, 16) != port:
                    continue
                if version == 4:
                    if len(encoded_address) != 8:
                        raise ValueError
                    address_bytes = bytes.fromhex(encoded_address)[::-1]
                else:
                    if len(encoded_address) != 32:
                        raise ValueError
                    raw = bytes.fromhex(encoded_address)
                    address_bytes = b"".join(
                        raw[offset:offset + 4][::-1]
                        for offset in range(0, len(raw), 4)
                    )
                address = ipaddress.ip_address(address_bytes)
                rendered = str(address) if version == 4 else f"[{address}]"
                bindings.add(f"{rendered}:{port}")
        except (ValueError, IndexError):
            raise GateDPreflightDenied("host_listener_state_unavailable") from None
    return tuple(sorted(bindings))


def _hosts_loopback_mapping(path: Path, hostname: str) -> tuple[str, ...]:
    """Read only an explicit hosts mapping; never invoke DNS."""
    try:
        matches: set[str] = set()
        for raw in path.read_text(encoding="utf-8").splitlines():
            fields = raw.split("#", 1)[0].split()
            if len(fields) >= 2 and hostname in fields[1:]:
                address = ipaddress.ip_address(fields[0])
                if not address.is_loopback:
                    return ()
                matches.add(str(address))
        return tuple(sorted(matches))
    except (OSError, ValueError):
        return ()


def collect_host_observation(
    *,
    proc_tcp: Path = Path("/proc/net/tcp"),
    proc_tcp6: Path = Path("/proc/net/tcp6"),
    hosts: Path = Path("/etc/hosts"),
) -> IngressObservation:
    """Collect non-network host facts; TLS/route proof remains unasserted."""
    bindings = _linux_listener_bindings(proc_tcp, proc_tcp6, INGRESS_PORT)
    return IngressObservation(
        hostname=CANDIDATE_HOSTNAME,
        resolved_addresses=_hosts_loopback_mapping(hosts, CANDIDATE_HOSTNAME),
        listener_bindings=bindings,
        tls_chain_verified=False,
        tls_hostname_verified=False,
        tls_minimum_version=None,
        upstream=None,
        exposed_routes=(),
        admin_routes_denied=False,
        proof_independently_established=False,
    )


def evaluate_preflight(
    workflow: WorkflowObservation,
    ingress: IngressObservation,
    *,
    environment: dict[str, str] | None = None,
) -> PreflightResult:
    """Make a pure fail-closed decision from sanitized independent evidence."""
    blockers: list[str] = []
    if not _safe_environment(environment):
        blockers.append("unsafe_environment")
    if (
        not workflow.metadata_verified or workflow.project_id != PROJECT_ID
        or workflow.receiver_id != RECEIVER_ID
        or workflow.receiver_active or workflow.active_workflows != 0
        or workflow.persisted_executions != 0
        or (workflow.webhook_method, workflow.webhook_route)
        != EXACT_EXPOSED_ROUTES[0]
    ):
        blockers.append("workflow_metadata_unverified")
    if ingress.hostname != CANDIDATE_HOSTNAME:
        blockers.append("unexpected_hostname")
    if ingress.resolved_addresses != (INGRESS_ADDRESS,):
        blockers.append("hostname_not_loopback_verified")
    if ingress.listener_bindings != (f"{INGRESS_ADDRESS}:{INGRESS_PORT}",):
        blockers.append("port_443_loopback_listener_absent_or_public")
    if not (
        ingress.tls_chain_verified and ingress.tls_hostname_verified
        and ingress.tls_minimum_version in {"TLSv1.2", "TLSv1.3"}
    ):
        blockers.append("verified_tls_absent")
    if ingress.upstream != (N8N_ADDRESS, N8N_PORT):
        blockers.append("exact_loopback_n8n_upstream_unverified")
    if (
        ingress.exposed_routes != EXACT_EXPOSED_ROUTES
        or not ingress.admin_routes_denied
        or not ingress.proof_independently_established
    ):
        blockers.append("exact_path_isolation_unverified")
    return PreflightResult(
        status="PASS" if not blockers else "BLOCKED",
        blockers=tuple(blockers),
    )


def preflight(
    *,
    workflow_reader: Callable[[], WorkflowObservation] | None = None,
    host_reader: Callable[[], IngressObservation] | None = None,
    environment: dict[str, str] | None = None,
) -> PreflightResult:
    if not _safe_environment(environment):
        return PreflightResult("BLOCKED", ("unsafe_environment",))
    try:
        workflow_reader = workflow_reader or collect_workflow_observation
        host_reader = host_reader or collect_host_observation
        workflow = workflow_reader()
        ingress = host_reader()
    except GateDPreflightDenied as error:
        return PreflightResult("BLOCKED", (str(error),))
    except Exception:
        return PreflightResult("BLOCKED", ("preflight_observation_unavailable",))
    return evaluate_preflight(workflow, ingress, environment=environment)


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    args = parser.parse_args(argv)
    if args.target != TARGET:
        print("BLOCKED unexpected_target")
        return 2
    result = preflight()
    print(result.status + " " + ",".join(result.blockers or ("gate_d_ingress_verified",)))
    print("READ_ONLY no POST, credential read, execution, activation, or resource change")
    return 0 if result.status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(run())
