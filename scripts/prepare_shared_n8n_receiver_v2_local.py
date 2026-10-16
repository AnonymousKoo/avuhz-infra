#!/usr/bin/env python3
"""Exact source-bound LOCAL n8n receiver v2 preflight / inactive-only import.

Default: read-only checks of current LOCAL n8n 127.0.0.1:5678.
--install-inactive is a separately approved SINGLE installed resource mutation.
No credentials, URLs, activation, event execution, retries or hosted provider
calls; the existing v1 503 receiver and System #001 child are not modified.

An inactive receiver has NO operational customer value until separately
reviewed HTTPS ingress, encrypted credentials and private durable receipt
are configured. This code never claims end-to-end unattended certification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import secrets
import sqlite3
import subprocess
import sys
from dataclasses import dataclass

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/"src"),str(ROOT)]
from avuhz_worker.local_n8n_receipt_dev_runner import inspect_private_local_n8n
from avuhz_worker.local_system001_n8n_readiness import preflight as check_child

SOURCE=ROOT/"contracts/templates/n8n/avuhz-shared-event-receiver-durable-inactive-v2.json"
SOURCE_SHA256="fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f"
TARGET="LOCAL_DEVELOPMENT_N8N_5678"
CONTAINER="n8n"
UNBOUND_RECEIPT="http://127.0.0.1:1/v1/avuhz/local-n8n-receipts"


class LocalReceiverInstallDenied(RuntimeError):
    """A safe constant code, without original n8n/provider/PII diagnostics."""


@dataclass(frozen=True,slots=True)
class ReceiverPreflight:
    personal_project: str
    workflow_count: int
    active_count: int
    executions: int
    receiver_matches: int
    shared_webhook_paths: int


def _source() -> dict:
    try:
        raw=SOURCE.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=SOURCE_SHA256:
            raise ValueError
        candidate=json.loads(raw)
        n=candidate["nodes"]
        if (
            candidate["active"] is not False
            or len(n)!=5
            or [node["type"] for node in n] != [
                "n8n-nodes-base.webhook", "n8n-nodes-base.code",
                "n8n-nodes-base.httpRequest", "n8n-nodes-base.code",
                "n8n-nodes-base.respondToWebhook",
            ]
            or n[0]["parameters"].get("authentication")!="headerAuth"
            or n[0]["parameters"].get("path")!="avuhz-events"
            or n[0]["parameters"].get("responseMode")!="responseNode"
            or n[2]["parameters"].get("url")!=UNBOUND_RECEIPT
            or n[2]["parameters"].get("authentication")!="genericCredentialType"
            or n[4]["parameters"]["options"]["responseCode"]!=202
            or len(candidate["connections"])!=4
            or len({node["id"] for node in n})!=5
            or any("credentials" in node for node in n)
            or "credentials" in candidate
            or any(candidate["settings"].get(key)!="none" for key in (
                "saveDataSuccessExecution","saveDataErrorExecution"
            ))
            or candidate["settings"].get("saveManualExecutions") is not False
            or "id" in candidate
        ):
            raise ValueError
        return candidate
    except (OSError, KeyError, ValueError, TypeError, IndexError, AttributeError):
        raise LocalReceiverInstallDenied("receiver_source_untrusted") from None


def _db_path() -> pathlib.Path:
    try:
        # No Docker env inspection, credential dump, direct DB mutation,
        # network request, or container subprocess shell.
        output=subprocess.run([
            "docker","inspect","-f",
            '{{range .Mounts}}{{if eq .Destination "/home/node/.n8n"}}{{.Source}}{{end}}{{end}}',
            CONTAINER,
        ],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,
            timeout=8,check=False)
        if output.returncode!=0:
            raise ValueError
        root=pathlib.Path(output.stdout.strip())
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise ValueError
        p=root/"database.sqlite"
        if not p.is_file() or p.is_symlink():
            raise ValueError
        return p
    except (OSError,subprocess.SubprocessError,ValueError):
        raise LocalReceiverInstallDenied("local_n8n_database_unavailable") from None


def _inventory(db: sqlite3.Connection, source: dict, *,
               expected_install_id: str | None=None,
               previous_count: int | None=None) -> ReceiverPreflight:
    try:
        projects=db.execute("select id from project where type='personal'").fetchall()
        if len(projects)!=1 or not isinstance(projects[0][0],str):
            raise ValueError
        counts=db.execute(
            "select count(*),coalesce(sum(case when active=1 then 1 else 0 end),0) "
            "from workflow_entity"
        ).fetchone()
        if counts is None or counts[1]!=0:
            raise ValueError
        executions=db.execute("select count(*) from execution_entity").fetchone()[0]
        if executions !=0:
            raise ValueError
        rows=db.execute(
            "select id,active,nodes,connections,settings from workflow_entity "
            "where name=?",(source["name"],)
        ).fetchall()
        installed_paths=0
        for (raw,) in db.execute("select nodes from workflow_entity"):
            # In-process read only: do not log other workflows, raw nodes or IDs.
            nodes=json.loads(raw)
            if not isinstance(nodes,list):
                raise ValueError
            for node in nodes:
                if node.get("type")=="n8n-nodes-base.webhook" and node.get(
                    "parameters",{}
                ).get("path")=="avuhz-events":
                    installed_paths+=1

        if expected_install_id is None:
            if rows or installed_paths:
                raise ValueError
        else:
            if (
                len(rows)!=1 or rows[0][0]!=expected_install_id
                or bool(rows[0][1]) or installed_paths!=1
                or counts[0]!=previous_count+1
                or json.loads(rows[0][2])!=source["nodes"]
                or json.loads(rows[0][3])!=source["connections"]
            ):
                raise ValueError
            settings=json.loads(rows[0][4])
            if (
                settings.get("saveDataSuccessExecution")!="none"
                or settings.get("saveDataErrorExecution")!="none"
                or settings.get("saveManualExecutions") is not False
            ):
                raise ValueError
            shared=db.execute(
                "select count(*) from shared_workflow where workflowId=?",
                (expected_install_id,),
            ).fetchone()[0]
            if shared!=1:
                raise ValueError
            if any("credentials" in node for node in json.loads(rows[0][2])):
                raise ValueError
        return ReceiverPreflight(
            personal_project=projects[0][0],
            workflow_count=counts[0],
            active_count=counts[1],
            executions=executions,
            receiver_matches=len(rows),
            shared_webhook_paths=installed_paths,
        )
    except (TypeError,ValueError,KeyError,IndexError,sqlite3.Error,AttributeError):
        raise LocalReceiverInstallDenied("local_receiver_install_boundary_denied") from None


def _inspect_source_and_installed() -> tuple[dict,pathlib.Path,ReceiverPreflight]:
    try:
        inspect_private_local_n8n()  # exact trusted local Docker bridge
        report=check_child(root=ROOT)  # exact inactive System #001 v2 source
        if not (
            report.get("all_workflows_inactive") is True
            and report.get("installed_v2_count")==1
            and report.get("installed_node_count")==5
            and report.get("qa_fixture_is_fictional") is True
            and report.get("credential_bound") is False
            and report.get("receipt_endpoint_configured") is False
            and report.get("shared_receiver_bound") is False
            and report.get("existing_execution_rows")==0
        ):
            raise ValueError
        source=_source()
        dbfile=_db_path()
        with sqlite3.connect(
            dbfile.as_uri()+"?mode=ro",uri=True,timeout=5,
        ) as db:
            db.execute("pragma query_only=ON")
            existing=_inventory(db,source)
        return source,dbfile,existing
    except LocalReceiverInstallDenied:
        raise
    except Exception:
        raise LocalReceiverInstallDenied("local_receiver_install_boundary_denied") from None


def _import_one(source: dict, project_id: str, workflow_id: str) -> None:
    doc={**source,"id":workflow_id,"active":False}
    wire=json.dumps([doc],sort_keys=True,separators=(",",":")).encode("utf-8")
    try:
        result=subprocess.run(
            ["docker","exec","-i",CONTAINER,"n8n","import:workflow",
             "--input=/dev/stdin","--projectId="+project_id],
            input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            timeout=60,check=False,
        )
        if result.returncode!=0:
            raise ValueError
    except (OSError,subprocess.SubprocessError,ValueError):
        # No retry: a failed CLI may have partially imported the workflow.
        raise LocalReceiverInstallDenied("inactive_receiver_import_unverified") from None


def run(argv: list[str] | None=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target",required=True)
    parser.add_argument("--install-inactive",action="store_true")
    parser.add_argument("--approved-source-sha256")
    args=parser.parse_args(argv)
    try:
        if (
            args.target!=TARGET
            or os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")
            or os.environ.get("AVUHZ_ENVIRONMENT","LOCAL") not in ("LOCAL","TEST")
        ):
            raise LocalReceiverInstallDenied("local_only_execution_required")
        if args.install_inactive:
            if args.approved_source_sha256!="sha256:"+SOURCE_SHA256:
                raise LocalReceiverInstallDenied("exact_source_approval_required")
        elif args.approved_source_sha256 is not None:
            raise LocalReceiverInstallDenied("preflight_must_not_claim_approval")
        source,path,prior=_inspect_source_and_installed()
        print("PASS exact LOCAL n8n inactive shared receiver v2 preflight",flush=True)
        if not args.install_inactive:
            print("PASS no resource changes; installed receiver not present",flush=True)
            return 0
        workflow_id=secrets.token_hex(8) # exact local n8n supported native ID length
        _import_one(source,prior.personal_project,workflow_id)
        with sqlite3.connect(path.as_uri()+"?mode=ro",uri=True,timeout=5) as db:
            db.execute("pragma query_only=ON")
            _inventory(db,source,expected_install_id=workflow_id,
                       previous_count=prior.workflow_count)
        print("PASS exactly one new inactive unbound shared receiver imported",flush=True)
        print("PASS zero activated workflows and zero executed events",flush=True)
        return 0
    except LocalReceiverInstallDenied as error:
        print("BLOCKED "+str(error),flush=True)
        return 2
    except Exception:
        print("BLOCKED inactive_receiver_postcondition_unavailable",flush=True)
        return 2


if __name__=="__main__":
    raise SystemExit(run())
