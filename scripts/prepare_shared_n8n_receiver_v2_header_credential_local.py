#!/usr/bin/env python3
"""Read-only by default; optional one LOCAL native n8n webhook header credential.

Source-only preparation is not authorization to provision. Approval must
identify exact LOCAL DefNet n8n resource, source digest and ONE credential
import. Never input tokens via command line, environment, Git or filesystem.
An independently authorized controller must supply a credential from its
approved secret boundary via inherited FD; this module provides no secret
creation, credential export, workflow binding, event execution or activation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import uuid
from dataclasses import dataclass

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/"src"),str(ROOT)]
from avuhz_worker.local_n8n_receipt_dev_runner import inspect_private_local_n8n
from avuhz_worker.local_system001_n8n_readiness import preflight as child_preflight
from scripts.prepare_shared_n8n_receiver_v2_local import (
    _source,_db_path,_inventory,
    TARGET, SOURCE_SHA256
)

HEADER_NAME="X-Avuhz-Webhook-Token"
CREDENTIAL_NAME="Avuhz Shared Receiver v2 LOCAL inbound header"
CREDENTIAL_TYPE="httpHeaderAuth"
MAX_TOKEN=512


class CredentialGateDenied(RuntimeError):
    pass


@dataclass(frozen=True,slots=True)
class Snapshot:
    project_id: str
    workflow_digest: str
    workflow_count: int
    credential_count: int
    shared_credential_count: int
    receiver_id: str
    receiver_credential_count: int
    active_workflow_count: int
    execution_count: int


def read_only_snapshot(dbfile: pathlib.Path, *, require_credential: bool=False,
                       expected_id: str | None=None) -> Snapshot:
    """Confirms EXACT installed source receiver, plus credential boundary.

    No credential payload is ever SELECTed, decrypted, copied or logged.
    Non-receiver workflows are hashed only in process to detect CLI side effects.
    """
    src=_source()
    try:
        with sqlite3.connect(dbfile.as_uri()+"?mode=ro",uri=True,timeout=5) as db:
            db.execute("PRAGMA query_only=ON")
            receiver=db.execute(
                "select id from workflow_entity where name=?",(src["name"],)
            ).fetchall()
            if len(receiver)!=1 or len(receiver[0][0])!=16:
                raise ValueError
            w_count=db.execute("select count(*) from workflow_entity").fetchone()[0]
            installed=_inventory(db,src,
                                 expected_install_id=receiver[0][0],
                                 previous_count=w_count-1)
            if (
                installed.active_count!=0 or installed.executions!=0
                or installed.shared_webhook_paths!=1
            ):
                raise ValueError
            rows=db.execute(
                "select id,active,nodes,connections,settings from "
                "workflow_entity order by id"
            ).fetchall()
            digest=hashlib.sha256(
                json.dumps(rows,ensure_ascii=True,
                           separators=(",",":"),sort_keys=True).encode()
            ).hexdigest()
            total=db.execute("select count(*) from credentials_entity").fetchone()[0]
            total_shared=db.execute("select count(*) from shared_credentials").fetchone()[0]
            matching=db.execute(
                "select id,type,length(data),substr(data,1,1) "
                "from credentials_entity where name=?",(CREDENTIAL_NAME,)
            ).fetchall()
            if require_credential:
                if (
                    expected_id is None or len(matching)!=1
                    or matching[0][0]!=expected_id
                    or matching[0][1]!=CREDENTIAL_TYPE
                    or type(matching[0][2]) is not int or matching[0][2]<20
                    or matching[0][3]=="{"
                    or db.execute(
                        "select count(*) from shared_credentials "
                        "where credentialsId=? and projectId=?",
                        (expected_id,installed.personal_project)
                    ).fetchone()[0]!=1
                ):
                    raise ValueError
            elif matching:
                raise ValueError
            return Snapshot(
                project_id=installed.personal_project,
                workflow_digest=digest,
                workflow_count=w_count,
                credential_count=total,
                shared_credential_count=total_shared,
                receiver_id=receiver[0][0],
                receiver_credential_count=len(matching),
                active_workflow_count=installed.active_count,
                execution_count=installed.executions,
            )
    except (sqlite3.Error,ValueError,KeyError,IndexError,TypeError,AttributeError):
        raise CredentialGateDenied("credential_boundary_untrusted") from None


def preflight() -> tuple[pathlib.Path,Snapshot]:
    try:
        inspect_private_local_n8n()
        result=child_preflight(root=ROOT)
        if not (result.get("all_workflows_inactive") is True
                and result.get("installed_v2_count")==1
                and result.get("credential_bound") is False
                and result.get("receipt_endpoint_configured") is False
                and result.get("shared_receiver_bound") is False
                and result.get("existing_execution_rows")==0):
            raise ValueError
        path=_db_path()
        return path,read_only_snapshot(path)
    except CredentialGateDenied:
        raise
    except Exception:
        raise CredentialGateDenied("credential_boundary_untrusted") from None


def load_private_token(fd: int) -> str:
    """Read only an independently approved existing shared secret via FD."""
    if type(fd) is not int or fd<3:
        raise CredentialGateDenied("approved_private_fd_required")
    raw=bytearray()
    try:
        while len(raw)<=MAX_TOKEN:
            chunk=os.read(fd,MAX_TOKEN+1-len(raw))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw)>MAX_TOKEN:
                break
    except OSError:
        raise CredentialGateDenied("private_credential_fd_unavailable") from None
    finally:
        try: os.close(fd)
        except OSError: pass
    if (
        not 32<=len(raw)<=MAX_TOKEN
        or any(byte<33 or byte>126 for byte in raw)
    ):
        raise CredentialGateDenied("private_credential_invalid")
    return raw.decode("ascii")


def import_once(project_id: str, token: str, credential_id: str) -> None:
    """Exactly one supported encrypted n8n credential import; no retries."""
    doc={
        "id":credential_id,
        "name":CREDENTIAL_NAME,
        "type":CREDENTIAL_TYPE,
        "data":{"name":HEADER_NAME,"value":token},
    }
    wire=json.dumps([doc],separators=(",",":")).encode("utf-8")
    try:
        result=subprocess.run(
            ["docker","exec","-i","n8n","n8n","import:credentials",
             "--input=/dev/stdin","--projectId="+project_id],
            input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            timeout=60,check=False,
        )
        if result.returncode!=0:
            raise ValueError
    except (OSError,subprocess.SubprocessError,ValueError):
        raise CredentialGateDenied("single_encrypted_credential_import_unverified") from None
    finally:
        wire=None
        doc=None


def run(argv: list[str] | None=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target",required=True)
    parser.add_argument("--import-one",action="store_true")
    parser.add_argument("--approved-source-sha256")
    parser.add_argument("--token-fd",type=int)
    args=parser.parse_args(argv)
    try:
        if (
            args.target!=TARGET
            or os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")
            or os.environ.get("AVUHZ_ENVIRONMENT","LOCAL") not in ("LOCAL","TEST")
        ):
            raise CredentialGateDenied("local_only_execution_required")
        if args.import_one:
            if args.approved_source_sha256!="sha256:"+SOURCE_SHA256:
                raise CredentialGateDenied("exact_source_approval_required")
            if args.token_fd is None:
                raise CredentialGateDenied("approved_private_fd_required")
        elif args.approved_source_sha256 is not None or args.token_fd is not None:
            raise CredentialGateDenied("read_only_does_not_load_secrets")
        path,before=preflight()
        print("PASS LOCAL shared receiver installed source and credential preflight",
              flush=True)
        if not args.import_one:
            print("PASS no resource changes; one separately approved secret required",
                  flush=True)
            return 0
        token=load_private_token(args.token_fd)
        cid=str(uuid.uuid4())
        try:
            import_once(before.project_id,token,cid)
        finally:
            token=None
        after=read_only_snapshot(path,require_credential=True,expected_id=cid)
        if (
            after.workflow_digest!=before.workflow_digest
            or after.workflow_count!=before.workflow_count
            or after.receiver_id!=before.receiver_id
            or after.credential_count!=before.credential_count+1
            or after.shared_credential_count!=before.shared_credential_count+1
            or after.receiver_credential_count!=1
            or after.active_workflow_count!=0
            or after.execution_count!=0
        ):
            raise CredentialGateDenied("single_credential_postcondition_denied")
        print("PASS exactly one n8n-encrypted LOCAL shared receiver header credential imported",
              flush=True)
        print("PASS all workflows unchanged, inactive, zero executions; credential NOT bound",
              flush=True)
        return 0
    except CredentialGateDenied as exc:
        print("BLOCKED "+str(exc),flush=True)
        return 2
    except Exception:
        print("BLOCKED local_credential_gate_unavailable",flush=True)
        return 2


if __name__=="__main__":
    raise SystemExit(run())
