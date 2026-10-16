#!/usr/bin/env python3
"""LOCAL/TEST one-way private secret-FD bridge to an existing n8n importer.

DEFAULT is a read-only exact LOCAL n8n preflight: no 1Password calls or writes.
Write mode requires a fresh external exact authorization, a signed-in owner
1Password session and an already approved LOCAL Avuhz webhook field.
No plaintext secret is written to files, CLI arguments, shell or logs.
Do not run write mode based only on a merged PR or CI approval.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sqlite3
import subprocess
import sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/"src"),str(ROOT)]
from avuhz_worker.local_n8n_onepassword_credential import (
    LocalN8nOnePasswordCredential, LocalN8nSecretUnavailable,
)
from scripts import prepare_shared_n8n_receiver_v2_header_credential_local as gate

IMPORTER=ROOT/"scripts/prepare_shared_n8n_receiver_v2_header_credential_local.py"
MAX_IMPORT_SECONDS=90


class BridgeDenied(RuntimeError):
    pass


def import_private_fd_once(token: str, *, source_sha256: str) -> None:
    """At most ONE approved importer process; token supplied via inherited FD.

    The importer has its own source/digest checks, encrypted-at-rest n8n CLI,
    and read-only before/after assertions. No automatic retry or cleanup.
    """
    if (
        type(token) is not str or not 32<=len(token)<=512
        or any(ord(c)<33 or ord(c)>126 for c in token)
        or type(source_sha256) is not str
        or source_sha256!="sha256:"+gate.SOURCE_SHA256
    ):
        raise BridgeDenied("private_import_boundary_denied")
    reader=None
    writer=None
    process=None
    try:
        reader,writer=os.pipe()
        # An exact local Python script path from the checked-out canonical
        # worktree, not a shell, PATH lookup, remote n8n or untrusted URL.
        process=subprocess.Popen(
            [sys.executable,str(IMPORTER),"--target",gate.TARGET,
             "--import-one","--approved-source-sha256",source_sha256,
             "--token-fd",str(reader)],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,pass_fds=(reader,),
            cwd=str(ROOT),
        )
        os.close(reader)
        reader=None
        # Secret enters only the inherited pipe, never argv or the environment.
        encoded=token.encode("ascii")
        sent=0
        while sent<len(encoded):
            count=os.write(writer,encoded[sent:])
            if count<=0:
                raise OSError("private_pipe_write_failed")
            sent+=count
        os.close(writer)
        writer=None
        result,_=process.communicate(timeout=MAX_IMPORT_SECONDS)
        if process.returncode!=0 or type(result)is not bytes:
            raise BridgeDenied("single_importer_postcondition_unverified")
        # Check only static success strings, do not relay provider messages.
        if b"PASS exactly one n8n-encrypted LOCAL shared receiver header credential imported" not in result:
            raise BridgeDenied("single_importer_postcondition_unverified")
        if b"PASS all workflows unchanged, inactive, zero executions; credential NOT bound" not in result:
            raise BridgeDenied("single_importer_postcondition_unverified")
    except BridgeDenied:
        raise
    except (OSError,subprocess.SubprocessError,UnicodeError):
        raise BridgeDenied("private_importer_unavailable") from None
    finally:
        if writer is not None:
            try:os.close(writer)
            except OSError:pass
        if reader is not None:
            try:os.close(reader)
            except OSError:pass
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()


def postcheck_exact_increment(path: pathlib.Path, before: gate.Snapshot) -> bool:
    """Independent bounded metadata check; never SELECT raw credential data."""
    try:
        with sqlite3.connect(path.as_uri()+"?mode=ro",uri=True,timeout=5) as db:
            db.execute("PRAGMA query_only=ON")
            ids=db.execute(
                "SELECT id FROM credentials_entity WHERE name=?",
                (gate.CREDENTIAL_NAME,),
            ).fetchall()
            if len(ids)!=1:
                return False
            after=gate.read_only_snapshot(path,require_credential=True,
                                          expected_id=ids[0][0])
            return (
                after.credential_count==before.credential_count+1
                and after.shared_credential_count==before.shared_credential_count+1
                and after.workflow_count==before.workflow_count
                and after.workflow_digest==before.workflow_digest
                and after.active_workflow_count==0
                and after.execution_count==0
                and after.receiver_id==before.receiver_id
                and after.receiver_credential_count==1
            )
    except (OSError,sqlite3.Error,gate.CredentialGateDenied,TypeError,ValueError):
        return False


def run(argv: list[str] | None=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target",required=True)
    parser.add_argument("--import-one",action="store_true")
    parser.add_argument("--approved-source-sha256")
    parser.add_argument("--approved-secret-reference")
    args=parser.parse_args(argv)
    try:
        if (
            args.target!=gate.TARGET
            or os.environ.get("CI")
            or os.environ.get("GITHUB_ACTIONS")
            or os.environ.get("AVUHZ_ENVIRONMENT","LOCAL") not in ("LOCAL","TEST")
        ):
            raise BridgeDenied("local_only_execution_required")
        if args.import_one:
            if (
                args.approved_source_sha256!="sha256:"+gate.SOURCE_SHA256
                or not args.approved_secret_reference
            ):
                raise BridgeDenied("separate_exact_secret_approval_required")
            # Validation-only: constructor never reads 1Password.
            provider=LocalN8nOnePasswordCredential(
                environment="LOCAL",
                approved_secret_reference=args.approved_secret_reference,
            )
        elif (args.approved_secret_reference is not None
              or args.approved_source_sha256 is not None):
            raise BridgeDenied("read_only_does_not_use_secrets")
        path,before=gate.preflight()
        print("PASS LOCAL shared n8n inactive receiver and zero bound credential preflight",
              flush=True)
        if not args.import_one:
            print("PASS no 1Password secret read, credential import or workflow mutation",
                  flush=True)
            return 0
        # Only an authenticated, separately approved 1Password field may be
        # read here. No sign-in, item enumeration, creation or fallback.
        secret=provider()
        try:
            import_private_fd_once(secret,source_sha256=args.approved_source_sha256)
        finally:
            secret=None
        if not postcheck_exact_increment(path,before):
            raise BridgeDenied("single_credential_postcondition_unverified")
        print("PASS one encrypted LOCAL n8n credential from approved private issuer",
              flush=True)
        print("PASS existing workflows remain inactive and unbound",flush=True)
        return 0
    except (BridgeDenied,gate.CredentialGateDenied,
            LocalN8nSecretUnavailable,ValueError):
        print("BLOCKED LOCAL shared credential prerequisite or postcondition",
              flush=True)
        return 2
    except Exception:
        print("BLOCKED LOCAL private secret bridge unavailable",flush=True)
        return 2


if __name__=="__main__":
    raise SystemExit(run())
