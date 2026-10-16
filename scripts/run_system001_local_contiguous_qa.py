#!/usr/bin/env python3
"""Opt-in ONE-run LOCAL/TEST System #001 QA: disposable PG + existing n8n.

Never starts on import or in CI. Requires an exact external operator approval
before --execute-local-qa is used. Default is read-only preflight. No hosted
Supabase AUTH/DATA, Render, production, real owner or real customer traffic.
Creates exactly one uniquely named loopback-only disposable PostgreSQL
container; existing guarded certifier owns limited inactive n8n QA imports and
restores the original System 001 child.

This is NOT a daemon, automatic trigger, trusted issuer, or production runtime.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from avuhz_worker.local_system001_n8n_readiness import preflight

IMAGE = "docker.io/library/postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94"
CHILD = ROOT / "scripts" / "certify_system001_live_local_n8n_to_work.py"
DSN_DATABASE = "avuhz_system001_durable_writer_test"
_CONTAINER_PREFIX = "avuhz-system001-qa-disposable-"
_REQUIRED_MARKERS = frozenset({
    "PASS exact LOCAL n8n project, inactive child, synthetic-only QA fixture",
    "PASS private receipt listener bound to verified Docker bridge",
    "PASS one dedicated QA header credential encrypted by n8n",
    "PASS one inactive v2 child bound only to private QA receipt",
    "PASS fictional shared HTTP acquisition committed and outbox projected one PII-free event",
    "PASS ONE actual n8n manual execution delivered exactly one private durable QA receipt",
    "PASS cross-tenant human denied before actual PostgreSQL Work Item writer",
    "PASS real n8n receipt -> exactly one PG Work Item/idempotency/lifecycle/outbox and deadline",
    "PASS persisted due review/escalation and tenant isolation certified",
    "PASS authorized handoff, resolution and revoked former owner certified",
    "PASS original unbound inactive System #001 child restored",
    "PASS private receipt service stopped; local ephemeral receipt database removed",
    "PASS NO hosted AUTH/DATA/production/customer/billing changes",
})


class LocalQaDenied(RuntimeError):
    """Safe fixed category; diagnostics must not include process output."""


def _invoke(command: list[str], *, timeout: int = 15, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        command, cwd=ROOT, env=env, timeout=timeout, check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def _check_n8n_readonly() -> None:
    try:
        report = preflight(root=ROOT)
        if not (
            report.get("all_workflows_inactive") is True
            and report.get("installed_node_count") == 5
            and report.get("installed_v2_count") == 1
            and report.get("qa_fixture_is_fictional") is True
            and report.get("existing_execution_rows") == 0
            and report.get("credential_bound") is False
            and report.get("receipt_endpoint_configured") is False
            and report.get("owner_lookup_connected") is False
        ):
            raise ValueError
    except Exception:
        raise LocalQaDenied("local_n8n_preflight_denied") from None


def _require_pinned_qa_python() -> None:
    """Never start a disposable database unless PG + security libs are pinned.

    The operator runs this entrypoint using an approved isolated Python
    environment with repository-matched requirements. No automatic network
    pip install, no untrusted fallback, and no surprising subprocess Python.
    """
    exact = {
        "psycopg": "3.3.4",
        "jsonschema": "4.10.3",
        "PyJWT": "2.14.0",
        "cryptography": "50.0.1",
    }
    try:
        if any(
            importlib.metadata.version(package) != version
            for package, version in exact.items()
        ):
            raise ValueError
    except (importlib.metadata.PackageNotFoundError, ValueError):
        raise LocalQaDenied("pinned_qa_python_unavailable") from None


def _require_local_only() -> None:
    # Require an interactive operator / agent to separately approve the run;
    # a CI runner must never create QA credentials or exercise installed n8n.
    if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
        raise LocalQaDenied("ci_execution_denied")
    if os.environ.get("AVUHZ_ENVIRONMENT", "LOCAL") not in {"LOCAL", "TEST"}:
        raise LocalQaDenied("nonlocal_environment_denied")


def _required_source_files() -> None:
    paths = (
        CHILD,
        ROOT / "tests" / "fixtures" / "system001_qa_tenant_local_v1.json",
        ROOT / "contracts" / "templates" / "n8n"
        / "avuhz-system-001-revenue-receipt-gated-inactive-v2.json",
    )
    if not all(p.is_file() and not p.is_symlink() for p in paths):
        raise LocalQaDenied("qa_source_incomplete")


def _image_present() -> None:
    result = _invoke(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"])
    if result.returncode != 0 or not re.fullmatch(r"sha256:[0-9a-f]{64}\n?", result.stdout):
        raise LocalQaDenied("pinned_pg17_image_absent")


def _wait_for_pg(container: str) -> None:
    stable = 0
    for _ in range(80):
        ready = _invoke([
            "docker", "exec", container,
            "pg_isready", "-U", "postgres", "-d", "postgres",
        ], timeout=5)
        stable = stable + 1 if ready.returncode == 0 else 0
        if stable >= 4:
            return
        time.sleep(0.25)
    raise LocalQaDenied("disposable_pg17_not_ready")


def _mapped_loopback_port(container: str) -> int:
    result = _invoke(["docker", "port", container, "5432/tcp"])
    if result.returncode != 0:
        raise LocalQaDenied("disposable_pg17_port_untrusted")
    match = re.fullmatch(r"127\.0\.0\.1:(\d{2,5})\n?", result.stdout)
    if match is None:
        raise LocalQaDenied("disposable_pg17_port_untrusted")
    port = int(match.group(1))
    if port < 1024 or port > 65535:
        raise LocalQaDenied("disposable_pg17_port_untrusted")
    return port


def _classify_certifier_output(raw: str, code: int) -> None:
    # Never print subprocess stdout/stderr or n8n raw CLI output: some n8n
    # commands produce full execution JSON including sensitive fields.
    entries = set(line for line in raw.splitlines() if line.startswith("PASS "))
    if code != 0 or "QA_RUN_BLOCKED" in raw or "BLOCKED " in raw or not _REQUIRED_MARKERS.issubset(entries):
        raise LocalQaDenied("contiguous_n8n_pg_certification_failed")


def run_local_qa() -> None:
    _require_local_only()
    _required_source_files()
    _require_pinned_qa_python()
    _check_n8n_readonly()
    _image_present()   # --pull=never avoids unexpected remote image fetch
    container = _CONTAINER_PREFIX + secrets.token_hex(6)
    created = False
    try:
        creation = _invoke([
            "docker", "run", "-d", "--rm", "--pull=never",
            "--name", container, "--network=bridge",
            "-p", "127.0.0.1::5432",
            "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
            IMAGE,
        ], timeout=30)
        created = creation.returncode == 0
        if not created or not re.fullmatch(
            r"[0-9a-f]{64}\n?", creation.stdout
        ):
            raise LocalQaDenied("disposable_pg17_start_denied")
        _wait_for_pg(container)
        port = _mapped_loopback_port(container)
        _check_n8n_readonly()  # fresh read immediately before n8n imports
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{ROOT}/src:{ROOT}"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["AVUHZ_LOCAL_POSTGRES_CONTAINER"] = container
        env["AVUHZ_WORK_ITEM_TEST_LOCAL_DSN"] = (
            f"host=127.0.0.1 port={port} dbname={DSN_DATABASE} user=postgres"
        )
        result = _invoke(
            [sys.executable, str(CHILD)], timeout=180, env=env,
        )
        _classify_certifier_output(result.stdout, result.returncode)
        _check_n8n_readonly()
        print("PASS contiguous fictional LOCAL acquisition -> installed n8n -> disposable PG17")
    except (subprocess.SubprocessError, OSError):
        raise LocalQaDenied("local_qa_execution_unavailable") from None
    finally:
        if created:
            removal = _invoke(["docker", "rm", "-f", container], timeout=15)
            if removal.returncode != 0 or removal.stdout.strip() != container:
                raise LocalQaDenied("disposable_pg17_cleanup_unverified")
            # The name is generated and was never used before this one run.
            check = _invoke([
                "docker", "ps", "-aq", "--filter", f"name=^/{container}$"
            ])
            if check.returncode != 0 or check.stdout.strip():
                raise LocalQaDenied("disposable_pg17_cleanup_unverified")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-local-qa", action="store_true",
                        help="Execute ONE authorized n8n/PG17 LOCAL QA cycle")
    args = parser.parse_args(argv)
    try:
        _require_local_only()
        _required_source_files()
        _check_n8n_readonly()
        _image_present()
        if args.execute_local_qa:
            run_local_qa()
        else:
            print("PASS LOCAL System #001 QA read-only preflight")
            print("NO resources changed; separate approval required before --execute-local-qa")
        return 0
    except LocalQaDenied as error:
        print("BLOCKED " + str(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
