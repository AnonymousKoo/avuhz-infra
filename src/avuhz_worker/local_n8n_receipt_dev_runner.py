"""Explicit LOCAL/TEST receipt-service launcher. Never automatically enabled.

Starting this service requires separate authorization. This module provides
no credential, tenant, backend path, or active network listener by default.
It cannot replace the canonical Avuhz command service or DATA RLS.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import stat
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from .local_n8n_receipt_http import LocalN8nReceiptHTTPServer
from .local_n8n_receipt_store import LocalN8nReceiptStore

_TARGET = "LOCAL_DEVELOPMENT_N8N_5678"
_ALLOWED = frozenset({"acquisition.intake.received"})
_MAX_SECRET_BYTES = 512
_INSPECT_N8N_FORMAT = (
    "{{json .Name}}|{{json .State.Running}}|"
    "{{json .HostConfig.NetworkMode}}|"
    "{{json .HostConfig.PortBindings}}|"
    "{{json .NetworkSettings.Networks}}"
)


@dataclass(frozen=True, slots=True)
class PrivateDockerBoundary:
    gateway: str
    client: str
    cidr: str


def _docker_output(*args: str) -> str:
    """Inspect selected non-sensitive Docker metadata, never container env."""
    try:
        return subprocess.check_output(
            ["docker", *args], timeout=8,
            stderr=subprocess.DEVNULL, text=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError("local_n8n_identity_unavailable") from None


def inspect_private_local_n8n() -> PrivateDockerBoundary:
    """Fail closed if the exact localhost n8n container or network drifts."""
    try:
        raw = _docker_output("inspect", "n8n", "--format", _INSPECT_N8N_FORMAT)
        columns = raw.strip().split("|")
        if len(columns) != 5:
            raise ValueError
        name, running, mode, ports, networks = [json.loads(x) for x in columns]
        if name != "/n8n" or running is not True or mode != "bridge":
            raise ValueError
        if ports != {"5678/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5678"}]}:
            raise ValueError
        network = networks["bridge"]
        gateway, client = network["Gateway"], network["IPAddress"]
        config = json.loads(
            _docker_output("network", "inspect", "bridge",
                           "--format", "{{json .IPAM.Config}}")
        )
        cidr = config[0]["Subnet"]
        subnet = ipaddress.IPv4Network(cidr, strict=True)
        gw = ipaddress.IPv4Address(gateway)
        cl = ipaddress.IPv4Address(client)
        if (
            not subnet.is_private or subnet.prefixlen < 16
            or not gw.is_private or not cl.is_private
            or gw not in subnet or cl not in subnet or gw == cl
            or gw.is_loopback or cl.is_loopback
        ):
            raise ValueError
    except (KeyError, TypeError, IndexError, ValueError):
        raise ValueError("local_n8n_network_boundary_untrusted") from None
    return PrivateDockerBoundary(gateway, client, cidr)


def validate_storage_path(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("private_receipt_path_required")
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError("private_receipt_directory_required")
    if stat.S_IMODE(parent.stat().st_mode) & 0o077 or parent.stat().st_uid != os.getuid():
        raise ValueError("private_receipt_directory_required")
    if path.exists() and (
        not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077
    ):
        raise ValueError("private_receipt_file_required")


def _check_tenant(value: str) -> str:
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("independently_verified_tenant_required") from None
    return value


def load_token_from_fd(fd: int) -> str:
    """Token never enters command arguments, env, Git or stdout."""
    if type(fd) is not int or fd < 3:
        raise ValueError("approved_secret_fd_required")
    try:
        raw = os.read(fd, _MAX_SECRET_BYTES + 1)
    except OSError:
        raise ValueError("approved_secret_fd_unavailable") from None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if not 32 <= len(raw) <= _MAX_SECRET_BYTES or any(byte < 33 or byte > 126 for byte in raw):
        raise ValueError("approved_secret_unavailable")
    return raw.decode("ascii")


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Local n8n receipt bridge; preflight only by default"
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--trusted-tenant-id", required=True)
    parser.add_argument("--receipt-db", type=Path, required=True)
    parser.add_argument("--serve", action="store_true", default=False)
    parser.add_argument("--token-fd", type=int)
    args = parser.parse_args(argv)
    if args.target != _TARGET:
        raise ValueError("local_development_target_required")
    tenant = _check_tenant(args.trusted_tenant_id)
    validate_storage_path(args.receipt_db)
    network = inspect_private_local_n8n()
    if not args.serve:
        if args.token_fd is not None:
            raise ValueError("preflight_must_not_load_credentials")
        print("LOCAL_DEVELOPMENT_PREFLIGHT_PASS; no listener; no database writes")
        print("n8n Docker gateway verified private; source identity pinned")
        return 0
    if args.token_fd is None:
        raise ValueError("approved_secret_fd_required")
    token = load_token_from_fd(args.token_fd)
    # Only an explicitly approved serve command has effects.
    store = LocalN8nReceiptStore(
        args.receipt_db, trusted_tenant_id=tenant,
        allowed_event_types=_ALLOWED,
    )
    server = LocalN8nReceiptHTTPServer(
        receipt_store=store, token_provider=lambda: token,
        bind_host=network.gateway, trusted_client_ip=network.client,
        bridge_cidr=network.cidr,
    )
    try:
        # Safe local metadata only; never print the secret, tenant ID, or payload.
        print(
            f"LOCAL_DEVELOPMENT_RECEIPT_BOUND_PRIVATE "
            f"http://{network.gateway}:{server.server_port}", flush=True,
        )
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
    return 0


def main() -> None:
    try:
        raise SystemExit(run())
    except (ValueError, OSError) as error:
        # Print safe static error names only, never token, header or event data.
        allowed = {
            "local_n8n_identity_unavailable", "local_n8n_network_boundary_untrusted",
            "private_receipt_path_required", "private_receipt_directory_required",
            "private_receipt_file_required", "independently_verified_tenant_required",
            "local_development_target_required", "preflight_must_not_load_credentials",
            "approved_secret_fd_required", "approved_secret_fd_unavailable",
            "approved_secret_unavailable",
        }
        code = str(error)
        print(code if code in allowed else "local_dev_server_unavailable")
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
