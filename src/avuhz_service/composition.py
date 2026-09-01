"""Local-only service composition over the existing governed runtime."""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from pathlib import Path
from typing import Mapping

from avuhz_runtime.command_registry import COMMANDS
from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, MemoryStore, UnitOfWork
from avuhz_runtime.validation import CommandValidator

from .application import AvuhzApplication, QUERY_READ_CAPABILITY, QueryRouter

def schema_root() -> Path:
    repository_root = Path(__file__).resolve().parents[2] / "contracts/schemas/v1"
    if repository_root.is_dir():
        return repository_root
    try:
        installed_root = Path(str(files("avuhz_contracts").joinpath("schemas", "v1")))
    except (ModuleNotFoundError, TypeError) as error:
        raise RuntimeError("canonical schema catalog is unavailable") from error
    if not installed_root.is_dir():
        raise RuntimeError("canonical schema catalog is unavailable")
    return installed_root


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost"})
_LOCAL_ENVIRONMENTS = frozenset({"LOCAL", "TEST"})
_KNOWN_CAPABILITIES = frozenset({QUERY_READ_CAPABILITY, *(definition.required_capability for definition in COMMANDS.values())})


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class LocalServiceSettings:
    tenant_id: str
    principal_id: str = "service.avuhz-local"
    environment: str = "LOCAL"
    capabilities: frozenset[str] = frozenset()
    host: str = "127.0.0.1"
    port: int = 8080

    def __post_init__(self):
        try:
            if str(uuid.UUID(self.tenant_id)) != self.tenant_id:
                raise ValueError
        except (ValueError, TypeError) as error:
            raise ValueError("canonical local tenant ID is required") from error
        if self.environment not in _LOCAL_ENVIRONMENTS:
            raise ValueError("standalone service is local/test only")
        if self.host not in _LOOPBACK_HOSTS:
            raise ValueError("standalone service must bind loopback")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 0 <= self.port <= 65535:
            raise ValueError("valid local port is required")
        if not self.principal_id or not self.capabilities <= _KNOWN_CAPABILITIES:
            raise ValueError("bounded local service identity is required")

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None):
        values = os.environ if environ is None else environ
        tenant = values.get("AVUHZ_LOCAL_TENANT_ID")
        if not tenant:
            raise ValueError("local tenant configuration is required")
        capabilities = frozenset(filter(None, (part.strip() for part in values.get("AVUHZ_LOCAL_CAPABILITIES", "").split(","))))
        try:
            port = int(values.get("AVUHZ_LOCAL_PORT", "8080"))
        except ValueError as error:
            raise ValueError("valid local port is required") from error
        return cls(
            tenant_id=tenant,
            principal_id=values.get("AVUHZ_LOCAL_PRINCIPAL_ID", "service.avuhz-local"),
            environment=values.get("AVUHZ_SERVICE_ENVIRONMENT", "LOCAL"),
            capabilities=capabilities,
            host=values.get("AVUHZ_LOCAL_HOST", "127.0.0.1"),
            port=port,
        )


class LocalIdentityResolver:
    """Fixed non-human local identity; request payloads/headers cannot widen it."""
    def __init__(self, settings: LocalServiceSettings):
        self.settings = settings

    def resolve(self, authenticated_identity: object):
        now = datetime.now(timezone.utc)
        return TrustedExecutionContext(
            True, self.settings.principal_id, "INTERNAL_SERVICE", self.settings.tenant_id,
            None, self.settings.capabilities, frozenset(), self.settings.environment,
            "avuhz-command-api", "STRONG", False,
            now.isoformat(timespec="seconds").replace("+00:00", "Z"),
            (now + timedelta(hours=1)).isoformat(timespec="seconds").replace("+00:00", "Z"),
        )


class MemoryDataProbe:
    def __init__(self, store):
        self.store = store

    def ready(self):
        return isinstance(self.store, MemoryStore)


class IdentityProbe:
    def __init__(self, resolver):
        self.resolver = resolver

    def ready(self):
        context = self.resolver.resolve(None)
        return bool(context.authenticated and context.tenant_id and context.audience == "avuhz-command-api")


def create_service_application(*, store, uow_factory, identity_resolver, readiness_probes, clock=utc_now, ids=None):
    options = {} if ids is None else {"ids": ids}
    executor = Executor(
        CommandValidator(schema_root()), GuardPipeline(), store,
        clock=clock, uow_factory=uow_factory, **options,
    )
    queries = QueryRouter(store, uow_factory, clock)
    return AvuhzApplication(executor, queries, identity_resolver, readiness_probes)


def create_local_application(settings: LocalServiceSettings, *, store=None):
    store = store or MemoryStore()
    resolver = LocalIdentityResolver(settings)
    return create_service_application(
        store=store,
        uow_factory=UnitOfWork,
        identity_resolver=resolver,
        readiness_probes={"data": MemoryDataProbe(store), "identity": IdentityProbe(resolver)},
    )
