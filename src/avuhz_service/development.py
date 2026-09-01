"""Fail-closed DEVELOPMENT composition for provider resource preparation."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping
from wsgiref.simple_server import make_server

from .composition import create_service_application
from .server import BoundedRequestHandler, ThreadingWSGIServer

DEVELOPMENT_ENVIRONMENT = "DEVELOPMENT"
DEVELOPMENT_HOST = "0.0.0.0"
DEVELOPMENT_DATA_PROJECT_REF = "pwlhruwutoitnieactol"
DEVELOPMENT_DATA_PROJECT_URL = "https://pwlhruwutoitnieactol.supabase.co"
DEVELOPMENT_AUTH_PROJECT_REF = "pwlhruwutoitnieactol"
DEVELOPMENT_AUTH_ISSUER = "https://pwlhruwutoitnieactol.supabase.co/auth/v1"
DEVELOPMENT_SERVICE_AUDIENCE = "audience.avuhz.command-service.development"
DEVELOPMENT_TENANT_BRIDGE = "TrustedExecutionContext.tenant_id -> avuhz.tenant_id"
DEVELOPMENT_RLS_POLICY_REFERENCE = "policy.avuhz.tenant-rls.development.v1"
DEVELOPMENT_COMMAND_SERVICE_IDENTITY = "avuhz_command_service_dev"


@dataclass(frozen=True)
class DevelopmentServiceSettings:
    environment: str
    data_project_ref: str
    data_project_url: str
    auth_project_ref: str
    auth_issuer: str
    service_audience: str
    tenant_bridge: str
    rls_policy_reference: str
    command_service_identity: str
    port: int
    host: str = DEVELOPMENT_HOST

    def __post_init__(self):
        expected = {
            "environment": DEVELOPMENT_ENVIRONMENT,
            "data_project_ref": DEVELOPMENT_DATA_PROJECT_REF,
            "data_project_url": DEVELOPMENT_DATA_PROJECT_URL,
            "auth_project_ref": DEVELOPMENT_AUTH_PROJECT_REF,
            "auth_issuer": DEVELOPMENT_AUTH_ISSUER,
            "service_audience": DEVELOPMENT_SERVICE_AUDIENCE,
            "tenant_bridge": DEVELOPMENT_TENANT_BRIDGE,
            "rls_policy_reference": DEVELOPMENT_RLS_POLICY_REFERENCE,
            "command_service_identity": DEVELOPMENT_COMMAND_SERVICE_IDENTITY,
            "host": DEVELOPMENT_HOST,
        }
        if any(getattr(self, key) != value for key, value in expected.items()):
            raise ValueError("approved development configuration is required")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError("valid development PORT is required")

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None):
        values = os.environ if environ is None else environ
        required = {
            "environment": "AVUHZ_SERVICE_ENVIRONMENT",
            "data_project_ref": "AVUHZ_DATA_PROJECT_REF",
            "data_project_url": "AVUHZ_DATA_PROJECT_URL",
            "auth_project_ref": "AVUHZ_AUTH_PROJECT_REF",
            "auth_issuer": "AVUHZ_AUTH_ISSUER",
            "service_audience": "AVUHZ_SERVICE_AUDIENCE",
            "tenant_bridge": "AVUHZ_TENANT_BRIDGE",
            "rls_policy_reference": "AVUHZ_RLS_POLICY_REFERENCE",
            "command_service_identity": "AVUHZ_COMMAND_SERVICE_IDENTITY",
        }
        if any(not values.get(name) for name in required.values()) or not values.get("PORT"):
            raise ValueError("complete development configuration is required")
        try:
            port = int(values["PORT"])
        except ValueError as error:
            raise ValueError("valid development PORT is required") from error
        return cls(**{key: values[name] for key, name in required.items()}, port=port)


class _UnavailableProbe:
    def ready(self):
        return False


class _ConfiguredProbe:
    def ready(self):
        return True


class _UnavailableIdentityResolver:
    def resolve(self, authenticated_identity: object):
        raise PermissionError("trusted development identity dependency is unavailable")


class _UnavailableStore:
    pass


class _UnavailableUnitOfWork:
    def __init__(self, *_args, **_kwargs):
        raise RuntimeError("development data dependency is unavailable")


def create_development_application(settings: DevelopmentServiceSettings):
    # Settings bind this composition to approved non-secret DEVELOPMENT references.
    # Provider adapters are deliberately not created here.
    store = _UnavailableStore()
    return create_service_application(
        store=store,
        uow_factory=_UnavailableUnitOfWork,
        identity_resolver=_UnavailableIdentityResolver(),
        readiness_probes={
            "configuration": _ConfiguredProbe(),
            "data": _UnavailableProbe(),
            "identity": _UnavailableProbe(),
        },
    )


def create_development_http_server(application, host=DEVELOPMENT_HOST, port=8080):
    if host != DEVELOPMENT_HOST:
        raise ValueError("DEVELOPMENT service must bind 0.0.0.0")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("valid development port is required")
    return make_server(
        host,
        port,
        application,
        server_class=ThreadingWSGIServer,
        handler_class=BoundedRequestHandler,
    )


def serve_development(application, host=DEVELOPMENT_HOST, port=8080):
    server = create_development_http_server(application, host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main():
    try:
        settings = DevelopmentServiceSettings.from_environment()
        application = create_development_application(settings)
    except (RuntimeError, ValueError):
        raise SystemExit("Avuhz development service configuration is invalid") from None
    try:
        serve_development(application, settings.host, settings.port)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
