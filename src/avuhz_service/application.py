"""Bounded WSGI command/query and health adapter for the governed runtime."""
from __future__ import annotations

import json
import re
import uuid
from http import HTTPStatus
from typing import Mapping, Protocol

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.phase5d_authorization import ImplementationAuthorizationReadService
from avuhz_runtime.phase5d_brief import ImplementationBriefReadService
from avuhz_runtime.phase5d_build_execution import BuildExecutionResultReadService
from avuhz_runtime.phase5d_client_acceptance import ClientAcceptanceReadService
from avuhz_runtime.phase5d_deployment_authorization import DeploymentAuthorizationReadService
from avuhz_runtime.phase5d_deployment_execution import DeploymentExecutionReadService
from avuhz_runtime.phase5d_deployment_verification import DeploymentVerificationReadService
from avuhz_runtime.phase5d_package import CodexBuildPackageReadService
from avuhz_runtime.phase5d_qa_result import QAResultReadService

MAX_REQUEST_BYTES = 1024 * 1024
QUERY_READ_CAPABILITY = "engagement:read"
_SAFE_CHECK_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


class ReadinessProbe(Protocol):
    def ready(self) -> bool: ...


class TrustedIdentityResolver(Protocol):
    def resolve(self, authenticated_identity: object) -> TrustedExecutionContext: ...


class RequestError(ValueError):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


class QueryRequestError(ValueError):
    pass


class AccessDenied(PermissionError):
    pass


class StaticTrustedIdentityResolver:
    """Test/local composition boundary; HTTP fields never alter the context."""
    def __init__(self, context: TrustedExecutionContext):
        self.context = context

    def resolve(self, authenticated_identity: object) -> TrustedExecutionContext:
        return self.context


class QueryRouter:
    """Allowlisted read-only dispatcher over existing tenant-scoped read services."""
    VERSIONED = frozenset({
        "implementation_brief_readiness",
        "implementation_authorization_status",
        "codex_build_package_readiness",
        "client_acceptance_status",
        "deployment_authorization_status",
    })
    UNVERSIONED = frozenset({
        "build_execution_status",
        "qa_result_status",
        "deployment_execution_status",
        "deployment_verification_status",
    })

    def __init__(self, store, uow_factory, clock):
        self.store = store
        self.uow_factory = uow_factory
        self.clock = clock

    @classmethod
    def _validate(cls, request: object):
        if not isinstance(request, dict):
            raise QueryRequestError("query request must be an object")
        if not set(request) <= {"query_type", "subject_id", "subject_version"}:
            raise QueryRequestError("query request contains unsupported fields")
        query_type = request.get("query_type")
        if query_type not in cls.VERSIONED | cls.UNVERSIONED:
            raise QueryRequestError("query type is not registered")
        subject_id = request.get("subject_id")
        try:
            if not isinstance(subject_id, str) or str(uuid.UUID(subject_id)) != subject_id:
                raise ValueError
        except ValueError as error:
            raise QueryRequestError("subject identity is invalid") from error
        version = request.get("subject_version")
        if query_type in cls.VERSIONED:
            if isinstance(version, bool) or not isinstance(version, int) or version < 1:
                raise QueryRequestError("positive subject version is required")
        elif "subject_version" in request:
            raise QueryRequestError("subject version is not accepted for this query")
        return query_type, subject_id, version

    def execute(self, request: object, context: TrustedExecutionContext):
        query_type, subject_id, version = self._validate(request)
        generated_at = self.clock()
        if not context.authenticated or not context.principal_id or not context.tenant_id:
            raise PermissionError("trusted identity is required")
        if context.audience != "avuhz-command-api" or not context.environment:
            raise PermissionError("trusted identity boundary is invalid")
        if context.expires_at and context.expires_at <= generated_at:
            raise PermissionError("trusted identity is expired")
        if QUERY_READ_CAPABILITY not in context.capabilities:
            raise AccessDenied("trusted query capability is required")
        uow = self.uow_factory(self.store)
        try:
            if hasattr(uow, "bind_trusted_context"):
                uow.bind_trusted_context(context)
            tenant = context.tenant_id
            if query_type == "implementation_brief_readiness":
                return ImplementationBriefReadService(uow).readiness(tenant, subject_id, version, generated_at)
            if query_type == "implementation_authorization_status":
                return ImplementationAuthorizationReadService(uow).status(tenant, subject_id, version, generated_at)
            if query_type == "codex_build_package_readiness":
                return CodexBuildPackageReadService(uow).readiness(tenant, subject_id, version, generated_at)
            if query_type == "build_execution_status":
                return BuildExecutionResultReadService(uow).status(tenant, subject_id, generated_at)
            if query_type == "qa_result_status":
                return QAResultReadService(uow).status(tenant, subject_id, generated_at)
            if query_type == "client_acceptance_status":
                return ClientAcceptanceReadService(uow).status(tenant, subject_id, version, generated_at)
            if query_type == "deployment_authorization_status":
                return DeploymentAuthorizationReadService(uow).status(tenant, subject_id, version, generated_at)
            if query_type == "deployment_execution_status":
                return DeploymentExecutionReadService(uow).status(tenant, subject_id, generated_at)
            if query_type == "deployment_verification_status":
                return DeploymentVerificationReadService(uow).status(tenant, subject_id, generated_at)
            raise QueryRequestError("query type has no read service")
        finally:
            if hasattr(uow, "rollback"):
                uow.rollback()
            if hasattr(uow, "close"):
                uow.close()


class AvuhzApplication:
    """WSGI adapter; mutations have exactly one route into the governed Executor."""
    def __init__(self, command_executor, query_router, identity_resolver, readiness_probes: Mapping[str, ReadinessProbe]):
        self.command_executor = command_executor
        self.query_router = query_router
        self.identity_resolver = identity_resolver
        self.readiness_probes = dict(readiness_probes)
        if not self.readiness_probes or any(not _SAFE_CHECK_NAME.fullmatch(name) for name in self.readiness_probes):
            raise ValueError("bounded readiness probes are required")
        self.started = True

    def __call__(self, environ, start_response):
        try:
            status, payload = self._route(environ)
        except RequestError as error:
            status, payload = error.status, {"error": error.code}
        except QueryRequestError:
            status, payload = 400, {"error": "invalid_query"}
        except AccessDenied:
            status, payload = 403, {"error": "access_denied"}
        except PermissionError:
            status, payload = 401, {"error": "trusted_identity_required"}
        except Exception:
            status, payload = 500, {"error": "internal_error"}
        return self._respond(start_response, status, payload)

    def _route(self, environ):
        method = environ.get("REQUEST_METHOD", "").upper()
        path = environ.get("PATH_INFO", "")
        if path in {"/health/startup", "/health/live", "/health/ready"}:
            if method != "GET":
                raise RequestError(405, "method_not_allowed")
            return self._health(path)
        if path not in {"/v1/commands", "/v1/queries"}:
            raise RequestError(404, "not_found")
        if method != "POST":
            raise RequestError(405, "method_not_allowed")
        request = self._json_request(environ)
        context = self.identity_resolver.resolve(environ.get("avuhz.trusted_identity"))
        if path == "/v1/commands":
            result = self.command_executor.execute(request, context)
            statuses = {"ACCEPTED": 202, "DUPLICATE": 200, "CONFLICT": 409,
                        "VALIDATION_FAILED": 422, "REJECTED": 403}
            return statuses.get(result.get("result"), 500), result
        result = self.query_router.execute(request, context)
        return (200, {"result": result}) if result is not None else (404, {"error": "not_found"})

    def _health(self, path):
        if path == "/health/startup":
            return 200, {"status": "started", "checks": {"runtime": "started"}}
        if path == "/health/live":
            return 200, {"status": "alive", "checks": {"runtime": "alive"}}
        checks = {}
        ready = True
        for name, probe in sorted(self.readiness_probes.items()):
            try:
                available = probe.ready() is True
            except Exception:
                available = False
            checks[name] = "ready" if available else "unavailable"
            ready = ready and available
        return (200 if ready else 503), {"status": "ready" if ready else "not_ready", "checks": checks}

    @staticmethod
    def _json_request(environ):
        content_type = environ.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise RequestError(415, "json_content_type_required")
        raw_length = environ.get("CONTENT_LENGTH", "")
        try:
            length = int(raw_length)
        except (TypeError, ValueError) as error:
            raise RequestError(411, "content_length_required") from error
        if length < 1:
            raise RequestError(400, "invalid_json")
        if length > MAX_REQUEST_BYTES:
            raise RequestError(413, "request_too_large")
        body = environ["wsgi.input"].read(length)
        try:
            request = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RequestError(400, "invalid_json") from error
        if not isinstance(request, dict):
            raise RequestError(400, "json_object_required")
        return request

    @staticmethod
    def _respond(start_response, status, payload):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        start_response(
            f"{status} {HTTPStatus(status).phrase}",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body))),
             ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff")],
        )
        return [body]
