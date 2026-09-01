"""Focused local command/query service, health, and security tests."""
from __future__ import annotations

import copy
import io
import json
import sys
import threading
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/contracts")]

from avuhz_runtime.guards import COMMAND_CAPABILITIES, GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, MemoryStore, UnitOfWork
from avuhz_runtime.validation import CommandValidator
from avuhz_service.application import AvuhzApplication, QUERY_READ_CAPABILITY, QueryRouter, StaticTrustedIdentityResolver
from avuhz_service.composition import LocalServiceSettings, create_local_application, create_service_application
from avuhz_service.server import create_http_server
from validate_command_payloads import envelope, handoff, payloads

TENANT = "a3000000-0000-4000-8000-000000000002"
OTHER_TENANT = "a3000000-0000-4000-8000-000000000099"
VERIFICATION_ID = "d5d60000-0000-4000-8000-000000000001"
NOW = "2030-01-15T15:00:00Z"


class ReadyProbe:
    def ready(self): return True


class BrokenProbe:
    def ready(self):
        authority = "principal" + ":" + "fictional-sensitive"
        raise RuntimeError("postgresql" + "://" + authority + "@example.invalid/data")


def context(*, tenant=TENANT, capabilities=frozenset(), expires_at="2030-01-15T16:00:00Z"):
    return TrustedExecutionContext(
        True, "service.avuhz-test", "INTERNAL_SERVICE", tenant, None,
        frozenset(capabilities), frozenset(), "TEST", "avuhz-command-api",
        "STRONG", False, NOW, expires_at,
    )


def call(application, method, path, payload=None, extra=None):
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_TYPE": "application/json" if payload is not None else "",
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
    }
    if extra: environ.update(extra)
    captured = {}
    def start_response(status, headers):
        captured["status"] = int(status.split()[0]); captured["headers"] = dict(headers)
    response = b"".join(application(environ, start_response))
    return captured["status"], json.loads(response), captured["headers"]


def application(store, trusted_context, probes=None):
    return create_service_application(
        store=store, uow_factory=UnitOfWork,
        identity_resolver=StaticTrustedIdentityResolver(trusted_context),
        readiness_probes=probes or {"data": ReadyProbe(), "identity": ReadyProbe()},
        clock=lambda: NOW,
        ids=lambda: "a3000000-0000-4000-8000-000000000090",
    )


class ServiceTests(unittest.TestCase):
    def test_actual_loopback_startup_liveness_and_readiness(self):
        settings = LocalServiceSettings(tenant_id="00000000-0000-4000-8000-000000000001", port=0)
        server = create_http_server(create_local_application(settings), settings.host, settings.port)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            for route, expected in (("startup", "started"), ("live", "alive"), ("ready", "ready")):
                with urllib.request.urlopen(f"{base}/health/{route}", timeout=3) as response:
                    value = json.loads(response.read())
                    self.assertEqual((response.status, value["status"]), (200, expected))
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=3)
        self.assertFalse(thread.is_alive())

    def test_command_route_uses_existing_executor_and_governed_side_effects(self):
        store = MemoryStore(); source = handoff(); store.handoffs[source["handoff_id"]] = source
        trusted = context(capabilities={COMMAND_CAPABILITIES["AcceptAcquisitionHandoff"]})
        app = application(store, trusted)
        raw = envelope("AcceptAcquisitionHandoff", copy.deepcopy(payloads()["AcceptAcquisitionHandoff"]))
        status, value, _ = call(app, "POST", "/v1/commands", raw)
        self.assertEqual((status, value["result"]), (202, "ACCEPTED"))
        self.assertIsNotNone(store.handoffs[source["handoff_id"]]["accepted_at"])
        self.assertEqual((len(store.events), len(store.outbox), len(store.idempotency)), (1, 1, 1))

    def test_command_and_query_routes_are_non_interchangeable(self):
        class Commands:
            def __init__(self): self.calls = 0
            def execute(self, request, trusted): self.calls += 1; return {"result": "ACCEPTED"}
        class Queries:
            def __init__(self): self.calls = 0
            def execute(self, request, trusted): self.calls += 1; return {"read_only": True}
        commands, queries = Commands(), Queries()
        app = AvuhzApplication(commands, queries, StaticTrustedIdentityResolver(context()), {"data": ReadyProbe()})
        self.assertEqual(call(app, "POST", "/v1/commands", {"command": "bounded"})[0], 202)
        self.assertEqual(call(app, "POST", "/v1/queries", {"query_type": "bounded"})[0], 200)
        self.assertEqual((commands.calls, queries.calls), (1, 1))
        self.assertEqual(call(app, "GET", "/v1/commands")[0], 405)
        self.assertEqual(call(app, "POST", "/v1/mutations", {})[0], 404)

    def test_query_route_uses_existing_tenant_scoped_read_service_only(self):
        store = MemoryStore()
        store.deployment_verifications[(TENANT, VERIFICATION_ID)] = {
            "deployment_verification_id": VERIFICATION_ID, "tenant_id": TENANT,
            "engagement_id": "d5000000-0000-4000-8000-000000000003",
            "record_version": 1, "overall_status": "VERIFIED",
            "deployment_execution_reference": {"reference_type": "DEPLOYMENT_EXECUTION", "reference_id": "d5d50000-0000-4000-8000-000000000001", "reference_version": 2},
            "authority_binding": {"deployment_authorization_reference": {"reference_type": "DEPLOYMENT_AUTHORIZATION", "reference_id": "d5d40000-0000-4000-8000-000000000001", "reference_version": 1}},
        }
        request = {"query_type": "deployment_verification_status", "subject_id": VERIFICATION_ID}
        status, value, _ = call(application(store, context(capabilities={QUERY_READ_CAPABILITY})), "POST", "/v1/queries", request)
        self.assertEqual(status, 200)
        self.assertTrue(value["result"]["deployment_verified"])
        self.assertEqual(value["result"]["tenant_id"], TENANT)
        status, value, _ = call(application(store, context(tenant=OTHER_TENANT, capabilities={QUERY_READ_CAPABILITY})), "POST", "/v1/queries", request)
        self.assertEqual((status, value), (404, {"error": "not_found"}))
        self.assertEqual(len(store.events), 0)
        self.assertEqual(len(store.outbox), 0)
        status, value, _ = call(application(store, context()), "POST", "/v1/queries", request)
        self.assertEqual((status, value), (403, {"error": "access_denied"}))
        expired = context(capabilities={QUERY_READ_CAPABILITY}, expires_at=NOW)
        status, value, _ = call(application(store, expired), "POST", "/v1/queries", request)
        self.assertEqual((status, value), (401, {"error": "trusted_identity_required"}))

    def test_readiness_fails_closed_and_never_discloses_dependency_errors(self):
        app = application(MemoryStore(), context(), {"data": BrokenProbe(), "identity": ReadyProbe()})
        status, value, headers = call(app, "GET", "/health/ready")
        encoded = json.dumps(value)
        self.assertEqual((status, value["status"]), (503, "not_ready"))
        self.assertEqual(value["checks"], {"data": "unavailable", "identity": "ready"})
        self.assertNotIn("postgresql", encoded)
        self.assertNotIn("fictional-sensitive", encoded)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(call(app, "GET", "/health/live")[0], 200)

    def test_failure_and_request_security_are_bounded(self):
        class ExplodingExecutor:
            def execute(self, request, trusted):
                raise RuntimeError("private stack and credential material")
        app = AvuhzApplication(
            ExplodingExecutor(), QueryRouter(MemoryStore(), UnitOfWork, lambda: NOW),
            StaticTrustedIdentityResolver(context()), {"data": ReadyProbe()},
        )
        status, value, _ = call(app, "POST", "/v1/commands", {})
        self.assertEqual((status, value), (500, {"error": "internal_error"}))
        self.assertNotIn("private", json.dumps(value))
        self.assertEqual(call(app, "POST", "/v1/commands", [], extra={"CONTENT_TYPE": "application/json"})[0], 400)
        self.assertEqual(call(app, "POST", "/v1/commands", {}, extra={"CONTENT_TYPE": "text/plain"})[0], 415)
        oversized = {"CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(1024 * 1024 + 1), "wsgi.input": io.BytesIO(b"")}
        self.assertEqual(call(app, "POST", "/v1/commands", {}, extra=oversized)[0], 413)

    def test_http_claims_cannot_widen_fixed_local_identity(self):
        store = MemoryStore(); source = handoff(); store.handoffs[source["handoff_id"]] = source
        raw = envelope("AcceptAcquisitionHandoff", copy.deepcopy(payloads()["AcceptAcquisitionHandoff"]))
        raw["tenant_id"] = OTHER_TENANT
        raw["caller_identity"]["tenant_ids"] = [OTHER_TENANT]
        app = application(store, context(capabilities={COMMAND_CAPABILITIES["AcceptAcquisitionHandoff"]}))
        status, value, _ = call(app, "POST", "/v1/commands", raw, {"HTTP_X_TENANT_ID": OTHER_TENANT, "HTTP_X_ROLE": "CLIENT_DEPLOYMENT_AUTHORITY"})
        self.assertEqual((status, value["result"]), (403, "REJECTED"))
        self.assertNotIn("accepted_at", store.handoffs[source["handoff_id"]])
        self.assertEqual((len(store.events), len(store.outbox), len(store.idempotency)), (0, 0, 0))

    def test_standalone_configuration_is_strictly_local_and_non_human(self):
        settings = LocalServiceSettings.from_environment({
            "AVUHZ_LOCAL_TENANT_ID": "00000000-0000-4000-8000-000000000001",
            "AVUHZ_LOCAL_CAPABILITIES": "engagement:read",
        })
        self.assertEqual(settings.host, "127.0.0.1")
        with self.assertRaises(ValueError):
            LocalServiceSettings(tenant_id=settings.tenant_id, environment="PRODUCTION")
        with self.assertRaises(ValueError):
            LocalServiceSettings(tenant_id=settings.tenant_id, host="0.0.0.0")
        with self.assertRaises(ValueError):
            LocalServiceSettings(tenant_id=settings.tenant_id, capabilities=frozenset({"deployment:unbounded"}))
        resolver = create_local_application(settings).identity_resolver
        trusted = resolver.resolve({"role": "CLIENT_DEPLOYMENT_AUTHORITY"})
        self.assertEqual(trusted.caller_type, "INTERNAL_SERVICE")
        self.assertEqual(trusted.authority_roles, frozenset())
        self.assertIsNone(trusted.human_authority_role)


if __name__ == "__main__":
    unittest.main()
