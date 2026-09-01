"""Focused fail-closed DEVELOPMENT service and Render packaging tests."""
from __future__ import annotations

import io
import json
import sys
import threading
import tomllib
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.application import StaticTrustedIdentityResolver
from avuhz_service.composition import LocalIdentityResolver, LocalServiceSettings
from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_DATA_PROJECT_REF,
    DevelopmentServiceSettings,
    create_development_application,
    create_development_http_server,
    main,
)


def environment():
    return {
        "AVUHZ_SERVICE_ENVIRONMENT": "DEVELOPMENT",
        "AVUHZ_DATA_PROJECT_REF": "pwlhruwutoitnieactol",
        "AVUHZ_DATA_PROJECT_URL": "https://pwlhruwutoitnieactol.supabase.co",
        "AVUHZ_AUTH_PROJECT_REF": "pwlhruwutoitnieactol",
        "AVUHZ_AUTH_ISSUER": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        "AVUHZ_SERVICE_AUDIENCE": "audience.avuhz.command-service.development",
        "AVUHZ_TENANT_BRIDGE": "TrustedExecutionContext.tenant_id -> avuhz.tenant_id",
        "AVUHZ_RLS_POLICY_REFERENCE": "policy.avuhz.tenant-rls.development.v1",
        "AVUHZ_COMMAND_SERVICE_IDENTITY": "avuhz_command_service_dev",
        "PORT": "10000",
    }


def call(application, method, path, payload=None):
    body = b"" if payload is None else json.dumps(payload).encode()
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_TYPE": "application/json" if payload is not None else "",
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
    }
    captured = {}

    def start_response(status, headers):
        captured["status"] = int(status.split()[0])
        captured["headers"] = dict(headers)

    response = b"".join(application(environ, start_response))
    return captured["status"], json.loads(response), captured["headers"]


class DevelopmentServiceTests(unittest.TestCase):
    def test_settings_require_exact_approved_nonsecret_configuration_and_render_port(self):
        settings = DevelopmentServiceSettings.from_environment(environment())
        self.assertEqual((settings.host, settings.port), ("0.0.0.0", 10000))
        self.assertEqual(settings.data_project_ref, DEVELOPMENT_DATA_PROJECT_REF)
        self.assertEqual(settings.auth_issuer, DEVELOPMENT_AUTH_ISSUER)
        for key in environment():
            invalid = environment()
            invalid.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                DevelopmentServiceSettings.from_environment(invalid)
        for key, value in (
            ("AVUHZ_SERVICE_ENVIRONMENT", "STAGING"),
            ("AVUHZ_DATA_PROJECT_REF", "unapproved-project"),
            ("AVUHZ_AUTH_ISSUER", "https://example.invalid/auth/v1"),
            ("PORT", "0"),
        ):
            invalid = environment()
            invalid[key] = value
            with self.subTest(invalid=key), self.assertRaises(ValueError):
                DevelopmentServiceSettings.from_environment(invalid)

    def test_local_adapter_boundary_is_unchanged_and_rejected_for_development(self):
        local = LocalServiceSettings(tenant_id="00000000-0000-4000-8000-000000000001")
        self.assertEqual((local.environment, local.host), ("LOCAL", "127.0.0.1"))
        with self.assertRaises(ValueError):
            LocalServiceSettings(tenant_id=local.tenant_id, environment="DEVELOPMENT")
        with self.assertRaises(ValueError):
            LocalServiceSettings(tenant_id=local.tenant_id, host="0.0.0.0")
        development_source = (ROOT / "src/avuhz_service/development.py").read_text()
        self.assertNotIn("LocalIdentityResolver", development_source)
        self.assertNotIn("StaticTrustedIdentityResolver", development_source)

    def test_unconfigured_dependencies_allow_health_but_deny_readiness_and_routes(self):
        app = create_development_application(DevelopmentServiceSettings.from_environment(environment()))
        for path, expected in (("/health/startup", "started"), ("/health/live", "alive")):
            status, value, headers = call(app, "GET", path)
            self.assertEqual((status, value["status"]), (200, expected))
            self.assertEqual(headers["Cache-Control"], "no-store")
        status, value, _ = call(app, "GET", "/health/ready")
        self.assertEqual((status, value), (503, {
            "status": "not_ready",
            "checks": {"configuration": "ready", "data": "unavailable", "identity": "unavailable"},
        }))
        self.assertEqual(call(app, "POST", "/v1/commands", {})[:2], (401, {"error": "trusted_identity_required"}))
        self.assertEqual(call(app, "POST", "/v1/queries", {})[:2], (401, {"error": "trusted_identity_required"}))
        self.assertNotIsInstance(app.identity_resolver, (LocalIdentityResolver, StaticTrustedIdentityResolver))

    def test_fail_closed_composition_still_uses_existing_governed_runtime(self):
        app = create_development_application(DevelopmentServiceSettings.from_environment(environment()))
        self.assertEqual(type(app.command_executor).__name__, "Executor")
        self.assertEqual(type(app.query_router).__name__, "QueryRouter")
        self.assertEqual(call(app, "GET", "/health/ready")[0], 503)

    def test_development_server_binds_all_interfaces_only_and_main_uses_render_port(self):
        app = create_development_application(DevelopmentServiceSettings.from_environment(environment()))
        server = create_development_http_server(app, "0.0.0.0", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/health/live", timeout=3) as response:
                self.assertEqual((response.status, json.loads(response.read())["status"]), (200, "alive"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
        with self.assertRaises(ValueError):
            create_development_http_server(app, "127.0.0.1", 0)
        captured = {}

        def fake_serve(application, host, port):
            captured.update(application=application, host=host, port=port)

        with patch("avuhz_service.development.os.environ", environment()), patch(
            "avuhz_service.development.serve_development", side_effect=fake_serve,
        ):
            self.assertEqual(main(), 0)
        self.assertEqual((captured["host"], captured["port"]), ("0.0.0.0", 10000))

    def test_packaging_and_documented_render_commands_are_exact(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        self.assertEqual(
            project["project"]["scripts"]["avuhz-service-development"],
            "avuhz_service.development:main",
        )
        development_source = (ROOT / "src/avuhz_service/development.py").read_text()
        self.assertNotIn("AVUHZ_LOCAL_", development_source)
        self.assertNotIn("create_local_application", development_source)
        readme = (ROOT / "README.md").read_text()
        for value in (
            "python -m pip install .",
            "avuhz-service-development",
            "/health/live",
            "readiness remains `503`",
            "No provider connection or mutation is performed",
        ):
            self.assertIn(value, readme)


if __name__ == "__main__":
    unittest.main()
