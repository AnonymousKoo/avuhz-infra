from __future__ import annotations

import ast
import io
import json
import urllib.error
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from avuhz_engineering import development_auth_provider_read_diagnostic as diagnostic
from avuhz_engineering.provider_read_http import MAX_PROVIDER_RESPONSE_BYTES


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ONLY_CREDENTIAL = "fixture-runtime-only-provider-read-material"


class FakeResponse:
    def __init__(
        self,
        status: int,
        payload: object | None = None,
        *,
        raw: bytes | None = None,
    ) -> None:
        self.status = status
        self._body = raw if raw is not None else json.dumps(payload).encode("utf-8")
        self.read_calls = 0

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self, limit: int = -1) -> bytes:
        self.read_calls += 1
        return self._body if limit < 0 else self._body[:limit]


class UnreadableErrorBody:
    def __init__(self) -> None:
        self.read_calls = 0

    def read(self, limit: int = -1) -> bytes:
        self.read_calls += 1
        raise AssertionError("provider failure body must never be read")

    def close(self) -> None:
        return None


class DevelopmentAuthProviderReadDiagnosticV1Tests(unittest.TestCase):
    def valid_project(self) -> dict[str, str]:
        return {
            "id": diagnostic.DEVELOPMENT_AUTH_PROJECT_REF,
            "ref": diagnostic.DEVELOPMENT_AUTH_PROJECT_REF,
            "name": diagnostic.DEVELOPMENT_AUTH_PROJECT_NAME,
        }

    def inspect_with(self, response: FakeResponse):
        requests = []

        def urlopen(request, timeout):
            requests.append((request, timeout))
            return response

        result = diagnostic.inspect_development_auth_project_metadata(
            read_token=RUNTIME_ONLY_CREDENTIAL,
            urlopen=urlopen,
        )
        return result, requests

    def test_exact_valid_development_auth_response_uses_one_get(self) -> None:
        result, requests = self.inspect_with(FakeResponse(200, self.valid_project()))
        self.assertEqual(
            result.classification,
            diagnostic.ProjectReadClassification.PROJECT_READ_OK,
        )
        self.assertEqual(len(requests), 1)
        request, timeout = requests[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, diagnostic.PROJECT_READ_URL)
        self.assertIsNone(request.data)
        self.assertEqual(timeout, 30)

    def test_wrong_project_fields_fail_closed(self) -> None:
        for field, value in (
            ("id", "wrong-project"),
            ("ref", "wrong-project"),
            ("name", "WRONG NAME"),
        ):
            with self.subTest(field=field):
                payload = self.valid_project()
                payload[field] = value
                response = FakeResponse(200, payload)
                calls = []

                def urlopen(request, timeout):
                    calls.append(request)
                    return response

                with self.assertRaises(
                    diagnostic.SafeProviderReadDiagnosticStop
                ) as raised:
                    diagnostic.inspect_development_auth_project_metadata(
                        read_token=RUNTIME_ONLY_CREDENTIAL,
                        urlopen=urlopen,
                    )
                self.assertEqual(raised.exception.code, "PROJECT_READ_MISMATCH")
                self.assertEqual(len(calls), 1)

    def test_http_statuses_have_exact_safe_classifications(self) -> None:
        cases = (
            (401, "PROJECT_READ_AUTHENTICATION_REJECTED"),
            (403, "PROJECT_READ_FORBIDDEN"),
            (404, "PROJECT_READ_NOT_FOUND"),
            (429, "PROJECT_READ_RATE_LIMITED"),
            (500, "PROJECT_READ_PROVIDER_FAILURE"),
            (503, "PROJECT_READ_PROVIDER_FAILURE"),
            (418, "PROJECT_READ_UNEXPECTED_STATUS"),
        )
        for status, expected_code in cases:
            with self.subTest(status=status):
                response = FakeResponse(
                    status,
                    {"private_provider_body": "must-not-escape"},
                )
                with self.assertRaises(
                    diagnostic.SafeProviderReadDiagnosticStop
                ) as raised:
                    diagnostic.inspect_development_auth_project_metadata(
                        read_token=RUNTIME_ONLY_CREDENTIAL,
                        urlopen=lambda request, timeout: response,
                    )
                self.assertEqual(raised.exception.code, expected_code)
                self.assertEqual(response.read_calls, 0)
                self.assertNotIn("private_provider_body", repr(raised.exception))

    def test_transport_failures_hide_arbitrary_exception_text(self) -> None:
        for failure in (
            TimeoutError("private timeout detail"),
            urllib.error.URLError("private dns detail"),
            ConnectionError("private connection detail"),
        ):
            with self.subTest(failure_type=type(failure).__name__):
                def urlopen(request, timeout):
                    raise failure

                with self.assertRaises(
                    diagnostic.SafeProviderReadDiagnosticStop
                ) as raised:
                    diagnostic.inspect_development_auth_project_metadata(
                        read_token=RUNTIME_ONLY_CREDENTIAL,
                        urlopen=urlopen,
                    )
                self.assertEqual(
                    raised.exception.code,
                    "PROJECT_READ_REQUEST_FAILED",
                )
                self.assertNotIn("private", repr(raised.exception))

    def test_invalid_accepted_responses_fail_closed(self) -> None:
        invalid_responses = (
            FakeResponse(200, raw=b""),
            FakeResponse(200, raw=b"{not-json"),
            FakeResponse(200, raw=b"x" * (MAX_PROVIDER_RESPONSE_BYTES + 1)),
            FakeResponse(200, ["not", "a", "project"]),
        )
        for response in invalid_responses:
            with self.subTest(body_size=len(response._body)):
                with self.assertRaises(
                    diagnostic.SafeProviderReadDiagnosticStop
                ) as raised:
                    diagnostic.inspect_development_auth_project_metadata(
                        read_token=RUNTIME_ONLY_CREDENTIAL,
                        urlopen=lambda request, timeout: response,
                    )
                self.assertEqual(
                    raised.exception.code,
                    "PROJECT_READ_RESPONSE_INVALID",
                )
                self.assertEqual(response.read_calls, 1)

    def test_http_error_body_is_never_read(self) -> None:
        body = UnreadableErrorBody()
        error = urllib.error.HTTPError(
            diagnostic.PROJECT_READ_URL,
            403,
            "private provider reason",
            {},
            body,
        )

        def urlopen(request, timeout):
            raise error

        with self.assertRaises(
            diagnostic.SafeProviderReadDiagnosticStop
        ) as raised:
            diagnostic.inspect_development_auth_project_metadata(
                read_token=RUNTIME_ONLY_CREDENTIAL,
                urlopen=urlopen,
            )
        self.assertEqual(raised.exception.code, "PROJECT_READ_FORBIDDEN")
        self.assertEqual(body.read_calls, 0)
        self.assertNotIn("private provider reason", repr(raised.exception))

    def test_token_header_and_provider_body_never_appear_in_output(self) -> None:
        provider_marker = "private-provider-body-marker"
        response = FakeResponse(401, {"detail": provider_marker})
        output = io.StringIO()
        with (
            redirect_stdout(output),
            redirect_stderr(output),
            self.assertRaises(
                diagnostic.SafeProviderReadDiagnosticStop
            ) as raised,
        ):
            diagnostic.inspect_development_auth_project_metadata(
                read_token=RUNTIME_ONLY_CREDENTIAL,
                urlopen=lambda request, timeout: response,
            )
        rendered = output.getvalue() + str(raised.exception) + repr(raised.exception)
        self.assertNotIn(RUNTIME_ONLY_CREDENTIAL, rendered)
        self.assertNotIn("Authorization", rendered)
        self.assertNotIn(provider_marker, rendered)
        self.assertEqual(response.read_calls, 0)

    def test_success_evidence_is_sanitized(self) -> None:
        result, _ = self.inspect_with(FakeResponse(200, self.valid_project()))
        evidence = diagnostic.sanitized_project_read_evidence(
            result,
            plan_id="205c2cef-1b90-4346-b4eb-d19ded202d6a",
            plan_digest="sha256:" + "a" * 64,
        )
        rendered = json.dumps(evidence, sort_keys=True)
        self.assertEqual(evidence["diagnostic_classification"], "PROJECT_READ_OK")
        self.assertEqual(evidence["provider_request_count"], 1)
        self.assertFalse(evidence["sql_session_inspection_attempted"])
        self.assertFalse(evidence["provider_mutation_attempted"])
        self.assertNotIn(RUNTIME_ONLY_CREDENTIAL, rendered)
        self.assertNotIn("Authorization", rendered)

    def test_exactly_one_network_request_is_structurally_reachable(self) -> None:
        http_source = (
            ROOT / "src/avuhz_engineering/provider_read_http.py"
        ).read_text(encoding="utf-8")
        diagnostic_source = (
            ROOT
            / "src/avuhz_engineering/development_auth_provider_read_diagnostic.py"
        ).read_text(encoding="utf-8")
        executor_source = (
            ROOT / "scripts/development_auth_provider_read_diagnostic_v1.py"
        ).read_text(encoding="utf-8")

        http_tree = ast.parse(http_source)
        diagnostic_tree = ast.parse(diagnostic_source)
        executor_tree = ast.parse(executor_source)
        urlopen_calls = [
            node
            for node in ast.walk(http_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "urlopen"
        ]
        request_json_calls = [
            node
            for node in ast.walk(diagnostic_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "request_json"
        ]
        diagnostic_calls = [
            node
            for node in ast.walk(executor_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "inspect_development_auth_project_metadata"
        ]
        self.assertEqual(len(urlopen_calls), 1)
        self.assertEqual(len(request_json_calls), 1)
        self.assertEqual(len(diagnostic_calls), 1)

    def test_sql_session_and_mutation_paths_are_structurally_absent(self) -> None:
        paths = (
            ROOT
            / "src/avuhz_engineering/development_auth_provider_read_diagnostic.py",
            ROOT / "src/avuhz_engineering/provider_read_http.py",
            ROOT / "scripts/development_auth_provider_read_diagnostic_v1.py",
            ROOT
            / ".github/workflows/development-auth-provider-read-diagnostic-v1.yml",
        )
        surface = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        for forbidden in (
            "/database/query/read-only",
            "auth.sessions",
            "auth.refresh_tokens",
            "/auth/v1/admin",
            "/auth/v1/logout",
            "request_local_session_logout",
            "run_recovery_session_lifecycle",
            "SUPABASE_AUTH_ADMIN_EPHEMERAL",
            "service_role",
        ):
            self.assertNotIn(forbidden, surface)

        plan = json.loads(
            (
                ROOT
                / "contracts/plans/v1/development-auth-provider-read-diagnostic-v1.plan.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(len(plan["steps"]), 1)
        self.assertEqual(plan["steps"][0]["execution_class"], "PROVIDER_READ")
        for prohibited in (
            "database.query",
            "sql.execute",
            "session.inspect",
            "provider.mutation",
            "credential.create",
            "credential.rotate",
            "data.operation",
            "render.operation",
            "n8n.operation",
            "staging.target",
            "production.target",
            "v32.retry",
            "v33.prepare",
        ):
            self.assertIn(prohibited, plan["prohibited_actions"])
            self.assertIn(prohibited, plan["steps"][0]["prohibited_actions"])


if __name__ == "__main__":
    unittest.main()
