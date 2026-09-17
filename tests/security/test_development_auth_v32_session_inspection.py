from __future__ import annotations

import hashlib
import io
import json
import re
import urllib.error
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from avuhz_engineering import development_auth_session_inspection as inspection


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_SUBJECT = "11111111-1111-4111-8111-111111111111"
UNEXPECTED_SUBJECT = "22222222-2222-4222-8222-222222222222"


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _boundary() -> dict:
    return {
        "row_kind": "BOUNDARY",
        "read_only_identity_ok": True,
        "state_kind": None,
        "provider_subject": None,
    }


def _state(kind: str, subject: str = EXPECTED_SUBJECT) -> dict:
    return {
        "row_kind": "STATE",
        "read_only_identity_ok": True,
        "state_kind": kind,
        "provider_subject": subject,
    }


def _payload(*rows: dict) -> dict:
    return {"result": [_boundary(), *rows]}


class FakeResponse:
    def __init__(self, status: int, payload: object) -> None:
        self.status = status
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self, limit: int = -1) -> bytes:
        return self._body if limit < 0 else self._body[:limit]


class DevelopmentAuthV32SessionInspectionTests(unittest.TestCase):
    def classify(self, *rows: dict) -> inspection.SessionInspectionResult:
        return inspection.classify_session_state(
            _payload(*rows),
            expected_subject_digest=_digest(EXPECTED_SUBJECT),
        )

    def test_exact_zero_zero_is_clean(self) -> None:
        result = self.classify()
        self.assertEqual(result.classification, inspection.InspectionClassification.CLEAN_0_0)
        self.assertEqual((result.session_count, result.refresh_token_count), (0, 0))
        self.assertIsNone(result.expected_subject_binding_verified)

    def test_expected_identity_session_only(self) -> None:
        result = self.classify(_state("SESSION"))
        self.assertEqual(result.classification, inspection.InspectionClassification.SESSION_PRESENT)
        self.assertEqual((result.session_count, result.refresh_token_count), (1, 0))
        self.assertTrue(result.expected_subject_binding_verified)

    def test_expected_identity_refresh_only(self) -> None:
        result = self.classify(_state("REFRESH_TOKEN"))
        self.assertEqual(
            result.classification,
            inspection.InspectionClassification.REFRESH_TOKEN_PRESENT,
        )
        self.assertEqual((result.session_count, result.refresh_token_count), (0, 1))
        self.assertTrue(result.expected_subject_binding_verified)

    def test_expected_identity_session_and_refresh(self) -> None:
        result = self.classify(_state("SESSION"), _state("REFRESH_TOKEN"))
        self.assertEqual(
            result.classification,
            inspection.InspectionClassification.SESSION_AND_REFRESH_PRESENT,
        )
        self.assertEqual((result.session_count, result.refresh_token_count), (1, 1))
        self.assertTrue(result.expected_subject_binding_verified)

    def test_unexpected_identity_binding_fails_closed_classification(self) -> None:
        result = self.classify(_state("SESSION", UNEXPECTED_SUBJECT))
        self.assertEqual(
            result.classification,
            inspection.InspectionClassification.IDENTITY_BINDING_MISMATCH,
        )
        self.assertFalse(result.expected_subject_binding_verified)

    def test_malformed_read_response_is_unverified(self) -> None:
        malformed = {"result": [{"session_count": 0, "refresh_token_count": 0}]}
        with self.assertRaises(inspection.SafeInspectionStop) as raised:
            inspection.classify_session_state(
                malformed,
                expected_subject_digest=_digest(EXPECTED_SUBJECT),
            )
        self.assertEqual(raised.exception.code, "SESSION_INSPECTION_RESPONSE_INVALID")
        self.assertEqual(
            raised.exception.classification,
            inspection.InspectionClassification.SESSION_STATE_UNVERIFIED,
        )

    def test_read_request_failure_is_unverified_and_payload_is_not_rendered(self) -> None:
        requests = []

        def urlopen(request, timeout):
            requests.append((request, timeout))
            if len(requests) == 1:
                return FakeResponse(
                    200,
                    {
                        "id": inspection.DEVELOPMENT_AUTH_PROJECT_REF,
                        "ref": inspection.DEVELOPMENT_AUTH_PROJECT_REF,
                        "name": "DEVELOPMENT AUTH",
                    },
                )
            raise urllib.error.URLError("fixture provider payload must not escape")

        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(inspection.SafeInspectionStop) as raised:
            inspection.inspect_development_auth_session_state(
                read_token="fixture-runtime-only-read-material",
                expected_subject_digest=_digest(EXPECTED_SUBJECT),
                urlopen=urlopen,
            )
        self.assertEqual(raised.exception.code, "SESSION_INSPECTION_READ_FAILED")
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("fixture provider payload", str(raised.exception))
        self.assertEqual(requests[0][0].get_method(), "GET")
        self.assertEqual(requests[1][0].get_method(), "POST")
        self.assertTrue(requests[1][0].full_url.endswith("/database/query/read-only"))
        self.assertEqual(json.loads(requests[1][0].data), {"query": inspection.SESSION_STATE_QUERY})

    def test_sanitized_evidence_contains_no_subject_or_provider_payload(self) -> None:
        result = self.classify(_state("SESSION"), _state("REFRESH_TOKEN"))
        evidence = inspection.sanitized_inspection_evidence(
            result,
            plan_id="8a1300d3-4bfb-461c-90c4-a22a53a11647",
            plan_digest="sha256:" + "a" * 64,
        )
        rendered = json.dumps(evidence, sort_keys=True)
        self.assertNotIn(EXPECTED_SUBJECT, rendered)
        self.assertNotIn(UNEXPECTED_SUBJECT, rendered)
        self.assertNotIn("provider_subject", rendered)
        self.assertNotIn("email", rendered.lower())
        self.assertEqual(evidence["session_count"], 1)
        self.assertEqual(evidence["refresh_token_count"], 1)
        self.assertFalse(evidence["provider_mutation_attempted"])
        self.assertFalse(evidence["credential_material_retained"])
        self.assertFalse(evidence["pii_retained"])

    def test_provider_mutation_is_structurally_impossible(self) -> None:
        query = re.sub(r"\s+", " ", inspection.SESSION_STATE_QUERY.lower())
        for keyword in ("insert ", "update ", "delete ", "truncate ", "alter ", "drop ", "create "):
            self.assertNotIn(keyword, query)
        self.assertIn("from auth.sessions", query)
        self.assertIn("from auth.refresh_tokens", query)
        self.assertEqual(
            inspection.READ_ONLY_SQL_PATH,
            "/v1/projects/pwlhruwutoitnieactol/database/query/read-only",
        )
        plan = json.loads(
            (ROOT / "contracts/plans/v1/development-auth-v32-session-inspection-v1.plan.json").read_text()
        )
        self.assertEqual([step["execution_class"] for step in plan["steps"]], ["PROVIDER_READ"])
        self.assertIn("provider.mutation", plan["prohibited_actions"])
        self.assertIn("provider.mutation", plan["steps"][0]["prohibited_actions"])

    def test_no_cleanup_function_is_reachable(self) -> None:
        module_source = (
            ROOT / "src/avuhz_engineering/development_auth_session_inspection.py"
        ).read_text(encoding="utf-8")
        executor_source = (
            ROOT / "scripts/development_auth_v32_session_inspection_v1.py"
        ).read_text(encoding="utf-8")
        workflow = (
            ROOT / ".github/workflows/development-auth-v32-session-inspection-v1.yml"
        ).read_text(encoding="utf-8")
        executable_surface = module_source + executor_source + workflow
        for forbidden in (
            "/auth/v1/logout",
            "request_local_session_logout",
            "run_recovery_session_lifecycle",
            "auth/v1/admin/users",
            "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        ):
            self.assertNotIn(forbidden, executable_surface)
        self.assertEqual(
            workflow.count("secrets.AVUHZ_DEVELOPMENT_SUPABASE_PROVIDER_READ_TOKEN"),
            1,
        )


if __name__ == "__main__":
    unittest.main()
