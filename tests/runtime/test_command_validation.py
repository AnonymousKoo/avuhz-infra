import copy
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]; sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/contracts")]
from avuhz_runtime.errors import RuntimeReason
from avuhz_runtime.models import ValidationSuccess
from avuhz_runtime.validation import CommandValidator
from validate_command_payloads import envelope, payloads


class CommandValidationTests(unittest.TestCase):
    def setUp(self): self.validator = CommandValidator(ROOT / "contracts/schemas/v1")
    def request(self, command): return envelope(command, copy.deepcopy(payloads()[command]))
    def reject(self, command, mutate, reason=None):
        raw=self.request(command); mutate(raw); result=self.validator.prepare(raw)
        self.assertNotIsInstance(result, ValidationSuccess)
        if reason: self.assertEqual(result.reason, reason)
    def test_all_five_commands_prepare(self):
        for command in ("AcceptAcquisitionHandoff", "OpenEngagement", "SubmitDiagnosticScope", "RecordHumanApproval", "ApproveDiagnosticScope", "CanonicalizeDiagnosticScope", "CreateAssessmentAccessProposal"):
            result=self.validator.prepare(self.request(command)); self.assertIsInstance(result, ValidationSuccess)
            self.assertEqual(result.prepared.command_type, command)
            self.assertFalse(hasattr(result.prepared, "authenticated_identity"))
    def test_rejections_fail_closed(self):
        self.reject("OpenEngagement", lambda x:x.update(command_type="UnknownCommand"), RuntimeReason.SCHEMA_UNSUPPORTED)
        self.reject("OpenEngagement", lambda x:x.update(command_type="FutureCommand"), RuntimeReason.SCHEMA_UNSUPPORTED)
        self.reject("SubmitDiagnosticScope", lambda x:x.update(subject_type="DIAGNOSTIC_SCOPE"))
        self.reject("SubmitDiagnosticScope", lambda x:x.update(payload_schema="urn:avuhz:schema:contracts:commands:approve-diagnostic-scope-payload:v1"), RuntimeReason.SCHEMA_UNSUPPORTED)
        self.reject("OpenEngagement", lambda x:x.update(payload_schema="../../outside"), RuntimeReason.SCHEMA_UNSUPPORTED)
        self.reject("OpenEngagement", lambda x:x.update(payload_schema="https://example.invalid/schema"), RuntimeReason.SCHEMA_UNSUPPORTED)
        self.reject("OpenEngagement", lambda x:x.update(payload_version=2), RuntimeReason.SCHEMA_UNSUPPORTED)
        self.reject("SubmitDiagnosticScope", lambda x:x.update(payload={"unregistered":"value"}))
        self.reject("OpenEngagement", lambda x:x["caller_identity"].update(caller_type="INVALID"), RuntimeReason.AUTH_INVALID)
        self.reject("SubmitDiagnosticScope", lambda x:x.pop("engagement_id"), RuntimeReason.PAYLOAD_INVALID)
        self.reject("AcceptAcquisitionHandoff", lambda x:x.update(engagement_id="a3000000-0000-4000-8000-000000000004"))
        self.reject("SubmitDiagnosticScope", lambda x:x.pop("expected_record_version"), RuntimeReason.VERSION_REQUIRED)
        self.reject("OpenEngagement", lambda x:x.update(expected_record_version=1))
        self.reject("ApproveDiagnosticScope", lambda x:x["payload"].update(sekinfra_approval_reference=x["payload"]["client_approval_reference"]))
        self.reject("CanonicalizeDiagnosticScope", lambda x:x["payload"].update(canonical_scope_digest="sha256:"+"a"*64), RuntimeReason.FIELD_FORBIDDEN)
        self.reject("CanonicalizeDiagnosticScope", lambda x:x.pop("expected_record_version"), RuntimeReason.VERSION_REQUIRED)
        self.reject("CanonicalizeDiagnosticScope", lambda x:x["payload"].update(diagnostic_scope_id="a3000000-0000-4000-8000-000000000099"), RuntimeReason.PAYLOAD_INVALID)
        self.reject("OpenEngagement", lambda x:x.update(extra="field"), RuntimeReason.FIELD_FORBIDDEN)
        self.reject("CreateAssessmentAccessProposal", lambda x:x["payload"].update(assessment_access_authority_digest="sha256:"+"a"*64), RuntimeReason.FIELD_FORBIDDEN)
        self.reject("OpenEngagement", lambda x:x.update(subject_type="FUTURE_SUBJECT"))
        self.reject("OpenEngagement", lambda x:x.update(subject_id="not-a-uuid"))
        self.reject("OpenEngagement", lambda x:x.update(requested_at="2030-01-15T15:00:00+01:00"))
        self.reject("OpenEngagement", lambda x:x.update(environment="SANDBOX"))


if __name__ == "__main__": unittest.main()
