import copy
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/contracts")]
from avuhz_runtime.errors import RuntimeReason
from avuhz_runtime.models import ValidationSuccess
from avuhz_runtime.validation import CommandValidator
from validate_command_payloads import envelope, payloads


class CommandValidationTests(unittest.TestCase):
    def setUp(self): self.validator = CommandValidator(ROOT / "contracts/schemas/v1")
    def request(self, command): return envelope(command, copy.deepcopy(payloads()[command]))
    def reject(self, command, mutate, reason=None):
        raw = self.request(command); mutate(raw); result = self.validator.prepare(raw)
        self.assertNotIsInstance(result, ValidationSuccess)
        if reason: self.assertEqual(result.reason, reason)
    def test_active_shared_system_commands_prepare(self):
        for command in ("AcceptAcquisitionHandoff", "OpenEngagement"):
            result = self.validator.prepare(self.request(command)); self.assertIsInstance(result, ValidationSuccess)
    def test_rejections_fail_closed(self):
        self.reject("OpenEngagement", lambda x: x.update(command_type="UnknownCommand"), RuntimeReason.SCHEMA_UNSUPPORTED)
        self.reject("OpenEngagement", lambda x: x.update(expected_record_version=1))
        self.reject("AcceptAcquisitionHandoff", lambda x: x.update(engagement_id=x["subject_id"]))
        self.reject("OpenEngagement", lambda x: x["caller_identity"].update(caller_type="INVALID"), RuntimeReason.AUTH_INVALID)
        self.reject("OpenEngagement", lambda x: x.update(extra="field"), RuntimeReason.FIELD_FORBIDDEN)


if __name__ == "__main__": unittest.main()
