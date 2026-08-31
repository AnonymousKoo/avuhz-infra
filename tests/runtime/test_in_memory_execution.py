import copy
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/contracts")]
from avuhz_runtime.in_memory import Executor, MemoryStore
from avuhz_runtime.validation import CommandValidator
from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext, COMMAND_CAPABILITIES
from validate_command_payloads import envelope, payloads, handoff
T = "a3000000-0000-4000-8000-000000000002"

def ctx(command):
    return TrustedExecutionContext(True, "fictional-principal", "INTERNAL_SERVICE", T, None, frozenset({COMMAND_CAPABILITIES[command]}), frozenset(), "TEST", "avuhz-command-api", "STRONG", False, "2030-01-15T15:00:00Z", "2030-01-15T16:00:00Z")

class Tests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore(); source = handoff(); self.store.handoffs[source["handoff_id"]] = source
        self.executor = Executor(CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(), self.store, ids=lambda: "b6000000-0000-4000-8000-000000000001")
    def execute(self, command): return self.executor.execute(envelope(command, copy.deepcopy(payloads()[command])), ctx(command))
    def test_shared_acquisition_and_engagement_lifecycle(self):
        self.assertEqual(self.execute("AcceptAcquisitionHandoff")["result"], "ACCEPTED")
        self.assertEqual(self.execute("AcceptAcquisitionHandoff")["result"], "DUPLICATE")
        self.assertEqual(self.execute("OpenEngagement")["result"], "ACCEPTED")
        self.assertEqual(len(self.store.events), 2); self.assertEqual(len(self.store.outbox), 2)
    def test_unaccepted_handoff_has_no_side_effects(self):
        before = (len(self.store.events), len(self.store.outbox))
        self.assertEqual(self.execute("OpenEngagement")["result"], "REJECTED")
        self.assertEqual((len(self.store.events), len(self.store.outbox)), before)

if __name__ == "__main__": unittest.main()
