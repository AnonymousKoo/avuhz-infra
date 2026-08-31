import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/"src"),str(ROOT/"tests/contracts")]
from avuhz_runtime.errors import RuntimeReason
from avuhz_runtime.guards import GuardFailure,GuardPipeline,GuardSuccess,TrustedExecutionContext,COMMAND_CAPABILITIES
from avuhz_runtime.runtime import prepare_and_guard_command
from avuhz_runtime.validation import CommandValidator
from validate_command_payloads import envelope,payloads
T="a3000000-0000-4000-8000-000000000002"
def ctx(command,**changes):
 value=dict(authenticated=True,principal_id="fictional-principal",caller_type="INTERNAL_SERVICE",tenant_id=T,organization_id=None,capabilities=frozenset({COMMAND_CAPABILITIES[command]}),authority_roles=frozenset(),environment="TEST",audience="avuhz-command-api",authentication_strength="STRONG",step_up_satisfied=False,authenticated_at="2030-01-15T15:00:00Z",expires_at="2030-01-15T16:00:00Z");value.update(changes);return TrustedExecutionContext(**value)
class Tests(unittest.TestCase):
 def setUp(self):self.validator=CommandValidator(ROOT/"contracts/schemas/v1");self.pipeline=GuardPipeline()
 def go(self,command,context=None):return prepare_and_guard_command(self.validator,self.pipeline,envelope(command,copy.deepcopy(payloads()[command])),context or ctx(command),None,"2030-01-15T15:30:00Z")
 def test_active_shared_commands(self):
  self.assertIsInstance(self.go("AcceptAcquisitionHandoff"),GuardSuccess);self.assertIsInstance(self.go("OpenEngagement"),GuardSuccess)
 def test_fail_closed(self):
  result=self.go("OpenEngagement",ctx("OpenEngagement",authenticated=False));self.assertIsInstance(result,GuardFailure);self.assertEqual(result.reason,RuntimeReason.AUTH_MISSING)
  result=self.go("OpenEngagement",ctx("OpenEngagement",capabilities=frozenset()));self.assertEqual(result.reason,RuntimeReason.AUTH_CAPABILITY_MISSING)
if __name__=="__main__":unittest.main()
