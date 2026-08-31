import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.guards import GuardPipeline,TrustedExecutionContext
def context(role="CLIENT_IMPLEMENTATION_AUTHORITY",caller="HUMAN",principal="human:opaque-1",organization="org:opaque-1",tenant="a3000000-0000-4000-8000-000000000002"):
 return TrustedExecutionContext(True,"resolved-session",caller,tenant,None,frozenset({"implementation_brief:approve"}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z","2030-01-15T16:00:00Z",principal,organization,role)
class Tests(unittest.TestCase):
 def test_client_and_provider_humans_are_distinct(self):
  g=GuardPipeline();self.assertIsNone(g.human_approval_authority(context(),"CLIENT_IMPLEMENTATION_AUTHORITY"));self.assertIsNone(g.human_approval_authority(context("PROVIDER_IMPLEMENTATION_AUTHORITY"),"PROVIDER_IMPLEMENTATION_AUTHORITY"))
 def test_workload_and_spoofing_are_denied(self):
  g=GuardPipeline();self.assertIsNotNone(g.human_approval_authority(context(caller="WORKLOAD"),"CLIENT_IMPLEMENTATION_AUTHORITY"));self.assertIsNotNone(g.human_approval_authority(context("PROVIDER_IMPLEMENTATION_AUTHORITY"),"CLIENT_IMPLEMENTATION_AUTHORITY"));self.assertIsNotNone(g.human_approval_authority(context(principal=None),"CLIENT_IMPLEMENTATION_AUTHORITY"))
if __name__=="__main__":unittest.main()
