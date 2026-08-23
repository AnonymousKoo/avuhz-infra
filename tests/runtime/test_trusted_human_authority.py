import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'))
from avuhz_runtime.guards import GuardPipeline,TrustedExecutionContext
def context(role='CLIENT_DECISION_AUTHORITY',caller='HUMAN',principal='human:opaque-1',organization='org:opaque-1',tenant='a3000000-0000-4000-8000-000000000002'):
 return TrustedExecutionContext(True,'resolved-session',caller,tenant,None,frozenset({'scope:approve'}),frozenset(),'TEST','avuhz-command-api','STRONG',False,'2030-01-15T15:00:00Z','2030-01-15T16:00:00Z',principal,organization,role)
class Tests(unittest.TestCase):
 def test_client_and_sekinfra_humans_are_distinct(self):
  g=GuardPipeline();self.assertIsNone(g.human_approval_authority(context(),'CLIENT_DECISION_AUTHORITY'));self.assertIsNone(g.human_approval_authority(context('SEKINFRA_ENGAGEMENT_AUTHORITY'),'SEKINFRA_ENGAGEMENT_AUTHORITY'))
 def test_workload_and_forgery_are_denied(self):
  g=GuardPipeline();self.assertIsNotNone(g.human_approval_authority(context(caller='INTERNAL_SERVICE'),'CLIENT_DECISION_AUTHORITY'));self.assertIsNotNone(g.human_approval_authority(context('SEKINFRA_ENGAGEMENT_AUTHORITY'),'CLIENT_DECISION_AUTHORITY'));self.assertIsNotNone(g.human_approval_authority(context(principal=None),'CLIENT_DECISION_AUTHORITY'));self.assertIsNotNone(g.human_approval_authority(context(organization=None),'CLIENT_DECISION_AUTHORITY'));self.assertIsNotNone(g.human_approval_authority(context(role='UNSUPPORTED'),'UNSUPPORTED'));self.assertIsNotNone(g.human_approval_authority(context(tenant=None),'CLIENT_DECISION_AUTHORITY'))
