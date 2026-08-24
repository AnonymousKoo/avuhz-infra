import copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from avuhz_runtime.assessment_access_authority import compute_assessment_access_authority_digest
from avuhz_runtime.in_memory import MemoryStore,UnitOfWork
class ProposalTests(unittest.TestCase):
 def record(self,status='OPEN'):return {'assessment_access_proposal_id':'p','tenant_id':'t1','engagement_id':'e','diagnostic_scope_reference':{'reference_id':'s','reference_version':1},'canonical_scope_digest':'sha256:'+'a'*64,'action_set_version':1,'diagnostic_agreement_authority_reference':{'reference_id':'g','reference_version':1},'diagnostic_payment_verification_reference':{'reference_id':'q','reference_version':1},'target_system_references':[{'system_reference_id':'b'},{'system_reference_id':'a'}],'permitted_actions':['VIEW_LOGS','VIEW_CONFIGURATION'],'status':status,'record_version':1}
 def test_digest_and_reads(self):
  a=self.record();b=copy.deepcopy(a);b['assessment_access_proposal_id']='other';b['status']='CONSUMED';b['target_system_references'].reverse();b['permitted_actions'].reverse();self.assertEqual(compute_assessment_access_authority_digest(a),compute_assessment_access_authority_digest(b));u=UnitOfWork(MemoryStore());u.assessment_access_proposals.save(a);self.assertIs(u.assessment_access_proposals.get('t1','p'),a);self.assertIsNone(u.assessment_access_proposals.get('t2','p'));self.assertIsNone(u.assessment_access_proposals.get('t1','unknown'))
if __name__=='__main__':unittest.main()
