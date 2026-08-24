import sys,unittest
sys.path.insert(0,'src')
from avuhz_runtime.assessment_eligibility import evaluate_assessment_eligibility
class T(unittest.TestCase):
 def test_chain(self):
  e={'tenant_id':'t','engagement_id':'e','engagement_state':'OPEN'};s={'tenant_id':'t','engagement_id':'e','diagnostic_scope_id':'s','status':'APPROVED','canonical_scope_digest':'d'};a={'tenant_id':'t','engagement_id':'e','diagnostic_agreement_authority_id':'a','status':'VERIFIED_ACTIVE','scope_reference':{'reference_id':'s'},'canonical_scope_digest':'d'};p={'tenant_id':'t','engagement_id':'e','verification_status':'VERIFIED','payment_purpose':'DIAGNOSTIC_OIA','diagnostic_agreement_authority_reference':{'reference_id':'a'}};self.assertTrue(evaluate_assessment_eligibility('t',e,s,a,p).eligible);p['verification_status']='INVALIDATED';self.assertFalse(evaluate_assessment_eligibility('t',e,s,a,p).eligible)
if __name__=="__main__":unittest.main()
