import copy,sys,unittest
sys.path.insert(0,'src')
from avuhz_runtime.assessment_eligibility import evaluate_assessment_eligibility
class T(unittest.TestCase):
 def records(self):
  e={'tenant_id':'t','engagement_id':'e','engagement_state':'OPEN'};s={'tenant_id':'t','engagement_id':'e','diagnostic_scope_id':'s','scope_version':1,'status':'APPROVED','canonical_scope_digest':'d'};a={'tenant_id':'t','engagement_id':'e','diagnostic_agreement_authority_id':'a','status':'VERIFIED_ACTIVE','scope_reference':{'reference_id':'s','reference_version':1},'canonical_scope_digest':'d','effective_at':'2030-01-01T00:00:00Z','ends_at':'2030-02-01T00:00:00Z'};p={'tenant_id':'t','engagement_id':'e','verification_status':'VERIFIED','payment_purpose':'DIAGNOSTIC_OIA','diagnostic_agreement_authority_reference':{'reference_id':'a'}};return e,s,a,p
 def test_chain_and_fail_closed(self):
  e,s,a,p=self.records();self.assertTrue(evaluate_assessment_eligibility('t',e,s,a,p,'2030-01-15T00:00:00Z').eligible)
  for obj,key,val in [(s,'scope_version',2),(a,'canonical_scope_digest','x'),(a,'effective_at','2030-02-15T00:00:00Z'),(a,'ends_at','2030-01-10T00:00:00Z'),(p,'verification_status','INVALIDATED'),(p,'payment_purpose','OTHER'),(p,'engagement_id','wrong')]:
   ee,ss,aa,pp=map(copy.deepcopy,(e,s,a,p)); {'s':ss,'a':aa,'p':pp}.get('s' if obj is s else 'a' if obj is a else 'p')[key]=val;self.assertFalse(evaluate_assessment_eligibility('t',ee,ss,aa,pp,'2030-01-15T00:00:00Z').eligible)
if __name__=='__main__':unittest.main()
