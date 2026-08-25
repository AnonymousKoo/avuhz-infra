import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/"src"),str(ROOT/"tests"/"runtime")]
from avuhz_runtime.commercial_ingress import DiagnosticCommercialIngressHandler,CommercialIngressRejected
from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.in_memory import UnitOfWork
from avuhz_runtime.assessment_access_usability import evaluate_assessment_access_usability
from test_record_human_approval import Tests as ScopeFlow
from test_verify_assessment_access import VerifyAssessmentAccessTests
T="a3000000-0000-4000-8000-000000000002";E="a3000000-0000-4000-8000-000000000004";S="a3000000-0000-4000-8000-000000000005";A="a3000000-0000-4000-8000-000000000013";P="a3000000-0000-4000-8000-000000000014"
def c(cap):return TrustedExecutionContext(True,"commercial","INTERNAL_SERVICE",T,None,frozenset({cap}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z")
class Tests(unittest.TestCase):
 def test_record_bindings_conflicts_and_invalidation_safety(self):
  flow=ScopeFlow();flow.setUp();flow.establish();flow.approval("CLIENT_DECISION_AUTHORITY","commercial-client-0001","b9000000-0000-4000-8000-000000000010");flow.approval("SEKINFRA_ENGAGEMENT_AUTHORITY","commercial-sekinfra-0001","b9000000-0000-4000-8000-000000000011");flow.final("commercial-final-0001",2);u=UnitOfWork(flow.s);h=DiagnosticCommercialIngressHandler(u)
  ap={"diagnostic_agreement_authority_id":A,"engagement_id":E,"diagnostic_scope_id":S,"scope_version":1,"agreement_reference":"agreement.external-001","effective_at":"2030-01-01T00:00:00Z"};a=h.record_agreement(c("diagnostic_agreement:record"),ap,"2030-01-15T15:00:00Z");self.assertEqual((a["status"],a["scope_reference"]["reference_id"],a["record_version"]),("VERIFIED_ACTIVE",S,1))
  pp={"diagnostic_payment_verification_id":P,"engagement_id":E,"diagnostic_agreement_authority_reference":{"reference_type":"DIAGNOSTIC_AGREEMENT_AUTHORITY","reference_id":A,"reference_version":1},"amount_minor":10000,"currency":"USD","provider_reference":"payment.external-001"};p=h.record_payment(c("diagnostic_payment:record"),pp,"2030-01-15T15:00:00Z");self.assertEqual((p["payment_purpose"],p["verification_status"]),("DIAGNOSTIC_OIA","VERIFIED"))
  with self.assertRaises(CommercialIngressRejected):h.record_agreement(c("diagnostic_agreement:record"),{**ap,"agreement_reference":"changed"},"2030-01-15T15:00:00Z")
  with self.assertRaises(CommercialIngressRejected):h.record_payment(c("diagnostic_payment:record"),{**pp,"engagement_id":"a3000000-0000-4000-8000-000000000099"},"2030-01-15T15:00:00Z")
  v=VerifyAssessmentAccessTests();active=v.setup();v.verify(active);self.assertTrue(evaluate_assessment_access_usability(active,T,"a3000000-0000-4000-8000-000000000015","2030-01-15T15:00:00Z").usable);i=DiagnosticCommercialIngressHandler(active).invalidate_payment(c("diagnostic_payment:invalidate"),{"diagnostic_payment_verification_id":P},"2030-01-16T00:00:00Z");self.assertEqual((i["verification_status"],i["invalidated_at"]),("INVALIDATED","2030-01-16T00:00:00Z"));self.assertEqual(evaluate_assessment_access_usability(active,T,"a3000000-0000-4000-8000-000000000015","2030-01-16T00:00:00Z").reason,"COMMERCIAL_AUTHORITY_INVALID")
  with self.assertRaises(CommercialIngressRejected):DiagnosticCommercialIngressHandler(active).invalidate_payment(c("diagnostic_payment:invalidate"),{"diagnostic_payment_verification_id":P},"2030-01-17T00:00:00Z")
if __name__=="__main__":unittest.main()
