import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
import copy, unittest
from avuhz_runtime.assessment_access_authority import build_assessment_access_authority_projection, compute_assessment_access_authority_digest
class AssessmentAccessAuthorityDigestTests(unittest.TestCase):
 def grant(self): return {"assessment_access_grant_id":"a","tenant_id":"t","engagement_id":"e","diagnostic_scope_reference":{"reference_type":"DIAGNOSTIC_SCOPE","reference_id":"s","reference_version":1},"canonical_scope_digest":"sha256:"+"a"*64,"action_set_version":1,"diagnostic_agreement_authority_reference":{"reference_type":"DIAGNOSTIC_AGREEMENT_AUTHORITY","reference_id":"g","reference_version":1},"diagnostic_payment_verification_reference":{"reference_type":"DIAGNOSTIC_PAYMENT_VERIFICATION","reference_id":"p","reference_version":1},"target_system_references":[{"system_reference_id":"system-b"},{"system_reference_id":"system-a"}],"permitted_actions":["VIEW_LOGS","VIEW_CONFIGURATION"],"status":"APPROVED","verified_at":None,"record_version":1}
 def test_normalizes_sets_and_excludes_lifecycle(self):
  a=self.grant();b=copy.deepcopy(a);b["target_system_references"].reverse();b["permitted_actions"].reverse();b.update(status="ACTIVE",verified_at="2030-01-01T00:00:00Z",record_version=2)
  self.assertEqual(compute_assessment_access_authority_digest(a),compute_assessment_access_authority_digest(b));self.assertEqual(build_assessment_access_authority_projection(a)["target_system_references"][0]["system_reference_id"],"system-a")
 def test_immutable_authority_change_changes_digest(self):
  a=self.grant();b=copy.deepcopy(a);b["permitted_actions"]=["VIEW_METRICS"];self.assertNotEqual(compute_assessment_access_authority_digest(a),compute_assessment_access_authority_digest(b))
 def test_duplicate_semantic_set_members_rejected(self):
  a=self.grant();a["permitted_actions"]=["VIEW_LOGS","VIEW_LOGS"]
  with self.assertRaises(ValueError):build_assessment_access_authority_projection(a)
if __name__=="__main__":unittest.main()
