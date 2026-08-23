import copy,hashlib,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.canonical_scope import build_canonical_scope_projection,canonical_json_bytes,compute_canonical_scope_digest

def scope():
 return {"diagnostic_scope_id":"s","scope_version":1,"engagement_id":"e","tenant_id":"t","target_outcome":"out","in_scope_systems":[{"b":2,"a":1}],"excluded_systems":[{"system_reference":{"a":1},"reason":"r"}],"permitted_diagnostic_actions":["VIEW_LOGS","VIEW_METRICS"],"prohibited_actions":["CREATE","MODIFY"],"assumptions":["a"],"constraints":[{"reference_id":"c","reference_type":"X"}],"record_version":9,"created_at":"x","canonical_scope_digest":None}
class Tests(unittest.TestCase):
 def test_determinism_and_correctness(self):
  a=scope();b=copy.deepcopy(a);b["in_scope_systems"]=[{"a":1,"b":2}]
  self.assertEqual(canonical_json_bytes(build_canonical_scope_projection(a)),canonical_json_bytes(build_canonical_scope_projection(b)))
  self.assertEqual(compute_canonical_scope_digest(a),"sha256:"+hashlib.sha256(canonical_json_bytes(build_canonical_scope_projection(a))).hexdigest())
 def test_array_order_and_fields(self):
  a=scope();b=copy.deepcopy(a);b["permitted_diagnostic_actions"].reverse();self.assertNotEqual(compute_canonical_scope_digest(a),compute_canonical_scope_digest(b))
  for field in build_canonical_scope_projection(a):
   c=copy.deepcopy(a);c[field]=2 if field=="scope_version" else "changed" if field=="target_outcome" else [] if isinstance(c[field],list) else "changed";self.assertNotEqual(compute_canonical_scope_digest(a),compute_canonical_scope_digest(c),field)
 def test_operational_fields_excluded(self):
  a=scope();b=copy.deepcopy(a);b["record_version"]=10;b["created_at"]="y";self.assertEqual(compute_canonical_scope_digest(a),compute_canonical_scope_digest(b))
if __name__=="__main__":unittest.main()
