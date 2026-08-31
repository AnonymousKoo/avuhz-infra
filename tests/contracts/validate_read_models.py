#!/usr/bin/env python3
import sys
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.schema_registry import SchemaRegistry
T="b4000000-0000-4000-8000-000000000002";E="b4000000-0000-4000-8000-000000000001";NOW="2030-01-15T15:00:00Z"
def main():
 r=SchemaRegistry(ROOT/"contracts/schemas/v1");checker=FormatChecker();checker.checks("date-time")(lambda x:isinstance(x,str) and x.endswith("Z"))
 ref={"reference_type":"ENGAGEMENT","reference_id":E};checks=[{"check_code":code,"status":"SATISFIED","reason_code":"READINESS_SATISFIED","subject_reference":ref,"evaluated_at":NOW} for code in ("HANDOFF_ACCEPTED","ENGAGEMENT_EXISTS","ENGAGEMENT_STATE_ALLOWED")];ready={"engagement_reference":ref,"tenant_id":T,"readiness_state":"ENGAGEMENT_OPEN","evaluated_at":NOW,"read_model_version":1,"checks":checks}
 source="fictional-acquisition-provider";summary={"engagement_reference":ref,"tenant_id":T,"account_reference":{"source_system":source,"object_type":"CANONICAL_ACCOUNT","external_id":"account-001","environment":"TEST"},"acquisition_opportunity_reference":{"source_system":source,"object_type":"ACQUISITION_OPPORTUNITY","external_id":"opportunity-001","environment":"TEST"},"engagement_type":"BUSINESS_REVIEW","engagement_state":"OPEN","engagement_version":1,"record_version":1,"handoff_status":"ACCEPTED","onboarding_readiness":ready,"opened_at":NOW,"updated_at":NOW,"generated_at":NOW,"read_model_version":1}
 for schema_id,value in (("urn:avuhz:schema:contracts:read-models:onboarding-readiness:v1",ready),("urn:avuhz:schema:contracts:read-models:engagement-summary:v1",summary)):
  if list(Draft202012Validator(r.expanded(schema_id),format_checker=checker).iter_errors(value)):raise SystemExit("read-model validation: FAIL")
 print("read-model validation: PASS (2 provider-neutral projections)")
if __name__=="__main__":main()
