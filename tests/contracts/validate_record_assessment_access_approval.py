#!/usr/bin/env python3
import copy,sys
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'))
from avuhz_runtime.schema_registry import SchemaRegistry
SID='urn:avuhz:schema:contracts:commands:record-assessment-access-approval-payload:v1'
def main():
 v=Draft202012Validator(SchemaRegistry(ROOT/'contracts/schemas/v1').expanded(SID),format_checker=FormatChecker());base={'assessment_access_grant_id':'a6000000-0000-4000-8000-000000000001','authority_role':'CLIENT_DECISION_AUTHORITY'}
 for x in (base,{**base,'authority_role':'SEKINFRA_ENGAGEMENT_AUTHORITY'}):assert not list(v.iter_errors(x))
 for key,val in [('assessment_access_grant_id',None),('assessment_access_grant_id','bad'),('authority_role',None),('authority_role','ACCESS_ADMIN'),('assessment_access_authority_digest','sha256:'+'a'*64),('target_system_references',[]),('permitted_actions',[]),('human_principal_reference','fictional'),('human_organization_reference','fictional'),('caller_type','HUMAN'),('metadata',{}),('extra','forbidden')]:
  x=copy.deepcopy(base)
  if val is None:x.pop(key)
  else:x[key]=val
  assert list(v.iter_errors(x)),key
 print('record-assessment-access-approval validation: PASS (2 positive, 12 negative)')
if __name__=='__main__':main()
