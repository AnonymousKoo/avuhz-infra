from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-implementation-handoff-provider-adapter-auth-credential-v1'
PLAN_ID='ad256fb9-c5da-4948-a382-8dfa9330eb35'
PLAN_DIGEST='sha256:61124306f5006b763d58cacefad2a8c92a67b06c2bb83f609c68427e22e7e8bd'
PROGRESS_ID='f8561573-3faa-480b-b899-95174eae9f19'
PROGRESS_DIGEST='sha256:6b43b485fa5a4c31d64e2b7996303905c822d0bcc936100f724378802f75711e'
RESOURCE_DIGEST='sha256:65901ebc69a66053be796da2980d1f7a91794c64654f134a2b205277e8b4f742'
FAILURE='sha256:1e31607337b069824b2a444313c7394c4ade0575139e90d9726b0a651bf44956'
STOPPED='sha256:f4c4a299b032e3cb4460bf6d6c756de88a34cfad6d52e5cf9f645158e49d50fd'
load=lambda n: json.loads((B/n).read_text())
def main():
 r=load(N+'.resource.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert not (B/(N+'.approval.json')).exists()
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['project_reference']=='pwlhruwutoitnieactol' and r['credential_create_count_authorized']==1
 assert r['failed_predecessor_evidence_digest']==FAILURE and r['failed_predecessor_progress_digest']==STOPPED
 assert r['failed_predecessor_state']=='STOPPED_CONSUMED_FAILED_FAIL'
 assert r['github_binding_authorized'] is False and r['identity_creation_authorized'] is False
 assert r['tenant_binding_authorized'] is False and r['allowlist_binding_authorized'] is False
 assert r['credential_value_agent_visible'] is False and r['credential_value_persistence_authorized'] is False and r['credential_digest_authorized'] is False
 assert r['retirement_required_after_continuation'] is True
 assert p['plan_id']==PLAN_ID and p['plan_version']==1 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-03T04:30:00Z','expires_at':'2026-10-03T08:30:00Z'}
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert len(p['steps'])==1; s=p['steps'][0]
 assert s['operation']=='provider.auth-admin-credential.create-dedicated-secret-key' and s['execution_class']=='PROVIDER_MUTATION'
 assert s['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert s['required_evidence']==[
  {'evidence_type':'auth.provider-adapter-identity.created','source_step_id':None,'binding_state':'BOUND','exact_digest':FAILURE},
  {'evidence_type':'authorization-plan.execution-progress','source_step_id':None,'binding_state':'BOUND','exact_digest':STOPPED},
 ]
 for x in ('github-secret.mutate','identity.create','tenant-metadata.modify','server-allowlist.bind','token.issue','session.issue','data.operation','render.operation','n8n.operation','production.target','credential.digest','credential.persist','credential.return'):
  assert x in s['prohibited_actions']
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 print('ImplementationHandoff provider-adapter Auth credential v1: PASS (one Supabase key only; no GitHub binding/identity/tenant/allowlist/token/session/downstream action)')
if __name__=='__main__': main()
