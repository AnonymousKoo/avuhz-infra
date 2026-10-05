#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest, initial_progress, plan_digest, progress_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v6'; V5='development-implementation-handoff-provider-adapter-positive-auth-v5'; PROJECT='pwlhruwutoitnieactol'; KEY='impl_handoff_provider_adapter_positive_auth_v6_ephemeral'; GH='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V6_EPHEMERAL'
CREATED='2026-10-05T14:20:52Z'; START='2026-10-05T16:00:00Z'; END='2026-10-05T22:00:00Z'; REJECT='sha256:e29e56af04b0b2664aa8d6749c367184f2c06446c2eb50fa1cbad4e394c09468'
def load(n): return json.loads((B/n).read_text())
def raw(p): return 'sha256:'+hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); a=load(N+'.approval.json'); x=load(N+'.execution-progress.json'); e1=load(N+'-step01-success.evidence.json'); e2=load(N+'-step02-plan-integrity-failure.evidence.json'); rej=load(V5+'-preactivation-integrity-rejection.evidence.json')
 validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,START); validate_progress(p,x,S)
 assert r['contract_digest']==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert prep['evidence_digest']==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
 assert rej['evidence_digest']==REJECT==canonical_digest({k:v for k,v in rej.items() if k!='evidence_digest'})
 assert rej['outcome']=='REJECTED_PREACTIVATION_UNEXECUTED' and rej['approval_artifact_created'] is False and all(v is False for v in rej['effects'].values())
 assert p['plan_version']==6 and p['plan_digest']==plan_digest(p) and p['definition_status']=='READY_FOR_APPROVAL'
 assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED' and p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END}
 assert r['project_reference']==PROJECT and r['fresh_provider_key_reference']==KEY and r['github_secret_binding_name']==GH
 assert r['required_v5_rejection_evidence_digest']==REJECT
 assert r['step5_executor_digest']==raw(ROOT/'scripts/development_provider_adapter_positive_auth_v6.py')
 assert r['step5_workflow_digest']==raw(ROOT/'.github/workflows/development-provider-adapter-positive-auth-v6-step5.yml')
 wf=(ROOT/'.github/workflows/development-provider-adapter-positive-auth-v6-step5.yml').read_text()
 assert 'scripts/development_provider_adapter_positive_auth_v6.py' in wf
 assert 'scripts/development_provider_adapter_positive_auth_v5.py' not in wf
 assert len(p['steps'])==10 and all('positive-auth-v6' in s['step_id'] for s in p['steps'])
 assert all(s['resource']['exact_version']=='provider-adapter-positive-auth.v6' and s['resource']['exact_digest']==r['contract_digest'] for s in p['steps'])
 for idx in (0,6,8):
  assert KEY in p['steps'][idx]['resource']['resource_reference']
  assert KEY in p['steps'][idx]['expected_postcondition']
 rendered=json.dumps(p,sort_keys=True)
 assert 'impl_handoff_provider_adapter_positive_auth_v4_ephemeral' not in rendered
 assert 'impl_handoff_provider_adapter_positive_auth_v5_ephemeral' not in rendered
 assert p['steps'][3]['operation']=='provider.auth-state.inspect-aggregate-only-via-supabase-mcp'
 assert p['steps'][5]['operation']=='provider.auth-session-state.inspect-read-only-via-supabase-mcp'
 assert p['steps'][3]['credential_policy']=={'permitted':False,'allowed_classes':['NONE'],'values_stored':False}
 assert p['steps'][5]['credential_policy']=={'permitted':False,'allowed_classes':['NONE'],'values_stored':False}
 assert any(x['evidence_type']=='auth.provider-adapter-positive-auth-v5.preactivation-integrity-rejected' and x['exact_digest']==REJECT for x in p['steps'][0]['required_evidence'])
 assert g==initial_progress(p,S,g['progress_id'],CREATED) and g['progress_digest']==progress_digest(g) and g['overall_state']=='NOT_STARTED'
 assert a['plan_id']==p['plan_id'] and a['plan_version']==6 and a['plan_digest']==p['plan_digest'] and a['decision']=='APPROVE' and a['status']=='ACTIVE'
 assert a['authority_scope']=='EXACT_PLAN_ONLY' and a['effective_at']==START and a['expires_at']==END and a['approval_digest']==approval_digest(a)
 assert canonical_digest(e1)=='sha256:b0a29a99d233db3526179e77b841c27e0946760be3894f51050e147ba3b5a046'
 assert e1['outcome']=='SUCCEEDED_VERIFIED' and e1['owner_confirmed_created'] is True and e1['credential_material_retained'] is False
 assert canonical_digest(e2)=='sha256:fdd233c078ee3e60bae0dd95128535526dc073759c54ee5cd21c8070cac15937'
 assert e2['outcome']=='FAILED_PREEXECUTION_PLAN_INTEGRITY' and e2['safe_error_code']=='PLAN_STATE_INVALID'
 assert e2['sanitized_result']['binding_created'] is False and e2['sanitized_result']['provider_mutation_performed'] is False
 assert x['progress_digest']=='sha256:c5d7bf0545ca10f453f4ac9775edccb1a2eb5e63efa7966225b95f5e5659df6f'==progress_digest(x)
 assert x['overall_state']=='STOPPED' and x['record_version']==5
 assert (x['step_states'][0]['authorization_state'],x['step_states'][0]['execution_state'],x['step_states'][0]['verification_state'],x['step_states'][0]['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
 assert (x['step_states'][1]['authorization_state'],x['step_states'][1]['execution_state'],x['step_states'][1]['verification_state'],x['step_states'][1]['authorization_consumed'])==('CONSUMED','FAILED','FAIL',True)
 assert all((s['authorization_state'],s['execution_state'],s['verification_state'],s['authorization_consumed'])==('BLOCKED','NOT_STARTED','NOT_STARTED',False) for s in x['step_states'][2:])
 assert 'bound in the v5 resource' in p['steps'][3]['expected_postcondition']
 assert 'fresh v5 GitHub environment credential' in p['steps'][4]['expected_postcondition']
 alltext='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json','-step01-success.evidence.json','-step02-plan-integrity-failure.evidence.json','.execution-progress.json'))
 assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',alltext) is None
 print('DEVELOPMENT provider-adapter positive-auth v6: PASS (STOPPED; Step 1 credential created; Step 2 failed closed before GitHub binding on stale v5 execution wording; Steps 3-10 blocked; retirement required)')
if __name__=='__main__': main()
