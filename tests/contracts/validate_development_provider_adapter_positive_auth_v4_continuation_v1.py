#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,progress_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
from scripts import development_provider_adapter_positive_auth_v4_continuation_v1 as executor
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v4-continuation-v1'
V4='development-implementation-handoff-provider-adapter-positive-auth-v4'
CORR='development-implementation-handoff-provider-adapter-positive-auth-v4-step4-surface-correction-v1'
PLAN_ID='43baee79-d5ca-51de-b812-62761844aad0'
PLAN_DIGEST='sha256:b3fe688ebb8e40da8f9c76db4f1054308e2a831ccd977b41852bb0322fb3ca32'
RESOURCE_DIGEST='sha256:23cd6de9908c86d90d6b8a9f98ae282b823d4afa3236382434f2f1d5f27cc790'
PREP_DIGEST='sha256:4b6c79bdbde7226b05fa223304a24ac32f75061c760d64206a25fe0673636bdb'
PROGRESS_ID='2df10de6-a149-5aa4-b5ce-4c23bd300074'
PROGRESS_DIGEST='sha256:140a47aa6f0ffdd7967952f1bb0e9951fd159196d2a55b2c9a2c8110a4741e98'
CORR_EVID='sha256:238b4af1586b4b57d919910acdd4042ea01abe95706a7133cadd9a8a6dc5887c'
CORR_PROGRESS='sha256:6b6eb329c6b945fde6f625be46794213b8f97a5126415a79389386547e123bdc'
V4_STOP='sha256:89597fb31105b2398295ba8c0be4534c7de80e7813b673e108db83a57a301c9c'
PROJECT='pwlhruwutoitnieactol'; WINDOW_START='2026-10-05T02:00:00Z'; WINDOW_END='2026-10-05T06:00:00Z'

def load(name): return json.loads((B/name).read_text())
def raw(p): return 'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()

def main():
 r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert p['plan_id']==PLAN_ID and p['plan_version']==1 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':WINDOW_START,'expires_at':WINDOW_END}
 assert len(p['steps'])==2 and p['ordered_step_ids']==[x['step_id'] for x in p['steps']]
 assert [x['operation'] for x in p['steps']]==['provider.auth-session.provider-adapter-recover-validate-live-probe-and-logout-global','provider.auth-session-state.inspect-read-only']
 assert not (B/(N+'.approval.json')).exists() and not (B/(N+'.execution-progress.json')).exists()
 assert not list(B.glob(N+'-step*-*.evidence.json'))
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['project_reference']==PROJECT and r['fresh_auth_admin_key_create_count_authorized']==0 and r['github_secret_binding_create_count_authorized']==0
 assert r['fresh_auth_admin_key_delete_count_authorized']==0 and r['github_secret_binding_delete_count_authorized']==0
 assert r['temporary_session_issue_count_authorized']==1 and r['global_logout_count_authorized']==1 and r['retry_authorized'] is False
 assert r['implementation_handoff_execution_authorized'] is False and r['data_operation_authorized'] is False
 assert r['credential_retirement_authorized'] is False
 assert r['credential_retirement_deferred_until_after_separately_governed_implementation_handoff'] is True
 assert r['post_success_next_boundary']=='SEPARATELY_GOVERNED_ACCEPT_IMPLEMENTATION_HANDOFF_USING_EXISTING_PROVEN_TEMPORARY_BINDING'
 assert r['post_success_credential_state']=='PRESERVE_EXACT_V4_KEY_AND_GITHUB_BINDING_UNCHANGED'
 assert r['step1_executor_digest']==raw(ROOT/'scripts/development_provider_adapter_positive_auth_v4_continuation_v1.py')
 assert r['step1_workflow_digest']==raw(ROOT/'.github/workflows/development-provider-adapter-positive-auth-v4-continuation-v1-step1.yml')
 assert r['surface_correction_success_evidence_digest']==CORR_EVID and r['surface_correction_execution_progress_digest']==CORR_PROGRESS
 assert r['v4_stopped_progress_digest']==V4_STOP
 session=r['session_verification']; assert session['interaction_surface']=='supabase.mcp.execute_sql' and session['credential_class']=='NONE'
 assert session['expected_result']=={'session_count':0,'refresh_token_count':0} and session['query_count']==1 and session['retry_authorized'] is False
 assert prep['evidence_digest']==PREP_DIGEST==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
 assert prep['provider_authority']=='NONE' and prep['external_provider_contact']=='PROHIBITED' and prep['resource_contract_digest']==RESOURCE_DIGEST
 assert prep['security_state']['provider_contact_performed'] is False and prep['security_state']['credential_retirement_authorized'] is False
 assert prep['security_state']['implementation_handoff_execution_authorized'] is False
 corr=load(CORR+'.execution-progress.json'); v4=load(V4+'.execution-progress.json')
 assert corr['overall_state']=='COMPLETED' and corr['progress_digest']==CORR_PROGRESS==progress_digest(corr)
 assert raw(B/(CORR+'-success.evidence.json'))==CORR_EVID
 assert v4['overall_state']=='STOPPED' and v4['progress_digest']==V4_STOP==progress_digest(v4)
 assert all(s['authorization_state']=='BLOCKED' for s in v4['step_states'][4:])
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST==progress_digest(g)
 executor._validate_boundary(p,r,g)
 rendered='\n'.join((B/(N+x)).read_text() for x in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
 for bad in ('Bearer eyJ','"access_token":','"refresh_token":','service_role_key'): assert bad not in rendered
 assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
 print('DEVELOPMENT provider-adapter positive-auth v4 continuation v1: PASS (READY_FOR_APPROVAL; 2 steps only; auth proof + zero-state; handoff and retirement separately governed; existing v4 key/binding preserved)')
 return 0
if __name__=='__main__': raise SystemExit(main())
