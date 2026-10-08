#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest,initial_progress,plan_digest,progress_digest,validate_approval,validate_plan,validate_progress
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
APPROVAL_ID='0ce18d6f-46d7-49a4-803b-6cec5fd62c2b'
APPROVAL_DIGEST='sha256:6c7dcfb95cf50ac79b9184839a36dd83957190aba454636dae37cbca4f53b94d'
APPROVAL_FILE_DIGEST='sha256:c980e33ee7e66f63b95762124fc6c024b68a5077650bfa5de6fe76518754ff53'
APPROVED_AT='2026-10-05T01:49:23Z'
WORKFLOW_RUN_ID=37253641818
EXECUTION_SHA='54b159fd1ba6e6eb0ee1cfa0dca4482ae316b034'
PREFLIGHT_AT='2026-10-05T02:00:34Z'
FAILURE_AT='2026-10-05T02:00:56Z'
RECORDED_AT='2026-10-05T02:04:24Z'
SAFE_ERROR_CODE='STOP_REQUIRES_FORWARD_ONLY_CORRECTIVE_CLEANUP_AND_RETIREMENT'
CAPABILITY_DIGEST='sha256:c13d080174a2852254982b64c54834e72808af97eabad4473c63a95086caac74'
FAILURE_DIGEST='sha256:d0adabce4a18b043eba5204b9896e8a454a4061d90a690a8a86df20b7852441d'
EXECUTION_PROGRESS_DIGEST='sha256:42ad20cde3ab60c8b040139ff34a6078d7097050d43e9a74cdc352dada0bd2db'
PROJECT='pwlhruwutoitnieactol'; WINDOW_START='2026-10-05T02:00:00Z'; WINDOW_END='2026-10-05T06:00:00Z'

def load(name): return json.loads((B/name).read_text())
def raw(p): return 'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()

def main():
 r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); a=load(N+'.approval.json'); f=load(N+'-step1-failure.evidence.json'); e=load(N+'.execution-progress.json')
 validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,WINDOW_START); validate_progress(p,e,S)
 assert p['plan_id']==PLAN_ID and p['plan_version']==1 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':WINDOW_START,'expires_at':WINDOW_END}
 assert len(p['steps'])==2 and p['ordered_step_ids']==[x['step_id'] for x in p['steps']]
 assert [x['operation'] for x in p['steps']]==['provider.auth-session.provider-adapter-recover-validate-live-probe-and-logout-global','provider.auth-session-state.inspect-read-only']
 assert raw(B/(N+'.approval.json'))==APPROVAL_FILE_DIGEST
 assert a['approval_id']==APPROVAL_ID and a['plan_id']==PLAN_ID and a['plan_version']==1
 assert a['plan_digest']==PLAN_DIGEST and a['owner_identity']=='github:AnonymousKoo'
 assert a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
 assert a['effective_at']==WINDOW_START and a['expires_at']==WINDOW_END
 assert a['approved_at']==APPROVED_AT and a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
 assert a['approval_digest']==APPROVAL_DIGEST==approval_digest(a) and APPROVED_AT < WINDOW_START
 assert canonical_digest(f)==FAILURE_DIGEST
 assert f['evidence_type']=='auth.provider-adapter-positive-auth.live-verified-logout-accepted'
 assert f['environment']=='DEVELOPMENT' and f['responsibility']=='AUTH' and f['provider_reference']=='supabase' and f['project_reference']==PROJECT
 assert f['plan_id']==PLAN_ID and f['plan_version']==1 and f['plan_digest']==PLAN_DIGEST
 assert f['approval_id']==APPROVAL_ID and f['approval_digest']==APPROVAL_DIGEST
 assert f['step_id']==p['steps'][0]['step_id'] and f['attempt']==1
 assert f['outcome']=='FAILED_UNVERIFIED' and f['safe_error_code']==SAFE_ERROR_CODE and f['classification']==SAFE_ERROR_CODE
 assert f['execution_observation']=={
   'workflow_run_id':WORKFLOW_RUN_ID,'execution_sha':EXECUTION_SHA,'workflow_event':'workflow_dispatch','run_attempt':1,'conclusion':'failure',
   'workflow_started_at':'2026-10-05T02:00:22Z','job_started_at':'2026-10-05T02:00:28Z',
   'authorization_preflight_passed_at':PREFLIGHT_AT,'execution_step_started_at':'2026-10-05T02:00:34Z','failure_observed_at':FAILURE_AT,
   'canonical_main_binding_passed':True,'dispatch_confirmation_passed':True,'plan_binding_passed':True,'authorization_window_check_passed':True,
   'executor_source_binding_passed':True,'authorization_preflight_passed_before_runtime_secret_resolution':True,'executor_entered':True,
   'provider_mutation_attempted':True,'retry_occurred':False}
 assert f['sanitized_runtime_outcome']=={
   'cleanup_verified':False,'credential_retirement_obligation_remains':True,'global_logout_acceptance_proven':False,'global_logout_accepted':False,
   'ordinary_later_steps_authorized':False,'retry_authorized':False,'separately_authorized_corrective_cleanup_required':True,'temporary_session_state':'UNKNOWN'}
 assert f['authority_state']=={'step1_authorization':'CONSUMED','authorization_consumed':True,'retry_authorized':False,'ordinary_later_steps_authorized':False}
 assert f['credential_material_retained'] is False and f['token_material_retained'] is False and f['pii_retained'] is False
 assert not any(f['security_state'].values()) and f['recorded_at']==RECORDED_AT
 assert e['progress_digest']==EXECUTION_PROGRESS_DIGEST==progress_digest(e) and e['record_version']==3 and e['overall_state']=='STOPPED' and e['updated_at']==RECORDED_AT
 x=e['step_states'][0]
 assert (x['authorization_state'],x['execution_state'],x['verification_state'],x['authorization_consumed'],x['safe_error_code'])==('CONSUMED','FAILED','FAIL',True,SAFE_ERROR_CODE)
 assert x['evidence']==[{'evidence_type':f['evidence_type'],'evidence_reference':f'github.actions.run.{WORKFLOW_RUN_ID}.step1.attempt1.failed-unverified','evidence_digest':FAILURE_DIGEST,'recorded_at':RECORDED_AT}]
 assert 'temporary session state UNKNOWN' in x['observed_postcondition'] and 'Step 2' in x['observed_postcondition']
 assert len(x['binding_assertions'])==1
 b=x['binding_assertions'][0]
 assert b['binding_id'].endswith('.admin-executor-capability') and b['phase']=='RESOLVED_BY_STEP_PREFLIGHT' and b['evidence_type']=='auth.admin-executor-capability.observed'
 assert b['evidence_digest']==CAPABILITY_DIGEST and b['value_digest']==CAPABILITY_DIGEST and b['sanitized_value'] is None and b['recorded_at']==PREFLIGHT_AT
 y=e['step_states'][1]
 assert (y['authorization_state'],y['execution_state'],y['verification_state'],y['authorization_consumed'])==('BLOCKED','NOT_STARTED','NOT_STARTED',False)
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
 rendered='\n'.join((B/(N+x)).read_text() for x in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json','-step1-failure.evidence.json','.execution-progress.json'))
 for bad in ('Bearer eyJ','"access_token":','"refresh_token":','service_role_key'): assert bad not in rendered
 assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
 print('DEVELOPMENT provider-adapter positive-auth v4 continuation v1: PASS (STOPPED; Step 1 CONSUMED/FAILED/FAIL; one authorized run; session state UNKNOWN; logout unproven; retry prohibited; Step 2 BLOCKED; corrective cleanup/retirement required)')
 return 0
if __name__=='__main__': raise SystemExit(main())
