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
PROGRESS_ID='2df10de6-a149-5aa4-b5ce-4c23bd300074'; PROGRESS_DIGEST='sha256:140a47aa6f0ffdd7967952f1bb0e9951fd159196d2a55b2c9a2c8110a4741e98'
CORR_EVID='sha256:238b4af1586b4b57d919910acdd4042ea01abe95706a7133cadd9a8a6dc5887c'
CORR_PROGRESS='sha256:6b6eb329c6b945fde6f625be46794213b8f97a5126415a79389386547e123bdc'
V4_STOP='sha256:89597fb31105b2398295ba8c0be4534c7de80e7813b673e108db83a57a301c9c'
APPROVAL_ID='0ce18d6f-46d7-49a4-803b-6cec5fd62c2b'; APPROVAL_DIGEST='sha256:6c7dcfb95cf50ac79b9184839a36dd83957190aba454636dae37cbca4f53b94d'
APPROVAL_FILE_DIGEST='sha256:c980e33ee7e66f63b95762124fc6c024b68a5077650bfa5de6fe76518754ff53'; APPROVED_AT='2026-10-05T01:49:23Z'
FAILURE_DIGEST='sha256:b506054b1de690a5a3472a6582a3a6af5c6b0111e52100c9f0696d0cc5ea36f6'
EXECUTION_PROGRESS_DIGEST='sha256:a2d2ab7be85787ad00354ad43ab42db8b2db3533827447761c8b4207549b92f4'
CAPABILITY_DIGEST='sha256:c13d080174a2852254982b64c54834e72808af97eabad4473c63a95086caac74'
RUN_ID=37253641818; EXECUTION_SHA='54b159fd1ba6e6eb0ee1cfa0dca4482ae316b034'
PREFLIGHT_AT='2026-10-05T02:00:34Z'; FAILURE_AT='2026-10-05T02:00:56Z'; RECORDED_AT='2026-10-05T02:06:42Z'
SAFE='STOP_REQUIRES_FORWARD_ONLY_CORRECTIVE_CLEANUP_AND_RETIREMENT'
PROJECT='pwlhruwutoitnieactol'; WINDOW_START='2026-10-05T02:00:00Z'; WINDOW_END='2026-10-05T06:00:00Z'

def load(name): return json.loads((B/name).read_text())
def raw(p): return 'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()

def main():
 r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); a=load(N+'.approval.json')
 failure=load(N+'-step1-failure.evidence.json'); execution=load(N+'.execution-progress.json')
 validate_plan(p,S); validate_progress(p,g,S); validate_progress(p,execution,S); validate_approval(p,a,S,WINDOW_START)
 assert p['plan_id']==PLAN_ID and p['plan_version']==1 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':WINDOW_START,'expires_at':WINDOW_END}
 assert len(p['steps'])==2 and [x['operation'] for x in p['steps']]==['provider.auth-session.provider-adapter-recover-validate-live-probe-and-logout-global','provider.auth-session-state.inspect-read-only']
 assert raw(B/(N+'.approval.json'))==APPROVAL_FILE_DIGEST
 assert a['approval_id']==APPROVAL_ID and a['approval_digest']==APPROVAL_DIGEST==approval_digest(a) and a['plan_digest']==PLAN_DIGEST
 assert a['effective_at']==WINDOW_START and a['expires_at']==WINDOW_END and a['approved_at']==APPROVED_AT and APPROVED_AT < WINDOW_START
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['project_reference']==PROJECT and r['temporary_session_issue_count_authorized']==1 and r['global_logout_count_authorized']==1 and r['retry_authorized'] is False
 assert r['credential_retirement_authorized'] is False and r['implementation_handoff_execution_authorized'] is False and r['data_operation_authorized'] is False
 assert r['step1_executor_digest']==raw(ROOT/'scripts/development_provider_adapter_positive_auth_v4_continuation_v1.py')
 assert r['step1_workflow_digest']==raw(ROOT/'.github/workflows/development-provider-adapter-positive-auth-v4-continuation-v1-step1.yml')
 assert r['surface_correction_success_evidence_digest']==CORR_EVID and r['surface_correction_execution_progress_digest']==CORR_PROGRESS and r['v4_stopped_progress_digest']==V4_STOP
 session=r['session_verification']; assert session['expected_result']=={'session_count':0,'refresh_token_count':0} and session['query_count']==1 and session['retry_authorized'] is False
 assert prep['evidence_digest']==PREP_DIGEST==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
 corr=load(CORR+'.execution-progress.json'); v4=load(V4+'.execution-progress.json')
 assert corr['overall_state']=='COMPLETED' and corr['progress_digest']==CORR_PROGRESS==progress_digest(corr)
 assert raw(B/(CORR+'-success.evidence.json'))==CORR_EVID
 assert v4['overall_state']=='STOPPED' and v4['progress_digest']==V4_STOP==progress_digest(v4)
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST==progress_digest(g)
 executor._validate_boundary(p,r,g)

 assert canonical_digest(failure)==FAILURE_DIGEST
 assert failure['plan_id']==PLAN_ID and failure['approval_id']==APPROVAL_ID and failure['step_id']==p['steps'][0]['step_id']
 assert failure['attempt']==1 and failure['outcome']=='FAILED_UNVERIFIED' and failure['safe_error_code']==SAFE and failure['classification']==SAFE
 obs=failure['execution_observation']
 assert obs['workflow_run_id']==RUN_ID and obs['execution_sha']==EXECUTION_SHA and obs['workflow_event']=='workflow_dispatch' and obs['run_attempt']==1 and obs['conclusion']=='failure'
 assert obs['workflow_started_at']=='2026-10-05T02:00:22Z' and obs['job_started_at']=='2026-10-05T02:00:28Z'
 assert obs['authorization_preflight_passed_at']==PREFLIGHT_AT and obs['execution_step_started_at']=='2026-10-05T02:00:34Z' and obs['failure_observed_at']==FAILURE_AT
 assert obs['canonical_main_binding_passed'] and obs['dispatch_confirmation_passed'] and obs['plan_binding_passed'] and obs['authorization_window_check_passed']
 assert obs['executor_source_binding_passed'] and obs['authorization_preflight_passed_before_runtime_secret_resolution'] and obs['executor_entered'] and obs['provider_mutation_attempted']
 assert obs['retry_occurred'] is False
 out=failure['sanitized_runtime_outcome']
 assert out=={'cleanup_verified':False,'credential_retirement_obligation_remains':True,'global_logout_acceptance_proven':False,'global_logout_accepted':False,'ordinary_later_steps_authorized':False,'retry_authorized':False,'separately_authorized_corrective_cleanup_required':True,'temporary_session_state':'UNKNOWN'}
 assert failure['authority_state']=={'step1_authorization':'CONSUMED','authorization_consumed':True,'retry_authorized':False,'ordinary_later_steps_authorized':False}
 assert failure['credential_material_retained'] is False and failure['token_material_retained'] is False and failure['pii_retained'] is False
 assert not any(failure['security_state'].values()) and failure['recorded_at']==RECORDED_AT

 assert execution['progress_digest']==EXECUTION_PROGRESS_DIGEST==progress_digest(execution) and execution['record_version']==3 and execution['overall_state']=='STOPPED' and execution['updated_at']==RECORDED_AT
 s1,s2=execution['step_states']
 assert (s1['authorization_state'],s1['execution_state'],s1['verification_state'],s1['authorization_consumed'],s1['safe_error_code'])==('CONSUMED','FAILED','FAIL',True,SAFE)
 assert s1['evidence']==[{'evidence_type':failure['evidence_type'],'evidence_reference':f'github.actions.run.{RUN_ID}.step1.attempt1.failed-unverified','evidence_digest':FAILURE_DIGEST,'recorded_at':RECORDED_AT}]
 assert 'temporary session state UNKNOWN' in s1['observed_postcondition']
 assert len(s1['binding_assertions'])==1 and s1['binding_assertions'][0]['evidence_digest']==CAPABILITY_DIGEST and s1['binding_assertions'][0]['value_digest']==CAPABILITY_DIGEST and s1['binding_assertions'][0]['recorded_at']==PREFLIGHT_AT
 assert (s2['authorization_state'],s2['execution_state'],s2['verification_state'],s2['authorization_consumed'])==('BLOCKED','NOT_STARTED','NOT_STARTED',False)

 rendered='\n'.join((B/(N+x)).read_text() for x in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json','-step1-failure.evidence.json','.execution-progress.json'))
 for bad in ('Bearer eyJ','"access_token":','"refresh_token":','service_role_key'): assert bad not in rendered
 assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
 print('DEVELOPMENT provider-adapter positive-auth v4 continuation v1: PASS (STOPPED; Step 1 CONSUMED/FAILED/FAIL; one authorized run; session state UNKNOWN; logout unproven; retry prohibited; Step 2 BLOCKED; corrective cleanup/retirement required)')
 return 0
if __name__=='__main__': raise SystemExit(main())
