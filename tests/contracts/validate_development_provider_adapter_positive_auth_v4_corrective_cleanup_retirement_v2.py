#!/usr/bin/env python3
from __future__ import annotations
import json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,progress_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v4-corrective-cleanup-retirement-v2'
V1='development-implementation-handoff-provider-adapter-positive-auth-v4-corrective-cleanup-retirement-v1'
CONT='development-implementation-handoff-provider-adapter-positive-auth-v4-continuation-v1'
PLAN_ID='f0f9e805-8429-5e0f-b604-471f36e4528f'
PLAN_DIGEST='sha256:311b9fb613104fc41f4e0393984e3c5c05652baa15200dabb1ad65f2355a80c0'
RESOURCE_ID='324774e6-5be4-59d8-9b68-fa14e34eddcb'
RESOURCE_DIGEST='sha256:96fae38d19b924600766e512ff93bd39d62f63e4f95112dbc7efc411f800af5e'
PREP_DIGEST='sha256:720f6932acd5dc57a76e7e7821926c325bf3c93c700ebe474280f29204710d83'
PROGRESS_ID='3cd10755-39f9-545c-9f66-5b06eed5db76'
PROGRESS_DIGEST='sha256:58c18f703e35c2eeedb06e493b28ba83712510f0a52e574121d0874bbc4a5a1c'
CREATED_AT='2026-10-05T02:31:27Z'; WINDOW_START='2026-10-05T03:15:00Z'; WINDOW_END='2026-10-05T06:00:00Z'
PROJECT='pwlhruwutoitnieactol'
KEY='impl_handoff_provider_adapter_positive_auth_v4_ephemeral'
GH='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V4_EPHEMERAL'
FAILURE='sha256:d0adabce4a18b043eba5204b9896e8a454a4061d90a690a8a86df20b7852441d'
STOPPED='sha256:42ad20cde3ab60c8b040139ff34a6078d7097050d43e9a74cdc352dada0bd2db'
KEY_CREATED='sha256:69cfb113f70f7e87ac681c7c0123dc338808f129a9f2fe534661b98805796302'
GH_CREATED='sha256:947336db2db2cc49029949d363b9cc34904ce0753d424887cc22504a9f1a779e'
GH_VERIFIED='sha256:b32dba957f080e4f0df22d3dd572afd2e2172c0f63c157f1a8328ca11a9aea0d'
QUERY="""select
  (select count(*) from auth.sessions) as session_count,
  (select count(*) from auth.refresh_tokens) as refresh_token_count;"""

def load(name): return json.loads((B/name).read_text())

def main():
    r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json')
    validate_plan(p,S); validate_progress(p,g,S)
    v1r=load(V1+'.resource.json'); v1p=load(V1+'.plan.json'); v1g=load(V1+'.progress.json'); v1prep=load(V1+'-preparation.evidence.json')
    assert v1p['plan_id']=='c4d14e3c-72fe-57f7-ae9a-3b9ea97fa74a' and v1p['plan_digest']=='sha256:819b9ef12bd7a4b25924e0ea1487f9da72b94f5215a571712557d773c82d2d2e'
    assert v1g['progress_digest']=='sha256:60f2271ba9b9ccfab1950729abf629a0a4817c5e3a580456b59e29cadbe57f9c' and v1g['overall_state']=='NOT_STARTED'
    assert all(x['authorization_state']=='PENDING' and x['execution_state']=='NOT_STARTED' and not x['authorization_consumed'] for x in v1g['step_states'])
    assert not (B/(V1+'.approval.json')).exists() and not (B/(V1+'.execution-progress.json')).exists()
    assert p['plan_id']==PLAN_ID and p['plan_version']==2 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
    assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
    assert p['environment']=='DEVELOPMENT' and p['target']['project_reference']==PROJECT and p['target']['responsibility']=='AUTH'
    assert p['authorization_window']=={'binding_state':'BOUND','starts_at':WINDOW_START,'expires_at':WINDOW_END}
    assert r['resource_id']==RESOURCE_ID and r['resource_version']=='provider-adapter-positive-auth-v4-corrective-cleanup-retirement.v2'
    assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
    assert r['boundary']==N and r['project_reference']==PROJECT and r['fresh_provider_key_reference']==KEY and r['github_secret_binding_name']==GH
    assert r['supersedes_v1']=={'plan_id':v1p['plan_id'],'plan_digest':v1p['plan_digest'],'resource_digest':v1r['contract_digest'],'preparation_evidence_digest':v1prep['evidence_digest'],'progress_digest':v1g['progress_digest'],'progress_state':'NOT_STARTED','approval_present':False,'execution_progress_present':False,'reason':'v1 authorization window began before owner approval was canonical; v1 remains pristine and unexecuted; v2 shifts timing only'}
    assert prep['supersedes_v1']==r['supersedes_v1']
    lin=r['lineage']
    assert lin['stopped_continuation_plan_id']=='43baee79-d5ca-51de-b812-62761844aad0'
    assert lin['stopped_continuation_plan_digest']=='sha256:b3fe688ebb8e40da8f9c76db4f1054308e2a831ccd977b41852bb0322fb3ca32'
    assert lin['stopped_continuation_approval_digest']=='sha256:6c7dcfb95cf50ac79b9184839a36dd83957190aba454636dae37cbca4f53b94d'
    assert lin['stopped_continuation_execution_progress_digest']==STOPPED
    assert lin['stopped_continuation_step1_failure_evidence_digest']==FAILURE
    assert lin['failed_workflow_run_id']==37253641818 and lin['failed_workflow_run_attempt']==1
    assert lin['failed_execution_sha']=='54b159fd1ba6e6eb0ee1cfa0dca4482ae316b034'
    sv=r['session_state_verification']
    assert sv['interaction_surface']=='supabase.mcp.execute_sql' and sv['credential_class']=='NONE'
    assert sv['query']==QUERY and sv['query_sha256']=='sha256:da814cfcb440fc635827734ca3388cb1bbe3c77a302e371d8f283681edeb12d1'
    assert sv['query_count']==1 and sv['result_fields']==['session_count','refresh_token_count'] and sv['expected_result']=={'session_count':0,'refresh_token_count':0}
    assert sv['aggregate_only'] is True and sv['raw_rows_authorized'] is False and sv['additional_sql_authorized'] is False and sv['retry_authorized'] is False
    assert r['authorized_counts']=={'session_state_aggregate_read':1,'supabase_key_delete':1,'github_environment_secret_delete':1,'supabase_key_absence_read':1,'github_secret_absence_read':1,'session_cleanup_mutation':0,'positive_auth_retry':0,'new_authentication':0,'session_issue':0,'token_issue':0,'implementation_handoff_execute':0}
    assert all(v is False for v in r['security_rules'].values())
    assert r['failure_handling']['unknown_session_state_at_entry'] is True and r['failure_handling']['zero_state_required_before_retirement'] is True
    assert r['failure_handling']['retirement_after_nonzero_or_ambiguous_state_authorized'] is False and r['failure_handling']['retry_failed_positive_auth_authorized'] is False
    assert prep['evidence_digest']==PREP_DIGEST==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
    assert prep['canonical_main_at_start']=='e5a01228e82ef13ad55b7c0039a878b19a72a118'
    assert prep['provider_authority']=='NONE' and prep['external_provider_contact']=='PROHIBITED' and prep['resource_contract_digest']==RESOURCE_DIGEST
    assert prep['authorization_window']=={'starts_at':WINDOW_START,'expires_at':WINDOW_END}
    assert all(v is False for v in prep['security_state'].values())
    steps=p['steps']; assert len(steps)==5 and p['ordered_step_ids']==[s['step_id'] for s in steps]
    assert all('positive-auth-v4-corrective-cleanup-retirement-v2' in s['step_id'] for s in steps)
    assert [s['execution_class'] for s in steps]==['PROVIDER_READ','PROVIDER_MUTATION','PROVIDER_MUTATION','PROVIDER_READ','PROVIDER_READ']
    assert [s['operation'] for s in steps]==['provider.auth-session-state.inspect-read-only','provider.auth-admin-credential.delete-dedicated-secret-key','provider.auth-secret-binding.delete-github-environment-reference','provider.auth-admin-credential.verify-dedicated-secret-key-absent','provider.auth-secret-binding.verify-github-environment-reference-absent']
    assert all(s['resource']['exact_digest']==RESOURCE_DIGEST and s['resource']['exact_version']=='provider-adapter-positive-auth-v4-corrective-cleanup-retirement.v2' for s in steps)
    assert steps[0]['credential_policy']=={'permitted':False,'allowed_classes':['NONE'],'values_stored':False}
    read_bind=[x for x in steps[0]['binding_declarations'] if x.get('evidence_type')=='provider.read-capability.observed']; assert len(read_bind)==1 and read_bind[0]['binding_id'].endswith('.step1-supabase-mcp-read')
    assert 'supabase.mcp.execute_sql' in steps[0]['expected_postcondition'] and 'count.nonzero' in steps[0]['stop_conditions'] and 'provider.mutation' in steps[0]['prohibited_actions']
    assert all(s['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False} for s in steps[1:])
    assert steps[0]['dependency_step_ids']==[]
    for i in range(1,5): assert steps[i]['dependency_step_ids']==[steps[i-1]['step_id']]
    first={(x['evidence_type'],x['exact_digest']) for x in steps[0]['required_evidence']}
    assert ('authorization-plan.execution-progress',v1g['progress_digest']) in first
    binds={x['binding_id']:x for x in steps[0]['binding_declarations']}
    assert binds['binding.development.provider-adapter-positive-auth-v4-corrective-cleanup-retirement-v2.v1-plan']['preapproval_value']['value']==v1p['plan_digest']
    assert binds['binding.development.provider-adapter-positive-auth-v4-corrective-cleanup-retirement-v2.v1-progress']['preapproval_value']['value']==v1g['progress_digest']
    for item in [('auth.provider-adapter-positive-auth.live-verified-logout-accepted',FAILURE),('authorization-plan.execution-progress',STOPPED),('auth.provider-adapter-positive-auth.admin-credential.created',KEY_CREATED),('auth.provider-adapter-positive-auth.github-binding.created',GH_CREATED),('auth.provider-adapter-positive-auth.github-binding.verified',GH_VERIFIED),('auth.provider-adapter-positive-auth.corrective-cleanup-retirement.prepared',PREP_DIGEST)]: assert item in first
    assert KEY in steps[1]['resource']['resource_reference'] and GH in steps[2]['resource']['resource_reference'] and KEY in steps[3]['resource']['resource_reference'] and GH in steps[4]['resource']['resource_reference']
    for forbidden in ('implementation-handoff.execute','session.issue','token.issue','token.refresh','logout.execute','positive-auth-continuation-v1.retry'): assert forbidden in p['prohibited_actions']
    assert g==initial_progress(p,S,PROGRESS_ID,CREATED_AT) and g['progress_digest']==PROGRESS_DIGEST==progress_digest(g) and g['overall_state']=='NOT_STARTED'
    assert all((x['authorization_state'],x['execution_state'],x['verification_state'],x['authorization_consumed'])==('PENDING','NOT_STARTED','NOT_STARTED',False) for x in g['step_states'])
    assert not (B/(N+'.approval.json')).exists() and not (B/(N+'.execution-progress.json')).exists() and not list(B.glob(N+'-step*.evidence.json'))
    f=load(CONT+'-step1-failure.evidence.json'); e=load(CONT+'.execution-progress.json')
    assert canonical_digest(f)==FAILURE and e['progress_digest']==STOPPED==progress_digest(e) and e['overall_state']=='STOPPED'
    assert e['step_states'][0]['authorization_state']=='CONSUMED' and e['step_states'][0]['execution_state']=='FAILED' and e['step_states'][0]['verification_state']=='FAIL'
    assert e['step_states'][1]['authorization_state']=='BLOCKED' and e['step_states'][1]['execution_state']=='NOT_STARTED'
    rendered='\n'.join((B/(N+x)).read_text() for x in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
    for bad in ('Bearer eyJ','"access_token":','"refresh_token":','service_role_key','sb_secret_'): assert bad not in rendered
    assert re.search(r'postgres(?:ql)?://[^\s/:]+:[^\s/@]+@',rendered,re.I) is None
    print('DEVELOPMENT provider-adapter positive-auth v4 corrective cleanup/retirement v2: PASS (READY_FOR_APPROVAL; pristine 5-step boundary; Supabase MCP zero-state read first; retirement only after 0/0; no retry/handoff/provider authority)')
    return 0
if __name__=='__main__': raise SystemExit(main())
