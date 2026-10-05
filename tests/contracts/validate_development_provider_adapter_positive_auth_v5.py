#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress, plan_digest, progress_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v5'; PROJECT='pwlhruwutoitnieactol'; DATA_PROJECT='gnuqaefotwgkwurjpyik'; KEY='impl_handoff_provider_adapter_positive_auth_v5_ephemeral'; GH='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V5_EPHEMERAL'
CREATED='2026-10-05T14:04:53Z'; START='2026-10-05T15:00:00Z'; END='2026-10-05T21:00:00Z'
def load(s): return json.loads((B/(N+s)).read_text())
def raw(p): return 'sha256:'+hashlib.sha256(Path(p).read_bytes()).hexdigest()
def evdig(d):
    return d['evidence_digest'] if 'evidence_digest' in d else canonical_digest(d)
def main():
    r=load('.resource.json'); e=load('-preparation.evidence.json'); p=load('.plan.json'); g=load('.progress.json')
    validate_plan(p,S); validate_progress(p,g,S)
    assert r['contract_digest']==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
    assert e['evidence_digest']==canonical_digest({k:v for k,v in e.items() if k!='evidence_digest'})
    assert p['plan_digest']==plan_digest(p)
    assert g['progress_digest']==progress_digest(g)
    assert p['plan_version']==5 and p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
    assert p['environment']=='DEVELOPMENT' and p['target']['project_reference']==PROJECT and p['target']['responsibility']=='AUTH'
    assert p['created_at']==CREATED and p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END}
    assert DATA_PROJECT not in json.dumps(r) and DATA_PROJECT not in json.dumps(p)
    assert r['boundary']==N and r['resource_version']=='provider-adapter-positive-auth.v5'
    assert r['fresh_provider_key_reference']==KEY and r['github_secret_binding_name']==GH
    assert r['step5_executor_digest']==raw(ROOT/'scripts/development_provider_adapter_positive_auth_v5.py')
    assert r['step5_workflow_digest']==raw(ROOT/'.github/workflows/development-provider-adapter-positive-auth-v5-step5.yml')
    assert r['failure_diagnostics_source_digest']==raw(ROOT/'src/avuhz_engineering/safe_auth_failure_diagnostics.py')
    assert r['preflight_contract']['interaction_surface']=='supabase.mcp.execute_sql' and r['preflight_contract']['credential_class']=='NONE'
    assert r['session_verification']['interaction_surface']=='supabase.mcp.execute_sql' and r['session_verification']['credential_class']=='NONE'
    assert r['preflight_contract']['expected_result']=={'auth_user_count':2,'target_identity_count':1,'target_password_null_count':1,'target_tenant_exact_count':1,'session_count':0,'refresh_token_count':0}
    assert r['post_cleanup_expected']=={'session_count':0,'refresh_token_count':0}
    assert r['retry_authorized'] is False and r['implementation_handoff_execution_authorized'] is False
    assert r['data_operation_authorized'] is False and r['render_mutation_authorized'] is False and r['n8n_operation_authorized'] is False
    assert r['staging_authorized'] is False and r['production_authorized'] is False
    diag=r['failure_diagnostics']
    assert diag['safe_error_code_retained'] and diag['failure_stage_retained']
    assert not diag['exception_text_retained'] and not diag['provider_payload_retained'] and not diag['credential_or_token_material_retained'] and not diag['pii_retained']
    cleanx=json.loads((B/'development-implementation-handoff-provider-adapter-positive-auth-v4-stale-credential-retirement-v2.execution-progress.json').read_text())
    clean2=json.loads((B/'development-implementation-handoff-provider-adapter-positive-auth-v4-stale-credential-retirement-v2-step2-success.evidence.json').read_text())
    clean4=json.loads((B/'development-implementation-handoff-provider-adapter-positive-auth-v4-stale-credential-retirement-v2-step4-success.evidence.json').read_text())
    assert cleanx['overall_state']=='COMPLETED' and cleanx['progress_digest']==r['required_clean_retirement_progress_digest']
    assert canonical_digest(clean2)==r['required_clean_key_absence_evidence_digest']
    assert canonical_digest(clean4)==r['required_clean_github_absence_evidence_digest']
    corr=json.loads((B/'development-implementation-handoff-provider-adapter-positive-auth-v4-step4-surface-correction-v1-success.evidence.json').read_text())
    corrx=json.loads((B/'development-implementation-handoff-provider-adapter-positive-auth-v4-step4-surface-correction-v1.execution-progress.json').read_text())
    assert evdig(corr)==r['required_step4_correction_evidence_digest'] and corrx['progress_digest']==r['required_step4_correction_progress_digest']
    cont=json.loads((B/'development-implementation-handoff-provider-adapter-positive-auth-v4-continuation-v1-step1-failure.evidence.json').read_text())
    contx=json.loads((B/'development-implementation-handoff-provider-adapter-positive-auth-v4-continuation-v1.execution-progress.json').read_text())
    assert canonical_digest(cont)==r['required_failed_continuation_evidence_digest'] and contx['progress_digest']==r['required_failed_continuation_progress_digest']
    assert e['resource_contract_digest']==r['contract_digest'] and e['observation_only'] is True and all(v is False for v in e['security_state'].values())
    assert len(p['steps'])==10 and p['ordered_step_ids']==[s['step_id'] for s in p['steps']]
    assert [s['ordinal'] for s in p['steps']]==list(range(1,11))
    assert all('positive-auth-v5' in s['step_id'] for s in p['steps'])
    assert all(s['resource']['exact_version']=='provider-adapter-positive-auth.v5' and s['resource']['exact_digest']==r['contract_digest'] for s in p['steps'])
    assert p['steps'][3]['operation']=='provider.auth-state.inspect-aggregate-only-via-supabase-mcp' and p['steps'][3]['credential_policy']=={'permitted':False,'allowed_classes':['NONE'],'values_stored':False}
    assert p['steps'][5]['operation']=='provider.auth-session-state.inspect-read-only-via-supabase-mcp' and p['steps'][5]['credential_policy']=={'permitted':False,'allowed_classes':['NONE'],'values_stored':False}
    assert p['steps'][4]['credential_policy']['allowed_classes']==['SUPABASE_AUTH_ADMIN_EPHEMERAL']
    assert 'coarse failure stage' in p['steps'][4]['expected_postcondition'] and 'ImplementationHandoff execution' in p['steps'][4]['expected_postcondition']
    assert g==initial_progress(p,S,g['progress_id'],CREATED) and g['overall_state']=='NOT_STARTED'
    assert not (B/(N+'.approval.json')).exists() and not (B/(N+'.execution-progress.json')).exists()
    assert not list(B.glob(N+'-step*-success.evidence.json')) and not list(B.glob(N+'-step*-failure.evidence.json'))
    rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
    for forbidden in ('Bearer eyJ','"access_token":','"refresh_token":','service_role_key','postgresql://'): assert forbidden not in rendered
    assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
    print('DEVELOPMENT provider-adapter positive-auth v5: PASS (PREPARED / UNAPPROVED / UNEXECUTED; clean v4 retirement bound; Step 4+6 Supabase MCP aggregate reads; safe staged diagnostics; no provider authority)')
if __name__=='__main__': main()
