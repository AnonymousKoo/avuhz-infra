#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress, plan_digest, progress_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v6'; V5='development-implementation-handoff-provider-adapter-positive-auth-v5'; PROJECT='pwlhruwutoitnieactol'; KEY='impl_handoff_provider_adapter_positive_auth_v6_ephemeral'; GH='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V6_EPHEMERAL'
CREATED='2026-10-05T14:20:52Z'; START='2026-10-05T16:00:00Z'; END='2026-10-05T22:00:00Z'; REJECT='sha256:e29e56af04b0b2664aa8d6749c367184f2c06446c2eb50fa1cbad4e394c09468'
def load(n): return json.loads((B/n).read_text())
def raw(p): return 'sha256:'+hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); rej=load(V5+'-preactivation-integrity-rejection.evidence.json')
 validate_plan(p,S); validate_progress(p,g,S)
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
 assert not (B/(N+'.approval.json')).exists() and not (B/(N+'.execution-progress.json')).exists()
 alltext='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
 assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',alltext) is None
 print('DEVELOPMENT provider-adapter positive-auth v6: PASS (PREPARED / UNAPPROVED / UNEXECUTED; v5 target-integrity rejection bound; exact v6 credential namespace; no provider authority)')
if __name__=='__main__': main()
