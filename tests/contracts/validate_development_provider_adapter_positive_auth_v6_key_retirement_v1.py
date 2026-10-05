#!/usr/bin/env python3
from __future__ import annotations
import json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress, plan_digest, progress_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v1'; V6='development-implementation-handoff-provider-adapter-positive-auth-v6'; KEY='impl_handoff_provider_adapter_positive_auth_v6_ephemeral'; GH='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V6_EPHEMERAL'; CREATED='2026-10-05T19:21:11Z'; START='2026-10-05T19:25:00Z'; END='2026-10-05T22:00:00Z'
E1='sha256:b0a29a99d233db3526179e77b841c27e0946760be3894f51050e147ba3b5a046'; X='sha256:c5d7bf0545ca10f453f4ac9775edccb1a2eb5e63efa7966225b95f5e5659df6f'
def load(n): return json.loads((B/n).read_text())
def main():
 r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); v6x=load(V6+'.execution-progress.json'); e1=load(V6+'-step01-success.evidence.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert r['contract_digest']==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert prep['evidence_digest']==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
 assert p['plan_digest']==plan_digest(p)
 assert g['progress_digest']==progress_digest(g) and g['overall_state']=='NOT_STARTED'
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['environment']=='DEVELOPMENT' and p['target']['project_reference']=='pwlhruwutoitnieactol' and p['target']['responsibility']=='AUTH'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END}
 assert r['target_key_reference']==KEY and r['github_secret_binding_name']==GH
 assert r['lineage']['v6_execution_progress_digest']==X and v6x['progress_digest']==X and v6x['overall_state']=='STOPPED'
 assert r['lineage']['v6_step1_key_creation_evidence_digest']==E1 and canonical_digest(e1)==E1
 assert r['authorized_counts']=={'supabase_key_delete':1,'supabase_key_absence_read':1,'github_secret_absence_read':1,'github_environment_secret_delete':0,'credential_create':0,'session_issue':0,'token_issue':0,'implementation_handoff_execute':0}
 assert all(x is False for x in r['security_rules'].values())
 assert len(p['steps'])==3 and [s['execution_class'] for s in p['steps']]==['PROVIDER_MUTATION','PROVIDER_READ','PROVIDER_READ']
 assert [s['operation'] for s in p['steps']]==['provider.auth-admin-credential.delete-dedicated-secret-key','provider.auth-admin-credential.verify-dedicated-secret-key-absent','provider.auth-secret-binding.verify-github-environment-reference-absent']
 assert KEY in p['steps'][0]['resource']['resource_reference'] and KEY in p['steps'][1]['resource']['resource_reference'] and GH in p['steps'][2]['resource']['resource_reference']
 assert not (B/(N+'.approval.json')).exists() and not (B/(N+'.execution-progress.json')).exists()
 rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
 assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
 print('DEVELOPMENT provider-adapter positive-auth v6 key retirement v1: PASS (PREPARED / UNAPPROVED / UNEXECUTED; exact one-key delete + key absence + GitHub absence only)')
if __name__=='__main__': main()
