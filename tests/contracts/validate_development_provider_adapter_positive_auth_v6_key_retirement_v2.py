#!/usr/bin/env python3
from __future__ import annotations
import json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress, plan_digest, progress_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v2'; V1='development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v1'; START='2026-10-05T20:30:00Z'; END='2026-10-05T23:30:00Z'; OBS='2026-10-05T19:33:00Z'; LATE='sha256:92b07fb7f7fec8c93603160f9404def011256eb0cbd243068c8e0090905074b4'
def load(n): return json.loads((B/n).read_text())
def main():
 r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); late=load(V1+'-late-window-rejection.evidence.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert late['evidence_digest']==LATE==canonical_digest({k:v for k,v in late.items() if k!='evidence_digest'})
 assert late['outcome']=='REJECTED_LATE_APPROVAL_NONCANONICALIZABLE' and late['approval_artifact_created'] is False and late['approval_canonicalized'] is False
 assert all(v is False for v in late['provider_effects'].values())
 assert r['contract_digest']==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert prep['evidence_digest']==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'}) and prep['late_approval_rejection_evidence_digest']==LATE
 assert p['plan_version']==2 and p['plan_digest']==plan_digest(p) and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END}
 assert r['target_key_reference']=='impl_handoff_provider_adapter_positive_auth_v6_ephemeral'
 assert r['github_secret_binding_name']=='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V6_EPHEMERAL'
 assert r['authorized_counts']=={'supabase_key_delete':1,'supabase_key_absence_read':1,'github_secret_absence_read':1,'github_environment_secret_delete':0,'credential_create':0,'session_issue':0,'token_issue':0,'implementation_handoff_execute':0}
 assert all(v is False for v in r['security_rules'].values())
 assert [s['operation'] for s in p['steps']]==['provider.auth-admin-credential.delete-dedicated-secret-key','provider.auth-admin-credential.verify-dedicated-secret-key-absent','provider.auth-secret-binding.verify-github-environment-reference-absent']
 assert g==initial_progress(p,S,g['progress_id'],OBS) and g['overall_state']=='NOT_STARTED' and g['progress_digest']==progress_digest(g)
 assert not (B/(N+'.approval.json')).exists() and not (B/(N+'.execution-progress.json')).exists()
 rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
 assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
 print('DEVELOPMENT provider-adapter positive-auth v6 key retirement v2: PASS (PREPARED / UNAPPROVED / UNEXECUTED; forward-only replacement after late v1 approval)')
if __name__=='__main__': main()
