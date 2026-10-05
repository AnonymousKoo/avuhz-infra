#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT))

from avuhz_engineering.authorization_plan import plan_digest, progress_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

ROOT=Path(__file__).resolve().parents[2]
B=ROOT/'contracts/plans/v1'
S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v4-stale-credential-retirement-v2'
RESOURCE='sha256:f64da257fe32bb578bdb2936e6251675e4e61b429db87013b3c2ee53bb823f97'
PREP='sha256:6279108dd1dbf7dad319d977a82c954b7fcc768916af058fbfc2a14d59000bdd'
PLAN='sha256:b012b3340f63afc8838d0516ca83c3a7b51d8c829528c40be0050a4cd48cef15'
PROGRESS='sha256:2deb6de046900a2b061cd2201f401f07f5b96f7db71e0df8923bb60c08abd3b8'
ZERO='sha256:15a15f8d6ad651d2140423e63fa5de42c42c9e6a6f18187e875b5386a6c9315d'
ZERO_PROGRESS='sha256:4c99f4933785fe8cc77c6379c957bb2e76a0bd7ec94be7b20dc8a2c84bcf93c1'
START='2026-10-05T13:00:00Z'
END='2026-10-05T17:00:00Z'

def load(suffix: str) -> dict:
    return json.loads((B/(N+suffix)).read_text())

def main() -> None:
    r=load('.resource.json'); e=load('-preparation.evidence.json'); p=load('.plan.json'); g=load('.progress.json')
    assert r['contract_digest']==RESOURCE==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
    assert e['evidence_digest']==PREP==canonical_digest({k:v for k,v in e.items() if k!='evidence_digest'})
    assert p['plan_digest']==PLAN==plan_digest(p)
    assert g['progress_digest']==PROGRESS==progress_digest(g)
    validate_plan(p,S); validate_progress(p,g,S)
    assert p['environment']=='DEVELOPMENT' and p['target']['project_reference']=='pwlhruwutoitnieactol' and p['target']['responsibility']=='AUTH'
    assert p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END}
    assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED' and p['definition_status']=='READY_FOR_APPROVAL'
    assert g['overall_state']=='NOT_STARTED'
    assert len(p['steps'])==4 and len(g['step_states'])==4
    assert all((s['authorization_state'],s['execution_state'],s['verification_state'],s['authorization_consumed'])==('PENDING','NOT_STARTED','NOT_STARTED',False) for s in g['step_states'])
    assert r['lineage']['corrective_zero_state_evidence_digest']==ZERO and r['lineage']['corrective_zero_state_execution_progress_digest']==ZERO_PROGRESS
    assert r['lineage']['corrective_zero_state_result']=={'session_count':0,'refresh_token_count':0}
    assert r['authorized_counts']=={'supabase_key_delete':1,'supabase_key_absence_read':1,'github_environment_secret_delete':1,'github_secret_absence_read':1,'credential_create':0,'session_issue':0,'token_issue':0,'implementation_handoff_execute':0,'auth_retry':0}
    assert r['retirement_interactions']['step1']['interaction_surface']=='supabase.dashboard.settings.api-keys'
    assert r['retirement_interactions']['step1']['execution_actor']=='OWNER_MANUAL_FIREFOX'
    assert r['retirement_interactions']['step2']['interaction_surface']=='supabase.dashboard.settings.api-keys'
    assert r['retirement_interactions']['step2']['execution_actor']=='OWNER_MANUAL_FIREFOX'
    assert r['retirement_interactions']['step3']['interaction_surface']=='github.cli.gh-secret-delete'
    assert r['retirement_interactions']['step3']['execution_actor']=='AGENT_AUTHENTICATED_GH_CLI'
    assert r['retirement_interactions']['step4']['interaction_surface']=='github.cli.gh-secret-list'
    assert r['retirement_interactions']['step4']['execution_actor']=='AGENT_AUTHENTICATED_GH_CLI'
    required={(x['evidence_type'],x['exact_digest']) for x in p['steps'][0]['required_evidence']}
    assert ('auth.provider-adapter-positive-auth.cleanup.verified',ZERO) in required
    assert ('authorization-plan.execution-progress',ZERO_PROGRESS) in required
    assert ('auth.provider-adapter-positive-auth.stale-credential-retirement.prepared',PREP) in required
    rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
    for forbidden in ('service_role','sb_secret_','access-material','refresh-material','Bearer eyJ'):
        assert forbidden not in rendered
    assert not (B/(N+'.approval.json')).exists()
    assert not (B/(N+'.execution-progress.json')).exists()
    assert not list(B.glob(N+'-step*-success.evidence.json'))
    print('DEVELOPMENT provider-adapter positive-auth v4 stale credential retirement v2: PASS (READY_FOR_APPROVAL; canonical 0/0 reused; Firefox owner key retirement/absence; gh CLI secret retirement/absence; no auth retry/session/handoff authority)')

if __name__=='__main__':
    main()
