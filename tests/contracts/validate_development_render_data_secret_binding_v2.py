#!/usr/bin/env python3
"""Validate forward-only DEVELOPMENT Render DATA secret-binding v2 package."""
from __future__ import annotations
import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest, initial_progress, plan_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
SCHEMA=ROOT/'contracts/schemas/v1'; BASE=ROOT/'contracts/plans/v1'
V1_PLAN=BASE/'development-render-data-secret-binding-v1.plan.json'
V1_APPROVAL=BASE/'development-render-data-secret-binding-v1.approval.json'
V1_PROGRESS=BASE/'development-render-data-secret-binding-v1.progress.json'
V2_PLAN=BASE/'development-render-data-secret-binding-v2.plan.json'
V2_PROGRESS=BASE/'development-render-data-secret-binding-v2.progress.json'
V2_APPROVAL=BASE/'development-render-data-secret-binding-v2.approval.json'
RESOURCE=BASE/'development-render-data-secret-binding-v1.resource.json'
PLAN_ID='d3e83c4d-18b7-4e20-8202-869a5e85ad4a'
PLAN_DIGEST='sha256:42effa3e94fd40cdfa6855b7e4d7e7a5b0b0fbe5cdc2b578159547775dc25777'
PROGRESS_ID='18d6a55e-92ae-47c9-926d-80ec8205b891'
PROGRESS_DIGEST='sha256:d544fe81597ce4cd6c8a86bb1a45f5826040acf6e0fdf1e6df6f5c91bfc7f181'
RESOURCE_DIGEST='sha256:6b5a9d6b18d2ad26df6eb650ca6838545676464c76475e8a053b7710f4fd74f9'
V1_PLAN_DIGEST='sha256:b1340b65458ef487d7fdc037ca6e255f38018b39207ff15718f7d1d6182fdcf8'
V1_APPROVAL_DIGEST='sha256:d916a034dca70c662379f62041ff54f31888928f976382088e4ca52374634171'
V1_PROGRESS_DIGEST='sha256:8904127e314cdde0c2a7faf5ff754bdf20b48fad7a5ecca1393767f1dd0d4364'
STEP_ID='development.render.data-secret-binding-v2.step.01.bind-avuhz-postgres-dsn'
APPROVAL_ID='631f537e-d0bb-4e06-82af-9e4db1bc3051'
APPROVAL_DIGEST='sha256:2e5a7f422468ec66240c4acb78a72b1f697a402ce1b06aa79684b99d63909b0c'
APPROVED_AT='2026-10-01T13:10:29Z'
def load(p): return json.loads(p.read_text())
def main():
    v1=load(V1_PLAN); a1=load(V1_APPROVAL); p1=load(V1_PROGRESS); v2=load(V2_PLAN); p2=load(V2_PROGRESS); a2=load(V2_APPROVAL); resource=load(RESOURCE)
    validate_plan(v1,SCHEMA); validate_progress(v1,p1,SCHEMA); validate_plan(v2,SCHEMA); validate_progress(v2,p2,SCHEMA); validate_approval(v2,a2,SCHEMA,v2['authorization_window']['starts_at'])
    assert v1['plan_digest']==V1_PLAN_DIGEST and a1['approval_digest']==V1_APPROVAL_DIGEST and p1['progress_digest']==V1_PROGRESS_DIGEST
    assert a1['status']=='ACTIVE' and a1['expires_at']=='2026-10-01T06:00:00Z'
    assert p1['overall_state']=='NOT_STARTED'
    s1=p1['step_states'][0]
    assert s1['authorization_state']=='PENDING' and s1['execution_state']=='NOT_STARTED' and s1['verification_state']=='NOT_STARTED' and s1['authorization_consumed'] is False and s1['evidence']==[]
    assert v2['plan_id']==PLAN_ID and v2['plan_version']==2 and v2['plan_digest']==PLAN_DIGEST==plan_digest(v2)
    assert v2['definition_status']=='READY_FOR_APPROVAL' and v2['environment']=='DEVELOPMENT'
    assert v2['target']==v1['target']
    assert v2['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-01T13:30:00Z','expires_at':'2026-10-01T17:30:00Z'}
    assert v2['ordered_step_ids']==[STEP_ID]
    step=v2['steps'][0]; old=v1['steps'][0]
    assert step['step_id']==STEP_ID and step['resource']==old['resource'] and step['resource']['exact_digest']==RESOURCE_DIGEST
    assert canonical_digest(resource)==RESOURCE_DIGEST
    for field in ('operation','dependency_step_ids','required_evidence','expected_postcondition','correction_reference','execution_class','credential_policy','unresolved_bindings'):
        assert step[field]==old[field], field
    assert 'v1.approval.backdate' in step['prohibited_actions'] and 'v1.plan.execute' in step['prohibited_actions']
    assert 'render.deploy' in step['prohibited_actions'] and 'deployment.trigger' in step['prohibited_actions']
    lineage={x['binding_id']:x for x in step['binding_declarations']}
    expected={
      'binding.development.render.data-secret-binding-v2.v1-plan':V1_PLAN_DIGEST,
      'binding.development.render.data-secret-binding-v2.v1-approval':V1_APPROVAL_DIGEST,
      'binding.development.render.data-secret-binding-v2.v1-progress':V1_PROGRESS_DIGEST,
    }
    for bid,val in expected.items():
        d=lineage[bid]; assert d['phase']=='PREAPPROVAL_BOUND' and d['value_class']=='CONTENT_DIGEST' and d['preapproval_value']=={'value':val,'exact_digest':canonical_digest(val)}
    assert p2==initial_progress(v2,SCHEMA,PROGRESS_ID,v2['created_at']) and p2['progress_digest']==PROGRESS_DIGEST and p2['overall_state']=='NOT_STARTED'
    s2=p2['step_states'][0]
    assert s2['authorization_state']=='PENDING' and s2['execution_state']=='NOT_STARTED' and s2['verification_state']=='NOT_STARTED' and s2['authorization_consumed'] is False and s2['evidence']==[] and s2['binding_assertions']==[]
    assert a2=={'approval_id':APPROVAL_ID,'plan_id':PLAN_ID,'plan_version':2,'plan_digest':PLAN_DIGEST,'owner_identity':'github:AnonymousKoo','decision':'APPROVE','environment':'DEVELOPMENT','effective_at':'2026-10-01T13:30:00Z','expires_at':'2026-10-01T17:30:00Z','approved_at':APPROVED_AT,'status':'ACTIVE','authority_scope':'EXACT_PLAN_ONLY','approval_digest':APPROVAL_DIGEST}
    assert a2['approval_digest']==APPROVAL_DIGEST==approval_digest(a2)
    rendered=V2_PLAN.read_text()+V2_PROGRESS.read_text()
    for forbidden in ('postgresql://','password=','op://'): assert forbidden not in rendered
    print('DEVELOPMENT Render DATA secret-binding v2: PASS (APPROVED forward-only replacement; v1 expired/pristine; exact one-service/one-key scope; deploy prohibited; no provider execution)')
    return 0
if __name__=='__main__': raise SystemExit(main())
