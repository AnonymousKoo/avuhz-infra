#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress, plan_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
RESOURCE=B/'development-render-runtime-config-final-verification-v1.resource.json'
PLAN=B/'development-render-runtime-config-final-verification-v1.plan.json'
PROGRESS=B/'development-render-runtime-config-final-verification-v1.progress.json'
V6_EXEC=B/'development-render-runtime-config-repair-v6.execution-progress.json'
def load(p): return json.loads(p.read_text())
def main():
 r=load(RESOURCE); p=load(PLAN); g=load(PROGRESS); v6=load(V6_EXEC)
 validate_plan(p,S); validate_progress(p,g,S)
 assert r['contract_digest']==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['environment']=='DEVELOPMENT' and r['provider']=='render'
 assert r['workspace_id']=='tea-dab95hv40ujc73a7ccag'
 assert r['service_id']=='srv-dab9n4qd0e5s73dq37mg' and r['service_name']=='avuhz-command-dev'
 expected={
  'AVUHZ_SERVICE_ENVIRONMENT':'DEVELOPMENT',
  'AVUHZ_DATA_PROJECT_REF':'gnuqaefotwgkwurjpyik',
  'AVUHZ_DATA_PROJECT_URL':'https://gnuqaefotwgkwurjpyik.supabase.co',
  'AVUHZ_AUTH_PROJECT_REF':'pwlhruwutoitnieactol',
  'AVUHZ_AUTH_ISSUER':'https://pwlhruwutoitnieactol.supabase.co/auth/v1',
  'AVUHZ_SERVICE_AUDIENCE':'audience.avuhz.command-service.development',
  'AVUHZ_TENANT_BRIDGE':'TrustedExecutionContext.tenant_id -> avuhz.tenant_id',
  'AVUHZ_RLS_POLICY_REFERENCE':'policy.avuhz.tenant-rls.development.v1',
  'AVUHZ_COMMAND_SERVICE_IDENTITY':'avuhz_command_service_dev'}
 assert r['expected_nonsecret_environment']==expected
 assert r['protected_secret_keys']==['AVUHZ_POSTGRES_DSN'] and r['provider_managed_keys']==['PORT']
 pol=r['verification_policy']
 assert pol['read_only'] is True and pol['mutation_allowed'] is False and pol['deployment_allowed'] is False
 assert pol['provider_api_environment_enumeration_allowed'] is False and pol['secret_value_visibility_allowed'] is False and pol['screenshot_commit_allowed'] is False
 assert pol['require_no_duplicate_keys'] is True and pol['require_branch_main'] is True and pol['require_auto_deploy_off'] is True and pol['require_no_new_deployment'] is True
 assert r['source_stop_progress_digest']==v6['progress_digest'] and v6['overall_state']=='STOPPED'
 assert p['plan_digest']==plan_digest(p) and p['plan_version']==1 and p['definition_status']=='READY_FOR_APPROVAL'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-02T03:00:00Z','expires_at':'2026-10-02T05:00:00Z'}
 assert len(p['steps'])==1
 st=p['steps'][0]
 assert st['operation']=='provider.render.dashboard.environment-config.verify-read-only-exact'
 assert st['execution_class']=='PROVIDER_READ'
 assert st['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert st['resource']['exact_digest']==r['contract_digest']
 assert st['required_evidence']==[{'evidence_type':'authorization-plan.execution-progress','source_step_id':None,'binding_state':'BOUND','exact_digest':v6['progress_digest']}]
 for x in ('provider.mutation','environment-variable.modify','deployment.trigger','secret.agent-visible','screenshot.commit','supabase.operation','n8n.operation','production.target'):
  assert x in p['prohibited_actions']
 assert g==initial_progress(p,S,g['progress_id'],p['created_at'])
 assert g['overall_state']=='NOT_STARTED' and g['step_states'][0]['authorization_state']=='PENDING'
 rendered=RESOURCE.read_text()+PLAN.read_text()+PROGRESS.read_text()
 for forbidden in ('postgresql://','password=','op://'): assert forbidden not in rendered
 print('DEVELOPMENT Render runtime config final verification v1: PASS (READY_FOR_APPROVAL; read-only; no env enumeration; no mutation/deploy/secret/screenshot persistence)')
 return 0
if __name__=='__main__': raise SystemExit(main())
