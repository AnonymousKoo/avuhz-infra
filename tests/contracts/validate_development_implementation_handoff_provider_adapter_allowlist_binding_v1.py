#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-allowlist-binding-v1'
PLAN_ID='cce4289e-d441-40f3-8d46-196355d093bc'
PLAN_DIGEST='sha256:7852e2c59abe083986d7e7add98e2f350460d76cf448aa9bb47b88603ad876fe'
PROGRESS_ID='9934545c-77ee-4218-aace-6a23bc3ce9c3'
PROGRESS_DIGEST='sha256:2b0204b13f6d6a4cd257417b31c83cf5d6b323a6d95ea0e7078df5132dd21fc7'
RESOURCE_DIGEST='sha256:30b1b24646e2934bafafdf0bb574fda2a269af53dd5fce668ecdbdf89c2ea553'
PREP_DIGEST='sha256:221ad2d264c64a4d89ade5171d76a60d342cdd49100ffc7adaeebbd40348b120'
CURRENT_SOURCE_DIGEST='sha256:17894ed10e4faa26616b8843df96f10a3e65de77fc6c5d85007970ceabd4a367'
TARGET_SOURCE_DIGEST='sha256:bbdf9c44c683118adedd42645bfb6b3c40617bbe8e402ce4bb65b20a7b1f6189'
TARGET_POLICY_DIGEST='sha256:7ed1565c16e150b4495509de36f98150f4f70b3898323789e306f2d5c831ce36'
SUBJECT='sha256:21ae3658908a20bb95e6440850180d699bba96da97ee1556e0574d1b12293e7a'
TENANT='1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0'
PRINCIPAL='provider-adapter.implementation-handoff-development'
PROJECT='pwlhruwutoitnieactol'
def load(n): return json.loads((B/n).read_text())
def rawsha(p): return 'sha256:'+hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert p['plan_id']==PLAN_ID and p['plan_digest']==PLAN_DIGEST==plan_digest(p) and p['plan_version']==1
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['target']['project_reference']==PROJECT and p['target']['responsibility']=='AUTH'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-04T02:15:00Z','expires_at':'2026-10-04T04:30:00Z'}
 assert not (B/(N+'.approval.json')).exists()
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['project_reference']==PROJECT and r['provider_subject_digest']==SUBJECT and r['canonical_tenant_id']==TENANT
 assert r['principal_reference']==PRINCIPAL and r['caller_type']=='PROVIDER_ADAPTER'
 assert r['capabilities']==['implementation_handoff:accept'] and r['authority_roles']==[] and r['target_entry_count']==2
 assert r['current_source_digest']==CURRENT_SOURCE_DIGEST and r['target_source_digest']==TARGET_SOURCE_DIGEST and r['target_policy_digest']==TARGET_POLICY_DIGEST
 source=ROOT/r['source_path']; current=source.read_text(); assert rawsha(source)==CURRENT_SOURCE_DIGEST
 assert current.count(r['authorized_source_before'])==1 and r['authorized_source_after'] not in current
 target=current.replace(r['authorized_source_before'],r['authorized_source_after']); compile(target,str(source),'exec')
 assert 'sha256:'+hashlib.sha256(target.encode()).hexdigest()==TARGET_SOURCE_DIGEST
 assert 'DEVELOPMENT_IDENTITY_ALLOWLIST = DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST' in current
 assert current.count('caller_type=_PROVIDER_ADAPTER_CALLER_TYPE')==0
 assert 'DevelopmentIdentityAllowlistEntry' in current and '_PROVIDER_ADAPTER_CAPABILITIES = frozenset({"implementation_handoff:accept"})' in current
 assert f'subject_digest="{SUBJECT}"' in r['authorized_source_after'] and f'principal_reference="{PRINCIPAL}"' in r['authorized_source_after']
 assert f'tenant_id="{TENANT}"' in r['authorized_source_after'] and 'caller_type=_PROVIDER_ADAPTER_CALLER_TYPE' in r['authorized_source_after']
 assert 'capabilities=_PROVIDER_ADAPTER_CAPABILITIES' in r['authorized_source_after']
 provider=r['provider_adapter_policy']; assert provider=={'issuer':'https://pwlhruwutoitnieactol.supabase.co/auth/v1','audience':'audience.avuhz.command-service.development','subject_digest':SUBJECT,'principal_reference':PRINCIPAL,'tenant_id':TENANT,'caller_type':'PROVIDER_ADAPTER','capabilities':['implementation_handoff:accept'],'authority_roles':[]}
 target_policy={'issuer':r['issuer'],'audience':r['service_audience'],'entries':[r['existing_policy'],provider]}; assert canonical_digest(target_policy)==TARGET_POLICY_DIGEST
 assert r['required_identity_creation_evidence_digest']=='sha256:27223a97cdb9943ddff839826f035d4db883a78c3531ab6575a649fec87a028d'
 assert r['required_passwordless_evidence_digest']=='sha256:26a90c35357ac14b23d1b7f17e18762e958248462d53aed168985dba249cbb10'
 assert r['required_tenant_verification_evidence_digest']=='sha256:42a33b97e8ab5c8fd9c7972d5d4a9cad57d06135ea9a05952ed6f669026c3936'
 assert r['required_existing_allowlist_evidence_digest']=='sha256:15d05b54d2f337ead4b4ed6f9881aef33c6063de29ed4501a805255e7999c2ba'
 assert all(r[k] is False for k in ('provider_contact_authorized','credential_use_authorized','provider_mutation_authorized','render_deployment_authorized','data_operation_authorized','n8n_operation_authorized','staging_authorized','production_authorized'))
 assert prep['evidence_digest']==PREP_DIGEST==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
 assert prep['provider_adapter_identity_observation']['provider_subject_digest']==SUBJECT and prep['provider_adapter_identity_observation']['tenant_binding_verified'] is True and prep['provider_adapter_identity_observation']['passwordless_state_verified'] is True
 assert prep['current_policy_observation']['source_digest']==CURRENT_SOURCE_DIGEST and prep['current_policy_observation']['entry_count']==1 and prep['current_policy_observation']['provider_adapter_entry_active'] is False
 assert prep['selected_binding']['target_source_digest']==TARGET_SOURCE_DIGEST and prep['selected_binding']['target_policy_digest']==TARGET_POLICY_DIGEST and prep['selected_binding']['execution_class']=='LOCAL_ONLY' and prep['selected_binding']['credential_class']=='NONE'
 assert all(v is False for v in prep['security_state'].values())
 step=p['steps'][0]; assert step['execution_class']=='LOCAL_ONLY' and step['credential_policy']=={'permitted':False,'allowed_classes':['NONE'],'values_stored':False}
 assert step['resource']['exact_digest']==RESOURCE_DIGEST and step['operation']=='local.capability-policy.activate-provider-adapter-exact-entry'
 assert len(step['required_evidence'])==4
 for action in ('provider.read','provider.mutation','credential.use','human-policy.modify','capability.add-extra','authority-role.add','render.operation','render.deployment','data.operation','n8n.operation','staging.target','production.target'):
  assert action in step['prohibited_actions'] and action in p['prohibited_actions']
 rendered=''.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
 for secret in ('postgresql://','postgres://','password=','sb_secret_','service_role'): assert secret not in rendered
 print('DEVELOPMENT provider-adapter allowlist binding v1: PASS (READY_FOR_APPROVAL; pristine; one exact LOCAL_ONLY server policy entry; no provider/deploy authority)')
if __name__=='__main__': main()
