#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
B=ROOT/'contracts/plans/v1'
EXEC=B/'development-render-deployment-v3.execution-progress.json'
EVIDENCE=B/'development-render-deployment-v3-success.evidence.json'
def load(p): return json.loads(p.read_text())
def raw(p): return 'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ex=load(EXEC); ev=load(EVIDENCE)
 assert ex['overall_state']=='COMPLETED'
 assert ex['progress_digest']=='sha256:1f628b63d94f127877ee6b96d31e1d66134a3c8ea7dd6eb31fc69da1c0b31e1a'
 assert len(ex['step_states'])==1
 st=ex['step_states'][0]
 assert st['step_id']=='development.render.deployment-v3.step.01.deploy-public-protected-canonical-main'
 assert st['authorization_state']=='CONSUMED' and st['authorization_consumed'] is True
 assert st['execution_state']=='SUCCEEDED' and st['verification_state']=='PASS' and st['safe_error_code'] is None
 assert len(st['evidence'])==1
 assert st['evidence'][0]['evidence_type']=='runtime.render.deployment.completed'
 assert st['evidence'][0]['evidence_digest']=='sha256:560b8147f448e12d34e9266816a889a04aba082abec2741a91647be7c6a9fd2a'
 assert raw(EVIDENCE)==st['evidence'][0]['evidence_digest']
 assert ev['outcome']=='SUCCEEDED_VERIFIED'
 assert ev['classification']=='MANUAL_RENDER_DEPLOYMENT_LIVE_EXACT_CANONICAL_MAIN'
 assert ev['deployment_observation']['deploy_id']=='dep-davkk6egekts73eefa40'
 assert ev['deployment_observation']['commit_id']=='43a9e1ccec2c1a2fd3eee530dd817981303caaba'
 assert ev['deployment_observation']['status']=='live'
 assert ev['deployment_observation']['trigger']=='api'
 assert ev['deployment_observation']['clear_cache'] is False
 assert ev['deployment_observation']['source_pull_succeeded'] is True
 assert ev['deployment_observation']['build_succeeded'] is True
 assert ev['deployment_observation']['runtime_start_succeeded'] is True
 assert ev['deployment_observation']['commit_matches_preflight'] is True
 assert ev['preflight']['repository_visibility']=='public'
 assert ev['preflight']['branch_protection']=={'required_status_checks':['main-pr-gate'],'required_pull_request_reviews':True,'enforce_admins':True}
 assert ev['post_deploy_provider_state']['latest_deploy_id']=='dep-davkk6egekts73eefa40'
 assert ev['post_deploy_provider_state']['latest_deploy_status']=='live'
 assert ev['post_deploy_provider_state']['branch']=='main'
 assert ev['post_deploy_provider_state']['auto_deploy']=='no'
 assert ev['post_deploy_provider_state']['auto_deploy_trigger']=='off'
 assert ev['post_deploy_provider_state']['second_deploy_detected'] is False
 sec=ev['security_state']
 for key in ('secret_material_observed','secret_material_recorded','environment_variable_enumeration_performed','environment_variable_mutation_attempted','environment_group_mutation_attempted','service_setting_mutation_attempted','github_visibility_mutation_attempted','github_branch_protection_mutation_attempted','supabase_operation_performed','n8n_touched','staging_touched','production_touched','retry_attempted','second_deploy_triggered'):
  assert sec[key] is False
 binds={x['binding_id']:x for x in st['binding_assertions']}
 assert binds['binding.development.render.deployment-v3.canonical-main-head']['sanitized_value']=='github.commit.sha-43a9e1ccec2c1a2fd3eee530dd817981303caaba'
 assert binds['binding.development.render.deployment-v3.github-repository-protection-preflight']['sanitized_value'] is None
 assert binds['binding.development.render.deployment-v3.render-service-preflight']['sanitized_value'] is None
 assert binds['binding.development.render.deployment-v3.result']['evidence_digest']==st['evidence'][0]['evidence_digest']
 rendered=EXEC.read_text()+EVIDENCE.read_text()
 for forbidden in ('postgresql://','password=','op://'):
  assert forbidden not in rendered
 print('DEVELOPMENT Render deployment v3 execution: PASS (COMPLETED/CONSUMED/SUCCEEDED/PASS; exact canonical main live; one deploy; no retry/config/secret mutation)')
 return 0
if __name__=='__main__': raise SystemExit(main())
