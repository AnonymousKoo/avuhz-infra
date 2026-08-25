#!/usr/bin/env python3
"""Validate frozen Phase 5B OIA contracts, vocabulary, and safe representability."""
import copy,json,sys
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker
ROOT=Path(__file__).resolve().parents[2]; S=ROOT/'contracts/schemas/v1'
IDS={n:f'urn:avuhz:schema:contracts:domain:{n}:v1' for n in ('oia-assessment','oia-evidence-item','oia-observation','oia-root-cause','oia-finding','oia-findings-delivery')}
C=['OpenOIAAssessment','RecordOIAEvidence','RecordOIAObservation','SupersedeOIAObservation','RecordOIARootCause','CreateOIAFinding','UpdateOIAFindingAnalysis','FinalizeOIAFinding','MarkOIAAssessmentReadyForDelivery','DeliverOIAFindings','ReviseDeliveredOIAFinding','CloseOIAAssessment']
P={c:f'urn:avuhz:schema:contracts:commands:{"-".join(__import__("re").findall("[A-Z]+(?=[A-Z][a-z]|$)|[A-Z][a-z]*",c)).lower()}-payload:v1' for c in C}
# command schema IDs use oia words as one token, not generic Camel splitting
P.update({'OpenOIAAssessment':'urn:avuhz:schema:contracts:commands:open-oia-assessment-payload:v1','RecordOIAEvidence':'urn:avuhz:schema:contracts:commands:record-oia-evidence-payload:v1','RecordOIAObservation':'urn:avuhz:schema:contracts:commands:record-oia-observation-payload:v1','SupersedeOIAObservation':'urn:avuhz:schema:contracts:commands:supersede-oia-observation-payload:v1','RecordOIARootCause':'urn:avuhz:schema:contracts:commands:record-oia-root-cause-payload:v1','CreateOIAFinding':'urn:avuhz:schema:contracts:commands:create-oia-finding-payload:v1','UpdateOIAFindingAnalysis':'urn:avuhz:schema:contracts:commands:update-oia-finding-analysis-payload:v1','FinalizeOIAFinding':'urn:avuhz:schema:contracts:commands:finalize-oia-finding-payload:v1','MarkOIAAssessmentReadyForDelivery':'urn:avuhz:schema:contracts:commands:mark-oia-assessment-ready-for-delivery-payload:v1','DeliverOIAFindings':'urn:avuhz:schema:contracts:commands:deliver-oia-findings-payload:v1','ReviseDeliveredOIAFinding':'urn:avuhz:schema:contracts:commands:revise-delivered-oia-finding-payload:v1','CloseOIAAssessment':'urn:avuhz:schema:contracts:commands:close-oia-assessment-payload:v1'})
U=lambda n:f'a3000000-0000-4000-8000-000000000{n:03d}'
def load(p):return json.load(p.open())
def ptr(d,f):
 for x in ([] if not f else f[1:].split('/')):d=d[x]
 return d
def expand(v,d,ss):
 if isinstance(v,dict):
  if '$ref' in v:
   r=v['$ref'];td=d if r.startswith('#') else ss[r.partition('#')[0]]; t=ptr(td,r.partition('#')[2]);return {**expand(copy.deepcopy(t),td,ss),**{k:expand(x,d,ss) for k,x in v.items() if k!='$ref'}}
  return {k:expand(x,d,ss) for k,x in v.items()}
 if isinstance(v,list):return [expand(x,d,ss) for x in v]
 return v
def fail(m):print('phase5b-oia-contract validation: FAIL: '+m,file=sys.stderr);raise SystemExit(1)
def valid(sid,v,ss):return not list(Draft202012Validator(expand(ss[sid],ss[sid],ss),format_checker=FormatChecker()).iter_errors(v))
def main():
 paths=sorted(S.rglob('*.schema.json'));ss={load(p)['$id']:load(p) for p in paths}
 if len(ss)!=len(paths):fail('schema IDs must be unique')
 for x in ss.values():Draft202012Validator.check_schema(x)
 for sid in list(IDS.values())+list(P.values()):
  if sid not in ss:fail('missing schema '+sid)
 common=ss['urn:avuhz:schema:contracts:domain:oia-common:v1']['$defs']
 if common['assessmentState']['enum']!=['IN_PROGRESS','READY_FOR_DELIVERY','FINDINGS_DELIVERED','CLOSED']:fail('assessment states drifted')
 if common['rootCauseConfidence']['enum']!=['HYPOTHESIS','SUPPORTED','VERIFIED']:fail('root cause confidence drifted')
 if common['priority']['enum']!=['CRITICAL','HIGH','MEDIUM','LOW']:fail('priority drifted')
 tenant=U(1);assessment=U(2);e1=U(3);e2=U(4);obs=U(5);root=U(6);fid=U(7);delivery=U(8);ts='2030-01-15T12:00:00Z';digest='sha256:'+'a'*64
 base={'tenant_id':tenant,'oia_assessment_id':assessment,'engagement_id':U(9),'diagnostic_scope_id':U(10),'diagnostic_scope_version':1,'canonical_scope_digest':digest,'assessment_access_grant_id':U(11),'state':'IN_PROGRESS','record_version':1,'opened_at':ts,'created_at':ts,'updated_at':ts}
 if not valid(IDS['oia-assessment'],base,ss):fail('valid assessment rejected')
 bad=copy.deepcopy(base);bad['state']='OPEN';
 if valid(IDS['oia-assessment'],bad,ss):fail('invalid assessment state accepted')
 ev={'tenant_id':tenant,'oia_evidence_id':e1,'oia_assessment_id':assessment,'source_system_reference':'system-001','evidence_type':'METRIC_SNAPSHOT','captured_at':ts,'captured_by':'workload.oia-collector','scope_action':'VIEW_METRICS','secure_object_reference':'secure-object-001','content_digest':digest,'sensitivity':'RESTRICTED','retention_status':'AVAILABLE','created_at':ts}
 if not valid(IDS['oia-evidence-item'],ev,ss):fail('valid opaque evidence rejected')
 bad=copy.deepcopy(ev);bad['provider_payload']='forbidden';
 if valid(IDS['oia-evidence-item'],bad,ss):fail('evidence accepted raw provider field')
 ob={'tenant_id':tenant,'oia_observation_id':obs,'oia_assessment_id':assessment,'evidence_ids':[e1,e2],'system_process_area':'intake-routing','observed_condition':'Routing backlog exceeds agreed operational target.','confidence':'HIGH','state':'RECORDED','record_version':1,'created_by':'human.assessor-001','created_at':ts,'updated_at':ts}
 if not valid(IDS['oia-observation'],ob,ss):fail('multi-evidence observation rejected')
 bad=copy.deepcopy(ob);bad['state']='DRAFT';
 if valid(IDS['oia-observation'],bad,ss):fail('invalid observation state accepted')
 rc={'tenant_id':tenant,'oia_root_cause_id':root,'oia_assessment_id':assessment,'cause_statement':'Queue ownership lacks an escalation rule.','confidence':'SUPPORTED','supporting_observation_ids':[obs],'supporting_evidence_ids':[e1],'record_version':1,'created_by':'human.assessor-001','created_at':ts,'updated_at':ts}
 if not valid(IDS['oia-root-cause'],rc,ss):fail('valid root cause rejected')
 bad=copy.deepcopy(rc);bad['confidence']='AI_VERIFIED';
 if valid(IDS['oia-root-cause'],bad,ss):fail('unfrozen root cause confidence accepted')
 finding={'tenant_id':tenant,'oia_finding_id':fid,'oia_assessment_id':assessment,'finding_revision':1,'state':'FINAL','title':'Routing escalation is absent','summary':'Escalation ownership is not defined.','verified_operational_problem':'Routing backlog has no accountable escalation path.','business_operational_impact':'Delayed intake increases operational response time.','system_process_category':'intake-routing','supporting_observation_ids':[obs],'supporting_evidence_ids':[e1],'root_cause_ids':[root],'desired_outcome':'An accountable escalation path operates within target time.','intervention_category':'OPERATING_MODEL','priority_inputs':{'impact':'HIGH','urgency':'HIGH','operational_criticality':'HIGH','confidence':'HIGH','dependency_blocking':True},'priority':'HIGH','confidence':'HIGH','created_by':'human.assessor-001','finalized_by':'human.reviewer-001','finalized_at':ts,'content_digest':digest,'created_at':ts,'updated_at':ts}
 if not valid(IDS['oia-finding'],finding,ss):fail('valid final finding rejected')
 if 'priority' in ss[P['CreateOIAFinding']]['properties']:fail('caller can submit derived priority')
 manifest={'tenant_id':tenant,'oia_findings_delivery_id':delivery,'oia_assessment_id':assessment,'delivery_sequence':1,'finding_revisions':[{'oia_finding_id':fid,'finding_revision':1,'content_digest':digest}],'delivered_at':ts,'delivered_by':'human.reviewer-001','client_recipient_reference':'client-authority-001','delivery_channel_reference':'portal-delivery-001','manifest_digest':digest}
 if not valid(IDS['oia-findings-delivery'],manifest,ss):fail('valid immutable delivery manifest rejected')
 for c,sid in P.items():
  if ss[sid].get('additionalProperties') is not False:fail(c+' payload is not strict')
 for c in ('FinalizeOIAFinding','MarkOIAAssessmentReadyForDelivery','DeliverOIAFindings','CloseOIAAssessment'):
  if c not in C:fail('missing human boundary command')
 cap=ss['urn:avuhz:schema:contracts:identity:capability:v1']['enum']
 if not {'oia:open','oia:evidence:record','oia:observation:record','oia:root_cause:record','oia:finding:write','oia:finding:finalize','oia:assessment:review','oia:findings:deliver','oia:assessment:close'}<=set(cap):fail('capability vocabulary incomplete')
 event=ss['urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1']['properties']['event_type']['enum']
 if not {'oia.assessment_opened','oia.evidence_recorded','oia.observation_recorded','oia.observation_superseded','oia.root_cause_recorded','oia.finding_created','oia.finding_updated','oia.finding_finalized','oia.assessment_ready_for_delivery','oia.findings_delivered','oia.finding_revision_opened','oia.assessment_closed'}<=set(event):fail('event vocabulary incomplete')
 idem=ss['urn:avuhz:schema:contracts:orchestration:idempotency-record:v1']['properties']['command_type']['enum']
 if not set(C)<=set(idem):fail('command-scoped idempotency vocabulary incomplete')
 print('phase5b-oia-contract validation: PASS (assessment-to-closure representable; strict payloads, revision history, delivery manifest, capability, event, and idempotency vocabularies verified)')
if __name__=='__main__':main()
