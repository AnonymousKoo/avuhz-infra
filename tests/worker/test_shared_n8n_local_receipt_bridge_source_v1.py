"""No-network structural and synthetic regression for a safe inactive n8n child."""
from __future__ import annotations
import json
from pathlib import Path
import shutil
import subprocess
import unittest

FILE=Path(__file__).resolve().parents[2]/'contracts/templates/n8n/avuhz-shared-local-receipt-bridge-child-inactive-v1.json'

class LocalN8nReceiptChildSourceTests(unittest.TestCase):
    def setUp(self):
        self.w=json.loads(FILE.read_text())

    def test_source_is_off_and_requires_future_encrypted_credential(self):
        w=self.w
        self.assertIs(w['active'],False)
        self.assertNotIn('id',w)
        self.assertNotIn('staticData',w)
        self.assertNotIn('pinData',w)
        self.assertEqual([n['type'] for n in w['nodes']],[
            'n8n-nodes-base.executeWorkflowTrigger',
            'n8n-nodes-base.code',
            'n8n-nodes-base.httpRequest','n8n-nodes-base.code'])
        self.assertTrue(all('credentials' not in n for n in w['nodes']))
        self.assertEqual(w['nodes'][0]['parameters']['inputSource'],'passthrough')
        for prop in ('saveDataSuccessExecution','saveDataErrorExecution'):
            self.assertEqual(w['settings'][prop],'none')
        self.assertIs(w['settings']['saveManualExecutions'],False)

    def test_backend_fail_closed_and_no_authority(self):
        p=self.w['nodes'][2]['parameters']
        self.assertEqual(p['url'],'http://127.0.0.1:1/v1/avuhz/local-n8n-receipts')
        self.assertEqual(p['method'],'POST')
        self.assertEqual(p['authentication'],'genericCredentialType')
        self.assertEqual(p['genericAuthType'],'httpHeaderAuth')
        self.assertEqual(p['headerParameters']['parameters'],[
            {'name':'X-Avuhz-Delivery-Key','value':'={{$json.delivery_idempotency_key}}'}])
        self.assertEqual(p['specifyBody'],'json')
        self.assertEqual(p['jsonBody'],'={{JSON.stringify($json)}}')
        self.assertEqual(p['options']['timeout'],1000)
        self.assertIs(p['options']['redirect']['redirect']['followRedirects'],False)
        self.assertEqual(p['options']['response']['response'],{
            'fullResponse':True,'responseFormat':'json','neverError':True})
        self.assertEqual(len(self.w['connections']),3)
        self.assertEqual(
            self.w['connections']['Receipt Backend UNCONFIGURED Fails Closed']['main'][0][0]['node'],
            'Confirm Exact 202 Durable Receipt Only')
        self.assertNotIn('Confirm Exact 202 Durable Receipt Only',self.w['connections'])

    def test_code_does_not_look_up_tenants_or_log_payloads(self):
        js=self.w['nodes'][1]['parameters']['jsCode']
        for bad in ('fetch(', 'httpRequest(', 'console.log', 'process.env', 'require(',
                    'service_role', 'contact_email', 'contact_phone', 'sendEmail('):
            self.assertNotIn(bad,js)
        self.assertIn('RECEIPT_ENVELOPE_DENIED',js)
        self.assertIn("v.event_type==='acquisition.intake.received'",js)

    def test_only_exact_202_durable_reply_produces_sanitized_marker(self):
        if not shutil.which('node'):self.skipTest('Node not available in CI')
        code=self.w['nodes'][3]['parameters']['jsCode']
        examples=[
            [{'statusCode':202,'body':{'accepted':True,'duplicate':False},
              'headers':{'authorization':'do-not-echo'},'statusMessage':'private'}],
            [{'statusCode':202,'body':{'accepted':True,'duplicate':True}}],
            [{'statusCode':200,'body':{'accepted':True,'duplicate':False}}],
            [{'statusCode':204,'body':{'accepted':True,'duplicate':False}}],
            [{'statusCode':302,'body':{'accepted':True,'duplicate':False}}],
            [{'statusCode':401,'body':{'accepted':True,'duplicate':False}}],
            [{'statusCode':409,'body':{'accepted':True,'duplicate':False}}],
            [{'statusCode':503,'body':{'accepted':True,'duplicate':False}}],
            [{'statusCode':202,'body':{'accepted':True,'duplicate':'false'}}],
            [{'statusCode':202,'body':{'accepted':True,'duplicate':False,'secret':'do-not-echo'}}],
            [{'statusCode':202,'body':{'accepted':'yes','duplicate':False}}],
            [{'statusCode':202,'body':None}],
            [],
            [{'statusCode':202,'body':{'accepted':True,'duplicate':False}}]*2,
        ]
        runner="""
const vm=require('node:vm');
const cfg=JSON.parse(process.argv[1]);
for(const values of cfg.examples){
 const ctx={$input:{all:()=>values.map(value=>({json:value}))}};
 try{
  const out=vm.runInNewContext('(function(){'+String.fromCharCode(10)+cfg.code+String.fromCharCode(10)+'})()',ctx,{timeout:1000});
  process.stdout.write(JSON.stringify({ok:true,out})+'\\n');
 }catch(e){process.stdout.write(JSON.stringify({ok:false,error:String(e.message)})+'\\n');}
}"""
        run=subprocess.run(['node','-e',runner,json.dumps({'code':code,'examples':examples})],
            capture_output=True,text=True,check=True,timeout=12)
        outputs=[json.loads(line) for line in run.stdout.splitlines()]
        self.assertEqual(len(outputs),len(examples))
        self.assertEqual(outputs[0]['out'][0]['json'],{
            'code':'NEW_DURABLE_RECEIPT','durable':True,'first_delivery':True})
        self.assertEqual(outputs[1]['out'][0]['json'],{
            'code':'DUPLICATE_RECEIPT_NO_EFFECT','durable':True,'first_delivery':False})
        for rejected in outputs[2:]:
            self.assertEqual(rejected,{'ok':False,'error':'DURABLE_RECEIPT_NOT_CONFIRMED'})
        self.assertNotIn('do-not-echo',run.stdout)

    def test_exact_synthetic_envelope_and_rejection(self):
        if not shutil.which('node'):self.skipTest('Node not available in CI')
        from tests.worker.test_local_n8n_receipt_store import envelope
        # Synthetic test helper uses the exact shared Avuhz fixture contract.
        ok=envelope()
        cases=[[ok],[{**ok,'contact_email':'synthetic@example.invalid'}],
               [{**ok,'event_type':'billing.paid'}],
               [{**ok,'tenant_id':'forged'}],
               [{**ok,'occurred_at':'2030-02-30T00:00:00Z'}],
               [{**ok,'occurred_at':'2030-01-01T00:00:00.1234567Z'}],
               [{**ok,'occurred_at':'2030-01-01T00:00:00.'+'9'*20000+'Z'}],
               [{**ok,'authoritative_subject_reference':{'reference_type':'ENGAGEMENT','reference_id':ok['authoritative_subject_reference']['reference_id']}}],
               [],[ok,ok]]
        runner="""
const vm=require('node:vm');
const b=JSON.parse(process.argv[1]);
for(const values of b.cases){
 const scope={$input:{all:()=>values.map(value=>({json:value}))}};
 try{
  const result=vm.runInNewContext('(function(){'+String.fromCharCode(10)+b.code+String.fromCharCode(10)+'})()',scope,{timeout:1000});
  process.stdout.write(JSON.stringify({ok:true,values:result})+'\\n');
 }catch(e){process.stdout.write(JSON.stringify({ok:false,error:String(e.message)})+'\\n');}
}"""
        run=subprocess.run(['node','-e',runner,json.dumps({
            'code':self.w['nodes'][1]['parameters']['jsCode'],'cases':cases
        })],capture_output=True,text=True,check=True,timeout=12)
        decoded=[json.loads(x) for x in run.stdout.splitlines()]
        self.assertEqual(len(decoded),len(cases))
        self.assertTrue(decoded[0]['ok'])
        self.assertEqual(decoded[0]['values'][0]['json'],ok)
        for item in decoded[1:]:
            self.assertEqual(item,{'ok':False,'error':'RECEIPT_ENVELOPE_DENIED'})
        self.assertNotIn('synthetic@example.invalid',run.stdout)

if __name__=='__main__':unittest.main()
