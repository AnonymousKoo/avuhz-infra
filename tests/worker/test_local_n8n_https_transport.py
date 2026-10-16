"""TLS-only source adapter contract, entirely mocked/no actual network."""
from __future__ import annotations

import json
import secrets
import ssl
import unittest
from unittest.mock import patch

from avuhz_worker.local_n8n_https_transport import LocalN8nHttpsTransport
from avuhz_worker.n8n_event_sink import N8nOutboxSink
from avuhz_worker.outbox import DeliveryRejected, DeliveryUnavailable
from tests.worker.test_n8n_event_sink import fixture_event, TENANT, KEY, URL

HOST = "n8n.example.invalid"


class FakeResponse:
    def __init__(self, code=202):
        self.status = code

    def read(self):
        raise AssertionError("response body must never be read")


class MockTLSConnection:
    calls = []
    response = 202

    def __init__(self, host, *, port, timeout, context):
        self.calls.append(("init",host,port,timeout,context))
        self.closed = False

    def request(self, method, path, *, body, headers):
        self.calls.append(("request",method,path,body,headers.copy()))

    def getresponse(self):
        self.calls.append(("getresponse",))
        return FakeResponse(self.response)

    def close(self):
        self.closed = True
        self.calls.append(("close",))


class LocalHttpsTransportTests(unittest.TestCase):
    def setUp(self):
        MockTLSConnection.calls = []
        MockTLSConnection.response = 202
        self.token = secrets.token_urlsafe(32)
        self.tls = ssl.create_default_context()
        # This transport deliberately rejects default contexts with an
        # implicit "minimum supported" value. The wiring must pin TLS 1.2+
        # explicitly, not infer policy from OpenSSL option flags.
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_2
        self.post = LocalN8nHttpsTransport(
            environment="TEST", expected_host=HOST, tls_context=self.tls,
            timeout_seconds=4,
        )

    def sink(self):
        return N8nOutboxSink(
            environment="TEST", tenant_id=TENANT, endpoint=URL,
            expected_host=HOST, credential_provider=lambda:self.token,
            post=self.post,
        )

    def test_existing_shared_sink_only_sends_opaque_eight_field_event(self):
        src = fixture_event()
        with patch("avuhz_worker.local_n8n_https_transport.http.client.HTTPSConnection",
                   MockTLSConnection):
            result=self.sink().deliver(KEY,src,"2030-01-15T15:01:00Z")
        self.assertEqual(result["result"],"PUBLISHED")
        self.assertEqual(len(MockTLSConnection.calls),4)
        init,post,response,closed=MockTLSConnection.calls
        self.assertEqual(init[0:4],("init",HOST,443,4))
        self.assertIs(init[4],self.tls)
        self.assertEqual(post[0:3],("request","POST","/webhook/avuhz-events"))
        raw, headers=post[3:]
        self.assertEqual(headers["X-Avuhz-Webhook-Token"],self.token)
        self.assertEqual(headers["X-Avuhz-Delivery-Key"],KEY)
        self.assertEqual(headers["Content-Type"],"application/json")
        payload=json.loads(raw)
        self.assertEqual(set(payload), {
            "event_id","event_type","tenant_id","correlation_id",
            "occurred_at","authoritative_subject_reference",
            "authoritative_subject_version","delivery_idempotency_key",
        })
        for forbidden in ("sanitized_metadata","contact_email","full_name",
                          "engagement_id",self.token):
            self.assertNotIn(forbidden,raw.decode("utf-8"))
        self.assertEqual(closed,("close",))
        self.assertEqual(response,("getresponse",))

    def test_http_redirect_is_not_followed_and_uses_existing_worker_retry_boundary(self):
        MockTLSConnection.response=302
        with patch("avuhz_worker.local_n8n_https_transport.http.client.HTTPSConnection",
                   MockTLSConnection):
            with self.assertRaisesRegex(DeliveryUnavailable,"^n8n transport unavailable$"):
                self.sink().deliver(KEY,fixture_event(),"2030-01-15T15:01:00Z")
        self.assertEqual(sum(c[0]=="request" for c in MockTLSConnection.calls),1)
        self.assertEqual(MockTLSConnection.calls[-1],("close",))

    def test_server_failure_and_client_rejection_reuse_existing_sink_policy(self):
        for status,error in ((429,DeliveryUnavailable),(503,DeliveryUnavailable),
                             (401,DeliveryRejected),(403,DeliveryRejected)):
            with self.subTest(status=status):
                MockTLSConnection.response=status
                MockTLSConnection.calls=[]
                with patch("avuhz_worker.local_n8n_https_transport.http.client.HTTPSConnection",
                           MockTLSConnection):
                    with self.assertRaises(error):
                        self.sink().deliver(KEY,fixture_event(),"2030-01-15T15:01:00Z")
                self.assertEqual(MockTLSConnection.calls[-1],("close",))

    def test_untrusted_url_is_denied_before_connection(self):
        env = {k: v for k, v in {
            "event_id":"a4730000-0000-4000-8000-000000000041",
            "event_type":"acquisition.intake.received",
            "tenant_id":TENANT,"correlation_id":"a4730000-0000-4000-8000-000000000042",
            "occurred_at":"2030-01-15T15:00:00Z",
            "authoritative_subject_reference":{
                "reference_type":"ACQUISITION_INTAKE",
                "reference_id":"a4730000-0000-4000-8000-000000000021",
            },
            "authoritative_subject_version":1,"delivery_idempotency_key":KEY,
        }.items()}
        body=json.dumps(env).encode("utf-8")
        headers={"Content-Type":"application/json",
                 "X-Avuhz-Webhook-Token":self.token,
                 "X-Avuhz-Delivery-Key":KEY}
        for url in (
            "http://n8n.example.invalid/webhook/avuhz-events",
            "https://evil.example.invalid/webhook/avuhz-events",
            "https://n8n.example.invalid:444/webhook/avuhz-events",
            "https://n8n.example.invalid/webhook/avuhz-events?token=x",
            "https://user@n8n.example.invalid/webhook/avuhz-events",
            "https://n8n.example.invalid/private",
            "https://127.0.0.1:5678/webhook/avuhz-events",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError), patch(
                    "avuhz_worker.local_n8n_https_transport.http.client.HTTPSConnection",
                ) as conn:
                    self.post(url,headers,body)
                conn.assert_not_called()

    def test_missing_tls_identity_and_hosted_environment_denied(self):
        for env,host in (("DEVELOPMENT",HOST),("PRODUCTION",HOST),
                         ("TEST","localhost"),("TEST","127.0.0.1"),
                         ("TEST","n8n.local"),("TEST","n8n.example.invalid:444")):
            with self.subTest(env=env,host=host):
                with self.assertRaises(ValueError):
                    LocalN8nHttpsTransport(environment=env,
                        expected_host=host,tls_context=self.tls)
        for timeout in (0,31,True,5.5,"5"):
            with self.subTest(timeout=timeout),self.assertRaises(ValueError):
                LocalN8nHttpsTransport(environment="TEST",
                    expected_host=HOST,tls_context=self.tls,timeout_seconds=timeout)

    def test_unverified_tls_context_rejected_before_any_request(self):
        unverified=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified.check_hostname=False
        unverified.verify_mode=ssl.CERT_NONE
        for context in (None,object(),unverified):
            with self.subTest(context=type(context).__name__):
                with self.assertRaisesRegex(ValueError,"^verified TLS context required$"):
                    LocalN8nHttpsTransport(environment="TEST",expected_host=HOST,
                                           tls_context=context)

    def test_tls_downgrade_after_initial_construction_denied_at_send(self):
        data = {
            "event_id":"a4730000-0000-4000-8000-000000000041",
            "event_type":"acquisition.intake.received",
            "tenant_id":TENANT,"correlation_id":"a4730000-0000-4000-8000-000000000042",
            "occurred_at":"2030-01-15T15:00:00Z",
            "authoritative_subject_reference":{
                "reference_type":"ACQUISITION_INTAKE",
                "reference_id":"a4730000-0000-4000-8000-000000000021",
            },
            "authoritative_subject_version":1,"delivery_idempotency_key":KEY,
        }
        headers={"Content-Type":"application/json",
                 "X-Avuhz-Webhook-Token":self.token,
                 "X-Avuhz-Delivery-Key":KEY}
        self.tls.minimum_version=ssl.TLSVersion.MINIMUM_SUPPORTED
        with patch("avuhz_worker.local_n8n_https_transport.http.client.HTTPSConnection"
                   ) as conn,self.assertRaisesRegex(ValueError,"^verified TLS context required$"):
            self.post(URL,headers,json.dumps(data).encode("utf-8"))
        conn.assert_not_called()

    def test_unexpected_request_fields_and_pii_denied_before_connection(self):
        fields={
            "event_id":"a4730000-0000-4000-8000-000000000041",
            "event_type":"acquisition.intake.received",
            "tenant_id":TENANT,
            "correlation_id":"a4730000-0000-4000-8000-000000000042",
            "occurred_at":"2030-01-15T15:00:00Z",
            "authoritative_subject_reference":{
                "reference_type":"ACQUISITION_INTAKE",
                "reference_id":"a4730000-0000-4000-8000-000000000021",
            },
            "authoritative_subject_version":1,
            "delivery_idempotency_key":KEY,
        }
        normal={"Content-Type":"application/json",
                "X-Avuhz-Webhook-Token":self.token,
                "X-Avuhz-Delivery-Key":KEY}
        for raw,headers in (
            (json.dumps({**fields,"contact_email":"qa@example.invalid"}).encode(),normal),
            (json.dumps(fields).encode(),{**normal,"Authorization":"Bearer invalid"}),
            (json.dumps(fields).encode(),{**normal,"X-Avuhz-Delivery-Key":"otherkey"} ),
            (json.dumps(fields).encode(),{**normal,"X-Avuhz-Webhook-Token":"short"}),
            (json.dumps(fields).encode(),{**normal,"X-Avuhz-Webhook-Token":"line\nbad"}),
            (b"not json",normal),
            (b"a"*4097,normal),
        ):
            with self.subTest(raw_len=len(raw),headers=list(headers)):
                with patch("avuhz_worker.local_n8n_https_transport.http.client.HTTPSConnection"
                           ) as conn,self.assertRaises(ValueError):
                    self.post(URL,headers,raw)
                conn.assert_not_called()

    def test_real_shared_dispatcher_reuses_tls_only_transport_for_committed_intake(self):
        # End-to-end SRC/TEST path: existing fictional WSGI writes a committed
        # event, existing OutboxWorker claims it, new unattended loop invokes
        # the existing schema-validating sink, and verified TLS transport
        # sends the eight-field event over a mocked HTTPSConnection.
        # Does NOT connect to installed n8n or any network endpoint.
        from threading import Event
        from avuhz_worker import MemoryOutboxUnitOfWork, OutboxWorker, WorkerSettings
        from avuhz_worker.local_unattended_n8n_dispatch import (
            LocalN8nOutboxDispatcher, LocalN8nDispatchConfig,
        )
        from tests.integration.test_acquisition_http_to_n8n_synthetic_journey import (
            event_and_outbox_from_committed_intake,
        )
        from tests.worker.test_outbox_worker import context, MutableClock
        from test_development_acquisition_http import application, request
        from test_development_acquisition_ingress import TENANT_A

        app,store=application()
        status,receipt,headers=request(app)
        self.assertEqual(status,202)
        self.assertFalse(receipt["duplicate"])
        memory=event_and_outbox_from_committed_intake(store)
        sink=N8nOutboxSink(
            environment="TEST",tenant_id=TENANT_A,
            endpoint=URL,expected_host=HOST,
            credential_provider=lambda:self.token,post=self.post,
        )
        clock=MutableClock()
        worker=OutboxWorker(
            memory,MemoryOutboxUnitOfWork,sink,context(tenant=TENANT_A),
            WorkerSettings(tenant_id=TENANT_A,max_attempts=3),
            clock=clock,
        )
        runner=LocalN8nOutboxDispatcher(
            worker,LocalN8nDispatchConfig(TENANT_A,1,3),
        )
        stop=Event()
        def wait(seconds):
            clock.advance(seconds)
            return False
        with patch(
            "avuhz_worker.local_n8n_https_transport.http.client.HTTPSConnection",
            MockTLSConnection,
        ), patch.object(stop,"wait",side_effect=wait):
            result=runner.run_until_stopped(stop)
        self.assertEqual((result.claimed,result.published,result.retry_scheduled,
                          result.dead_lettered,result.cycles),(1,1,0,0,3))
        self.assertEqual(len([c for c in MockTLSConnection.calls if c[0]=="request"]),1)
        self.assertEqual(memory.outbox[0]["status"],"PUBLISHED")
        sent=next(c for c in MockTLSConnection.calls if c[0]=="request")
        payload=json.loads(sent[3])
        self.assertEqual(payload["authoritative_subject_reference"]["reference_id"],
                         receipt["intake_id"])
        self.assertEqual(len(payload),8)
        self.assertNotIn("sanitized_metadata",payload)
        self.assertNotIn(self.token,sent[3].decode("utf-8"))

    def test_network_failure_always_closes_connection_and_hides_exception(self):
        class BrokenConnection(MockTLSConnection):
            def request(self,*args,**kwargs):
                raise OSError("provider secret; forbidden diagnostic")
        with patch("avuhz_worker.local_n8n_https_transport.http.client.HTTPSConnection",
                   BrokenConnection):
            with self.assertRaisesRegex(DeliveryUnavailable,"^n8n transport unavailable$"):
                self.sink().deliver(KEY,fixture_event(),"2030-01-15T15:01:00Z")
        self.assertEqual(MockTLSConnection.calls[-1],("close",))


if __name__ == "__main__":
    unittest.main()
