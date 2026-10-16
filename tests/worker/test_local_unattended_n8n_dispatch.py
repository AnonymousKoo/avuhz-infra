"""Unattended LOCAL polling of existing Avuhz outbox and non-PII n8n sink.

No real n8n service, credentials, DATA, AUTH, customers, or network calls.
The event/DB writer and receiver are existing fictional test components.
"""
from __future__ import annotations

import copy
from dataclasses import replace
import json
import sys
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT/"src", ROOT/"tests/service", ROOT/"tests/worker"):
    if str(folder) not in sys.path:
        sys.path.insert(0,str(folder))

from avuhz_runtime.in_memory import MemoryStore
from avuhz_worker.local_unattended_n8n_dispatch import (
    LocalN8nDispatchConfig, LocalN8nDispatchUnavailable,
    LocalN8nOutboxDispatcher,
)
from avuhz_worker import FakeLocalSink
from tests.integration.test_acquisition_http_to_n8n_synthetic_journey import (
    SyntheticAuthenticatedN8nReceiver,
    event_and_outbox_from_committed_intake,
    worker_for,
    CREDENTIAL,
)
from test_development_acquisition_http import application, request
from test_development_acquisition_ingress import TENANT_A, TENANT_B, sample

def committed_qa_acquisition():
    app, conn = application()
    status, response, _ = request(app)
    assert status == 202 and response["duplicate"] is False
    return event_and_outbox_from_committed_intake(conn)

class LocalN8nUnattendedDispatchTests(unittest.TestCase):
    def create(self, *, receiver=None, store=None, max_cycles=4, token=CREDENTIAL):
        receiver = receiver if receiver is not None else SyntheticAuthenticatedN8nReceiver()
        store = store if store is not None else committed_qa_acquisition()
        worker, clock = worker_for(store, receiver, supplied_token=token)
        config = LocalN8nDispatchConfig(TENANT_A, poll_interval_seconds=5,
                                        max_cycles=max_cycles)
        runner = LocalN8nOutboxDispatcher(worker,config)
        return runner, store, receiver, clock, worker

    @staticmethod
    def fake_time(stop,clock):
        # No delay or time/host dependency. Existing outbox retry state is
        # evaluated against the same advancing worker clock.
        waits=[]
        def advance(seconds):
            waits.append(seconds)
            clock.advance(seconds)
            return stop.is_set()
        return waits, advance

    def test_new_work_arrives_while_unattended_loop_is_already_waiting(self):
        empty = MemoryStore(events=[],outbox=[])
        runner, store, receiver, clock, worker = self.create(store=empty,max_cycles=4)
        self.assertEqual(store.events,[])
        self.assertEqual(store.outbox,[])
        incoming=committed_qa_acquisition()
        stop=Event()
        ticks=[]
        def wait(seconds):
            ticks.append(seconds)
            clock.advance(seconds)
            if len(ticks)==1:
                # Acquired and queued independently after the dispatcher
                # already started: no operator manually calls run_once.
                store.events.extend(copy.deepcopy(incoming.events))
                store.outbox.extend(copy.deepcopy(incoming.outbox))
            return False
        with patch.object(stop,"wait",side_effect=wait):
            summary=runner.run_until_stopped(stop)
        self.assertEqual(summary.cycles,4)
        self.assertEqual(summary.published,1)
        self.assertEqual(summary.termination,"CYCLE_LIMIT")
        self.assertEqual(store.outbox[0]["status"],"PUBLISHED")
        self.assertEqual(len(receiver.receipts),1)
        self.assertEqual(ticks,[5,5,5,5])
        payload=next(iter(receiver.receipts.values()))
        encoded=json.dumps(payload)
        for forbidden in (sample()["contact_name"],sample()["contact_email"],
                          sample()["business_name"],sample()["diagnostic_summary"],
                          CREDENTIAL,"sanitized_metadata"):
            self.assertNotIn(forbidden,encoded)
        self.assertEqual(payload["tenant_id"],TENANT_A)

    def test_lost_ack_is_retried_after_due_without_duplicate_receipt(self):
        receiver=SyntheticAuthenticatedN8nReceiver(lose_first_ack=True)
        runner,store,receiver,clock,worker=self.create(receiver=receiver,max_cycles=3)
        stop=Event()
        ticks,advance=self.fake_time(stop,clock)
        with patch.object(stop,"wait",side_effect=advance):
            result=runner.run_until_stopped(stop)
        self.assertEqual(result.cycles,3)
        self.assertEqual((result.claimed,result.published,result.retry_scheduled,
                          result.dead_lettered),(2,1,1,0))
        self.assertEqual(receiver.attempt_count,2)
        self.assertEqual(len(receiver.receipts),1)
        self.assertEqual(store.outbox[0]["status"],"PUBLISHED")
        self.assertEqual(ticks,[5,5,5])

    def test_bad_receiver_auth_dead_letters_and_never_retries(self):
        runner,store,receiver,clock,worker=self.create(token="invalid-local-test-only",
                                                       max_cycles=3)
        stop=Event()
        with patch.object(stop,"wait",side_effect=lambda seconds: clock.advance(seconds) or False):
            result=runner.run_until_stopped(stop)
        self.assertEqual((result.claimed,result.dead_lettered,result.published),(1,1,0))
        self.assertEqual(store.outbox[0]["status"],"FAILED_TERMINAL")
        self.assertEqual(receiver.receipts,{})
        self.assertEqual(result.termination,"CYCLE_LIMIT")

    def test_stop_event_prevents_any_delivery(self):
        runner,store,receiver,clock,worker=self.create()
        stop=Event();stop.set()
        with patch.object(worker,"run_once",side_effect=AssertionError("should not run")):
            result=runner.run_until_stopped(stop)
        self.assertEqual(result.cycles,0)
        self.assertEqual(result.termination,"STOP_REQUESTED")
        self.assertEqual(receiver.receipts,{})
        self.assertEqual(store.outbox[0]["status"],"PENDING")

    def test_stop_event_interrupts_wait_after_single_cycle(self):
        runner,store,receiver,clock,worker=self.create(max_cycles=300)
        stop=Event()
        def interrupt(seconds):
            stop.set()
            return True
        with patch.object(stop,"wait",side_effect=interrupt) as wait:
            result=runner.run_until_stopped(stop)
        self.assertEqual(result.termination,"STOP_REQUESTED")
        self.assertEqual(result.cycles,1)
        self.assertEqual(result.published,1)
        self.assertEqual(wait.call_count,1)

    def test_wrong_tenant_hosted_identity_or_unscoped_sink_denied(self):
        runner,store,receiver,clock,worker=self.create()
        for wrong in (TENANT_B,"not-a-uuid"):
            with self.subTest(tenant=wrong):
                with self.assertRaises(ValueError):
                    LocalN8nOutboxDispatcher(worker,LocalN8nDispatchConfig(wrong))
        with patch.object(worker,"context",
                          replace(worker.context,environment="PRODUCTION")):
            with self.assertRaises(ValueError):
                LocalN8nOutboxDispatcher(worker,LocalN8nDispatchConfig(TENANT_A))
        with patch.object(worker.sink,"_tenant_id",TENANT_B):
            with self.assertRaises(ValueError):
                LocalN8nOutboxDispatcher(worker,LocalN8nDispatchConfig(TENANT_A))
        with patch.object(worker,"sink",FakeLocalSink()):
            with self.assertRaises(ValueError):
                LocalN8nOutboxDispatcher(worker,LocalN8nDispatchConfig(TENANT_A))

    def test_integer_limits_and_explicit_stop_event_required(self):
        for seconds,cycles in ((0,1),(301,1),(True,1),(1,False),
                               (1,0),(1,17281),("5",1),(-1,1)):
            with self.subTest(seconds=seconds,cycles=cycles),self.assertRaises(ValueError):
                LocalN8nDispatchConfig(TENANT_A,poll_interval_seconds=seconds,max_cycles=cycles)
        runner,store,receiver,clock,worker=self.create()
        for stop in (None,object(),True, "stop"):
            with self.subTest(stop=stop),self.assertRaises(ValueError):
                runner.run_until_stopped(stop)

    def test_provider_exceptions_not_exposed_or_spun_on(self):
        runner,store,receiver,clock,worker=self.create()
        stop=Event()
        with patch.object(worker,"run_once",side_effect=RuntimeError(
            "PII or provider secret internal")),patch.object(stop,"wait") as wait:
            with self.assertRaisesRegex(LocalN8nDispatchUnavailable,
                                        "^local_outbox_cycle_unavailable$"):
                runner.run_until_stopped(stop)
            wait.assert_not_called()

    def test_invalid_worker_counter_shapes_not_accepted_as_completion(self):
        runner,store,receiver,clock,worker=self.create()
        invalid=(
            {},
            {"claimed":0,"published":1,"retry_scheduled":0,"dead_lettered":0},
            {"claimed":True,"published":0,"retry_scheduled":0,"dead_lettered":0},
            {"claimed":-1,"published":0,"retry_scheduled":0,"dead_lettered":0},
            {"claimed":1,"published":0,"retry_scheduled":0,"dead_lettered":0,
             "owner_verification":True},
            None,
        )
        for outcome in invalid:
            with self.subTest(outcome=outcome),patch.object(worker,"run_once",return_value=outcome):
                with self.assertRaisesRegex(LocalN8nDispatchUnavailable,
                                            "^local_outbox_cycle_unavailable$"):
                    runner.run_until_stopped(Event())

if __name__=="__main__":
    unittest.main()
