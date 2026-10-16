"""Offline security tests for an opt-in LOCAL 1Password n8n credential source."""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import unittest
from unittest.mock import patch

from avuhz_worker.local_n8n_onepassword_credential import (
    LocalN8nOnePasswordCredential, LocalN8nSecretUnavailable,
)
from avuhz_worker.n8n_event_sink import N8nOutboxSink
from avuhz_worker.outbox import DeliveryUnavailable
from tests.worker.test_n8n_event_sink import (
    TENANT, URL, KEY, fixture_event,
)

# Reference is synthetic stable IDs only, never an account reference or item
# known to be in the real owner's local 1Password account.
REFERENCE = "op://testvaultid/testitemid/testfieldid"


class OnePasswordN8nCredentialTests(unittest.TestCase):
    def make_provider(self, **opts):
        return LocalN8nOnePasswordCredential(
            environment="LOCAL",
            approved_secret_reference=REFERENCE,
            **opts,
        )

    def test_exact_scoped_reference_and_environment_are_required(self):
        for value in (
            "", "op://", "op://vault/secret",
            "op://vault/item/field/extra",
            "op://vault/item/field?attribute=otp",
            "op://vault/item/field#fragment",
            "https://vault/item/field",
            "op://vault/item/../field",
            "op://vault/item/field\n",
            "op://vault/item/sensitive value",
            "op://vault;whoami/item/field",
            "op://vault/$(id)/field",
            "op://vault/item/field" + "a"*180,
        ):
            with self.subTest(reference=value), self.assertRaises(ValueError):
                LocalN8nOnePasswordCredential(
                    environment="LOCAL", approved_secret_reference=value,
                )
        for env in ("DEVELOPMENT", "STAGING", "PRODUCTION", ""):
            with self.subTest(env=env), self.assertRaises(ValueError):
                LocalN8nOnePasswordCredential(
                    environment=env, approved_secret_reference=REFERENCE,
                )
        for t in (0, -1, 11, True, 3.5):
            with self.subTest(timeout=t), self.assertRaises(ValueError):
                self.make_provider(timeout_seconds=t)

    def test_one_private_cli_read_per_delivery_never_shell_or_log(self):
        value=secrets.token_urlsafe(40)
        trace=[]
        def fake_run(args,**kwargs):
            trace.append((args,kwargs))
            return subprocess.CompletedProcess(args,0,value.encode(),b"")
        with (
            patch.dict(os.environ,{"CI":"","GITHUB_ACTIONS":"",
                                   "AVUHZ_ENVIRONMENT":"LOCAL"}),
            patch("avuhz_worker.local_n8n_onepassword_credential.subprocess.run",
                  side_effect=fake_run),
        ):
            provider=self.make_provider(timeout_seconds=3)
            self.assertEqual(provider(),value)
            self.assertEqual(provider(),value)
        self.assertEqual(len(trace),2)
        for args,kwargs in trace:
            self.assertEqual(args,["op","read","--no-newline",REFERENCE])
            self.assertFalse(kwargs.get("shell",False))
            self.assertEqual(kwargs["timeout"],3)
            self.assertEqual(kwargs["stdin"],subprocess.DEVNULL)
            self.assertEqual(kwargs["stdout"],subprocess.PIPE)
            self.assertEqual(kwargs["stderr"],subprocess.DEVNULL)
            self.assertNotIn(value,str(args))

    def test_no_sign_in_automatic_retry_fallback_or_secret_echo(self):
        for response in (
            subprocess.CompletedProcess([],1,b"hidden-token",b"private auth failed"),
            subprocess.CompletedProcess([],0,b"too-short",b""),
            subprocess.CompletedProcess([],0,b"x"*513,b""),
            subprocess.CompletedProcess([],0,b"x"*31,b""),
            subprocess.CompletedProcess([],0,b"x"*40+b"\n",b""),
            subprocess.CompletedProcess([],0,b"x"*40+b"\x00",b""),
            subprocess.CompletedProcess([],0,b"\xff"*40,b""),
        ):
            with (
                self.subTest(outcome=(response.returncode,len(response.stdout))),
                patch.dict(os.environ,{"CI":"","GITHUB_ACTIONS":"",
                                       "AVUHZ_ENVIRONMENT":"LOCAL"}),
                patch("avuhz_worker.local_n8n_onepassword_credential.subprocess.run",
                      return_value=response) as run,
            ):
                with self.assertRaisesRegex(
                    LocalN8nSecretUnavailable,
                    "^approved LOCAL secret issuer unavailable$",
                ) as caught:
                    self.make_provider()()
                self.assertEqual(run.call_count,1)
                self.assertNotIn("hidden-token",str(caught.exception))
                self.assertNotIn("private auth failed",str(caught.exception))

    def test_subprocess_timeout_and_os_errors_are_sanitized(self):
        for failure in (
            FileNotFoundError("op missing with sensitive data"),
            subprocess.TimeoutExpired("op",5,output=b"secret"),
            OSError("permission denied: confidential path"),
        ):
            with (
                self.subTest(error=type(failure).__name__),
                patch.dict(os.environ,{"CI":"","GITHUB_ACTIONS":"",
                                       "AVUHZ_ENVIRONMENT":"LOCAL"}),
                patch("avuhz_worker.local_n8n_onepassword_credential.subprocess.run",
                      side_effect=failure) as run,
            ):
                with self.assertRaisesRegex(
                    LocalN8nSecretUnavailable,
                    "^approved LOCAL secret issuer unavailable$",
                ) as caught:
                    self.make_provider()()
                self.assertNotIn("confidential",str(caught.exception))
                self.assertEqual(run.call_count,1)

    def test_ci_and_nonlocal_never_read_vault(self):
        for env in (
            {"CI":"true","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"LOCAL"},
            {"CI":"","GITHUB_ACTIONS":"true","AVUHZ_ENVIRONMENT":"LOCAL"},
            {"CI":"","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"PRODUCTION"},
        ):
            with (
                self.subTest(env=env),patch.dict(os.environ,env),
                patch("avuhz_worker.local_n8n_onepassword_credential.subprocess.run")
                as run,
            ):
                with self.assertRaises(LocalN8nSecretUnavailable):
                    self.make_provider()()
                run.assert_not_called()

    def test_existing_shared_sink_receives_token_in_memory_and_202_only(self):
        secret=secrets.token_urlsafe(36)
        def fake_run(args,**kwargs):
            return subprocess.CompletedProcess(args,0,secret.encode(),b"")
        deliveries=[]
        def fake_post(url,headers,body):
            deliveries.append((url,headers,body))
            return 202
        with (
            patch.dict(os.environ,{"CI":"","GITHUB_ACTIONS":"",
                                   "AVUHZ_ENVIRONMENT":"LOCAL"}),
            patch("avuhz_worker.local_n8n_onepassword_credential.subprocess.run",
                  side_effect=fake_run),
        ):
            sink=N8nOutboxSink(
                environment="LOCAL",tenant_id=TENANT,endpoint=URL,
                expected_host="n8n.example.invalid",
                credential_provider=self.make_provider(),post=fake_post,
            )
            result=sink.deliver(KEY,fixture_event(),"2030-01-15T15:01:00Z")
        self.assertEqual(result["result"],"PUBLISHED")
        self.assertEqual(len(deliveries),1)
        _,headers,body=deliveries[0]
        self.assertEqual(headers["X-Avuhz-Webhook-Token"],secret)
        self.assertNotIn(secret,body.decode())
        self.assertEqual(set(json.loads(body)),{
            "event_id","event_type","tenant_id","correlation_id",
            "occurred_at","authoritative_subject_reference",
            "authoritative_subject_version","delivery_idempotency_key",
        })

    def test_existing_shared_sink_retries_when_secret_source_not_signed_in(self):
        with (
            patch.dict(os.environ,{"CI":"","GITHUB_ACTIONS":"",
                                   "AVUHZ_ENVIRONMENT":"LOCAL"}),
            patch("avuhz_worker.local_n8n_onepassword_credential.subprocess.run",
                  return_value=subprocess.CompletedProcess([],1,b"",b"")) as run,
        ):
            sink=N8nOutboxSink(
                environment="LOCAL",tenant_id=TENANT,endpoint=URL,
                expected_host="n8n.example.invalid",
                credential_provider=self.make_provider(),
                post=lambda *args:self.fail("no request without credential"),
            )
            with self.assertRaisesRegex(
                DeliveryUnavailable,
                "^n8n credential temporarily unavailable$",
            ):
                sink.deliver(KEY,fixture_event(),"2030-01-15T15:01:00Z")
        run.assert_called_once()


if __name__=="__main__":
    unittest.main()
