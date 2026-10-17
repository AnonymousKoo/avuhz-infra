"""Synthetic safety tests for one in-place encrypted LOCAL inbound rotation."""
from __future__ import annotations

import contextlib
from dataclasses import replace
import io
import json
import os
import subprocess
import unittest
from unittest.mock import Mock, patch

from scripts import prepare_shared_n8n_v2_local_inbound_rotation as gate

LOCAL={"AVUHZ_ENVIRONMENT":"LOCAL","CI":"","GITHUB_ACTIONS":""}
REF="op://fictional-vault-id/fictional-item-id/password"
HEAD="b"*40
TOKEN="RandomReplacementToken"+("AbC123"*7)


class InboundRotationTests(unittest.TestCase):
    def setUp(self):
        self.credential=(
            gate.INBOUND_CREDENTIAL_ID,gate.inbound.CREDENTIAL_NAME,
            "httpHeaderAuth",160,"e","2026-10-16 12:00:00.001",
            "2026-10-16 12:00:00.001",0,
        )
        self.outbound=(
            gate.RECEIPT_CREDENTIAL_ID,gate.qa.receipt.CREDENTIAL_NAME,
            "httpHeaderAuth",160,"e","2026-10-17 01:00:00.001",
            "2026-10-17 01:00:00.001",0,
        )
        self.state=gate.Snapshot(
            endpoint="http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts",
            pid=1939646,project_id="qa-synthetic-only-personal-project",
            receiver_rows=((gate.RECEIVER_ID,"synthetic-bound-workflow"),),
            all_workflows=((gate.RECEIVER_ID,"synthetic-bound-workflow"),),
            credentials=(self.credential,self.outbound),
            credential_shares=(
                (gate.INBOUND_CREDENTIAL_ID,"qa-synthetic-only-personal-project","credential:owner"),
                (gate.RECEIPT_CREDENTIAL_ID,"qa-synthetic-only-personal-project","credential:owner"),
            ),
            workflow_shares=((gate.RECEIVER_ID,"qa-synthetic-only-personal-project","workflow:owner"),),
            execution_rows=(),
            total_webhooks=0,receipt_count=0,
        )
        new=list(self.credential);new[6]="2026-10-17 12:00:00.999"
        self.after=replace(self.state,credentials=(tuple(new),self.outbound))
        self.args=["--target",gate.TARGET,"--rotate-one",
                   "--approved-receiver-id",gate.RECEIVER_ID,
                   "--approved-credential-id",gate.INBOUND_CREDENTIAL_ID,
                   "--approved-receipt-credential-id",gate.RECEIPT_CREDENTIAL_ID,
                   "--approved-project-id",self.state.project_id,
                   "--approved-receiver-sha256",gate.RECEIVER_SHA256,
                   "--approved-receipt-endpoint",self.state.endpoint,
                   "--approved-source-commit",HEAD,
                   "--approved-secret-reference",REF,
                   "--approved-execution-13-14-absence","EXACT_13_AND_14_ABSENT"]

    def test_default_preflight_does_not_read_op_or_import(self):
        with (
            patch.dict(os.environ,LOCAL),
            patch.object(gate,"_read_only_snapshot",return_value=self.state) as pre,
            patch.object(gate,"LocalN8nOnePasswordCredential") as op,
            patch.object(gate,"_native_update_once") as importer,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(gate.run(["--target",gate.TARGET]),0)
        pre.assert_called_once()
        op.assert_not_called()
        importer.assert_not_called()
        self.assertIn("no 1Password field read",output.getvalue())

    def test_default_rejects_approval_flags_without_secret_access(self):
        with (
            patch.dict(os.environ,LOCAL),
            patch.object(gate,"_read_only_snapshot",return_value=self.state),
            patch.object(gate,"LocalN8nOnePasswordCredential") as op,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(gate.run(["--target",gate.TARGET,"--approved-secret-reference",REF]),2)
        op.assert_not_called()

    def test_wrong_environment_or_target_blocks_before_snapshot(self):
        for args,env in (
            (["--target","PRODUCTION"],{}),
            (["--target",gate.TARGET],{"AVUHZ_ENVIRONMENT":"TEST"}),
            (["--target",gate.TARGET],{"AVUHZ_ENVIRONMENT":"PRODUCTION"}),
            (["--target",gate.TARGET],{"CI":"1"}),
            (["--target",gate.TARGET],{"GITHUB_ACTIONS":"true"}),
        ):
            with (
                self.subTest(args=args,env=env),
                patch.dict(os.environ,{**LOCAL,**env}),
                patch.object(gate,"_read_only_snapshot") as pre,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(gate.run(args),2)
                pre.assert_not_called()

    def test_changed_scope_or_approval_denied_before_op_read(self):
        for field,value in (
            ("--approved-receiver-id","wrong-receiver"),
            ("--approved-credential-id",gate.RECEIPT_CREDENTIAL_ID),
            ("--approved-receipt-credential-id",gate.INBOUND_CREDENTIAL_ID),
            ("--approved-project-id","wrong-project"),
            ("--approved-receiver-sha256","sha256:"+"0"*64),
            ("--approved-receipt-endpoint","http://172.17.0.1:9999/v1/avuhz/local-n8n-receipts"),
            ("--approved-source-commit","a"*40),
            ("--approved-secret-reference","op://other/other/otp"),
            ("--approved-secret-reference","op://other/other/notes"),
            ("--approved-execution-13-14-absence","unapproved"),
        ):
            args=self.args.copy()
            args[args.index(field)+1]=value
            with (
                self.subTest(field=field),
                patch.dict(os.environ,LOCAL),
                patch.object(gate,"_read_only_snapshot",return_value=self.state),
                patch.object(gate,"_git_source_commit",return_value=HEAD),
                patch.object(gate,"LocalN8nOnePasswordCredential") as op,
                patch.object(gate,"_native_update_once") as importer,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(gate.run(args),2)
                op.assert_not_called()
                importer.assert_not_called()

    def test_exact_gate_b_one_vault_read_one_native_update(self):
        with (
            patch.dict(os.environ,LOCAL),
            patch.object(gate,"_read_only_snapshot",side_effect=[self.state,self.state,self.after]) as pre,
            patch.object(gate,"_git_source_commit",return_value=HEAD),
            patch.object(gate,"LocalN8nOnePasswordCredential",return_value=lambda:TOKEN) as op,
            patch.object(gate,"_native_update_once") as importer,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(gate.run(self.args),0)
        self.assertEqual(pre.call_count,3)
        op.assert_called_once_with(environment="LOCAL",approved_secret_reference=REF)
        importer.assert_called_once_with(self.state.project_id,TOKEN)
        self.assertNotIn(TOKEN,out.getvalue())
        self.assertIn("NOT PROVEN",out.getvalue())

    def test_runtime_drift_before_op_denied(self):
        drift=replace(self.state,pid=999999)
        with (
            patch.dict(os.environ,LOCAL),
            patch.object(gate,"_read_only_snapshot",side_effect=[self.state,drift]),
            patch.object(gate,"_git_source_commit",return_value=HEAD),
            patch.object(gate,"LocalN8nOnePasswordCredential") as op,
            patch.object(gate,"_native_update_once") as importer,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(gate.run(self.args),2)
        op.assert_not_called()
        importer.assert_not_called()

    def test_both_execution_absences_require_fresh_exact_approval(self):
        self.assertEqual(gate.EXPECTED_EXECUTIONS, frozenset())
        args = self.args.copy()
        args[args.index("--approved-execution-13-14-absence") + 1] = (
            "EXACT_13_ABSENT_14_PRESERVED"
        )
        with (
            patch.dict(os.environ, LOCAL),
            patch.object(gate, "_read_only_snapshot", return_value=self.state),
            patch.object(gate, "_git_source_commit", return_value=HEAD),
            patch.object(gate, "LocalN8nOnePasswordCredential") as secret,
            patch.object(gate, "_native_update_once") as update,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(gate.run(args), 2)
        secret.assert_not_called()
        update.assert_not_called()

    def test_old_13_only_approval_flag_cannot_reach_secret_read(self):
        args = self.args.copy()
        args[args.index("--approved-execution-13-14-absence")] = (
            "--approved-execution-13-absence"
        )
        with (
            patch.dict(os.environ, LOCAL),
            patch.object(gate, "_read_only_snapshot") as preflight,
            patch.object(gate, "LocalN8nOnePasswordCredential") as secret,
            patch.object(gate, "_native_update_once") as update,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as result:
                gate.run(args)
        self.assertEqual(result.exception.code, 2)
        preflight.assert_not_called()
        secret.assert_not_called()
        update.assert_not_called()

    def test_reappearing_historical_execution_rejected_after_import(self):
        for execution_id in (13, 14):
            execution = (execution_id, gate.RECEIVER_ID, "manual", "running", 0, None, None)
            with self.subTest(execution_id=execution_id):
                with self.assertRaises(gate.RotationDenied):
                    gate._verify_postcondition(
                        self.state, replace(self.after, execution_rows=(execution,))
                    )

    def test_owner_provider_failure_no_import(self):
        from avuhz_worker.local_n8n_onepassword_credential import LocalN8nSecretUnavailable
        def deny():
            raise LocalN8nSecretUnavailable("UNTRUSTED_PROVIDER_ERROR")
        with (
            patch.dict(os.environ,LOCAL),
            patch.object(gate,"_read_only_snapshot",return_value=self.state),
            patch.object(gate,"_git_source_commit",return_value=HEAD),
            patch.object(gate,"LocalN8nOnePasswordCredential",return_value=deny),
            patch.object(gate,"_native_update_once") as importer,
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(gate.run(self.args),2)
        importer.assert_not_called()
        self.assertNotIn("UNTRUSTED_PROVIDER_ERROR",out.getvalue())

    def test_native_import_single_same_id_and_private_stdin(self):
        result=Mock(returncode=0)
        with patch.object(gate.subprocess,"run",return_value=result) as runner:
            gate._native_update_once(self.state.project_id,TOKEN)
        runner.assert_called_once()
        a=runner.call_args
        self.assertEqual(a.args[0][0:6],
            ["docker","exec","-i","n8n","n8n","import:credentials"])
        self.assertEqual(a.args[0][-2:],
            ["--input=/dev/stdin","--projectId="+self.state.project_id])
        self.assertEqual(a.kwargs["stdout"],subprocess.DEVNULL)
        self.assertEqual(a.kwargs["stderr"],subprocess.DEVNULL)
        self.assertEqual(json.loads(a.kwargs["input"]),[{
            "id":gate.INBOUND_CREDENTIAL_ID,
            "name":gate.inbound.CREDENTIAL_NAME,
            "type":"httpHeaderAuth",
            "data":{"name":gate.inbound.HEADER_NAME,"value":TOKEN},
        }])
        self.assertNotIn(TOKEN,str(a.args[0]))

    def test_invalid_token_never_calls_importer(self):
        for token in ("short","A"*47,"A"*65,"A"*63+"!","A"*63+"\n"):
            with (
                self.subTest(length=len(token)),
                patch.object(gate.subprocess,"run") as runner,
            ):
                with self.assertRaises(gate.RotationDenied):
                    gate._native_update_once(self.state.project_id,token)
                runner.assert_not_called()

    def test_import_nonzero_or_transport_failure_no_retry(self):
        for result in (Mock(returncode=2),OSError("UNSAFE_PROVIDER_RAW_ERROR"),
                       subprocess.TimeoutExpired(cmd=["docker"],timeout=75)):
            with (
                self.subTest(result=repr(type(result))),
                patch.object(gate.subprocess,"run",
                             side_effect=result if isinstance(result,Exception) else None,
                             return_value=result if not isinstance(result,Exception) else None) as runner,
            ):
                with self.assertRaises(gate.RotationDenied) as e:
                    gate._native_update_once(self.state.project_id,TOKEN)
                self.assertNotIn("UNSAFE_PROVIDER_RAW_ERROR",str(e.exception))
                runner.assert_called_once()

    def test_false_cli_success_without_update_timestamp_is_blocked(self):
        with self.assertRaises(gate.RotationDenied):
            gate._verify_postcondition(self.state,self.state)

    def test_other_credential_or_receipt_change_is_denied(self):
        for after in (
            replace(self.after,credentials=(self.after.credentials[0],
                (*self.outbound[:3],140,*self.outbound[4:]))),
            replace(self.after,receipt_count=1),
            replace(self.after,pid=899),
            replace(self.after,execution_rows=((15,gate.RECEIVER_ID,"manual","running",0,None,None),)),
            replace(self.after,workflow_shares=()),
            replace(self.after,all_workflows=()),
            replace(self.after,project_id="wrong-personal"),
            replace(self.after,credentials=(self.after.credentials[0],)),
        ):
            with self.subTest(drift=str(after.project_id)):
                with self.assertRaises(gate.RotationDenied):
                    gate._verify_postcondition(self.state,after)

    def test_inbound_id_created_at_or_managed_drift_is_denied(self):
        for new in (
            (*self.after.credentials[0][:5],"changed-created-at",*self.after.credentials[0][6:]),
            (*self.after.credentials[0][:7],1),
            ("not-existing-id",*self.after.credentials[0][1:]),
            (gate.INBOUND_CREDENTIAL_ID,"wrong name",*self.after.credentials[0][2:]),
        ):
            with self.subTest(record=new[0:3]):
                with self.assertRaises(gate.RotationDenied):
                    gate._verify_postcondition(self.state,
                        replace(self.after,credentials=(new,self.outbound)))

    def test_postchange_uncertainty_never_retries(self):
        with (
            patch.dict(os.environ,LOCAL),
            patch.object(gate,"_read_only_snapshot",side_effect=[self.state,self.state,self.state]),
            patch.object(gate,"_git_source_commit",return_value=HEAD),
            patch.object(gate,"LocalN8nOnePasswordCredential",return_value=lambda:TOKEN) as op,
            patch.object(gate,"_native_update_once") as importer,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(gate.run(self.args),2)
        op.assert_called_once()
        importer.assert_called_once()
        self.assertNotIn(TOKEN,output.getvalue())
        self.assertIn("no retry",output.getvalue())


if __name__=="__main__":
    unittest.main()
