"""No external effects while testing the optional local n8n/PG QA launcher."""
from __future__ import annotations

import contextlib
import io
import os
import subprocess
import unittest
from unittest.mock import patch, call

from scripts import run_system001_local_contiguous_qa as qa


def outcome(cmd, stdout="", code=0):
    return subprocess.CompletedProcess(cmd, code, stdout, "")


def good_report():
    return {
        "all_workflows_inactive": True, "installed_node_count": 5,
        "installed_v2_count": 1, "qa_fixture_is_fictional": True,
        "existing_execution_rows": 0, "credential_bound": False,
        "receipt_endpoint_configured": False, "owner_lookup_connected": False,
    }


class BoundedLocalSystem001RunnerTests(unittest.TestCase):
    def test_dependency_gate_fails_before_starting_docker_or_n8n(self):
        with patch.object(qa.importlib.metadata, "version",
                          side_effect=qa.importlib.metadata.PackageNotFoundError):
            with self.assertRaisesRegex(qa.LocalQaDenied,"pinned_qa_python_unavailable"):
                qa._require_pinned_qa_python()

    def test_read_only_default_preflight_cannot_start_containers_or_n8n(self):
        with (
            patch.object(qa, "preflight", return_value=good_report()) as preflight,
            patch.object(qa, "_invoke", return_value=outcome([], "sha256:"+"a"*64+"\n")) as invoke,
            patch.dict(os.environ, {"CI":"","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"LOCAL"}),
        ):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                result = qa.main([])
        self.assertEqual(result, 0)
        self.assertIn("read-only preflight", output.getvalue())
        self.assertEqual(preflight.call_count, 1)
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(invoke.call_args.args[0][:3], ["docker","image","inspect"])
        self.assertNotIn("docker run", str(invoke.call_args_list))
        self.assertNotIn("n8n", str(invoke.call_args_list))

    def test_ci_and_nonlocal_environment_block_even_explicit_execute(self):
        for env in (
            {"CI":"true","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"LOCAL"},
            {"CI":"","GITHUB_ACTIONS":"true","AVUHZ_ENVIRONMENT":"TEST"},
            {"CI":"","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"PRODUCTION"},
            {"CI":"","GITHUB_ACTIONS":"","AVUHZ_ENVIRONMENT":"DEVELOPMENT"},
        ):
            with self.subTest(env=env), patch.dict(os.environ,env):
                with patch.object(qa,"_invoke") as invoke:
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(qa.main(["--execute-local-qa"]),2)
                    invoke.assert_not_called()

    def test_any_n8n_drifts_fail_before_docker_start(self):
        for field, bad in (
            ("all_workflows_inactive",False),("installed_v2_count",2),
            ("installed_node_count",4),("credential_bound",True),
            ("owner_lookup_connected",True),("existing_execution_rows",1),
            ("receipt_endpoint_configured",True),("qa_fixture_is_fictional",False),
        ):
            with self.subTest(field=field):
                report=good_report()
                report[field]=bad
                with patch.object(qa,"preflight",return_value=report):
                    with self.assertRaisesRegex(qa.LocalQaDenied,"local_n8n_preflight_denied"):
                        qa._check_n8n_readonly()

    def test_image_is_pinned_and_cannot_be_pulled(self):
        with patch.object(qa,"_invoke",return_value=outcome([],"sha256:"+"a"*64+"\n")) as invoke:
            qa._image_present()
        self.assertEqual(invoke.call_args.args[0][0:3],["docker","image","inspect"])
        self.assertEqual(invoke.call_args.args[0][3],qa.IMAGE)
        self.assertIn("@sha256:",qa.IMAGE)

    def test_any_invalid_pg_port_binding_fails_closed(self):
        for value in ("0.0.0.0:1234\n",":::5432\n","127.0.0.1:22\n",
                      "127.0.0.1:33000\n127.0.0.1:33001\n","0.0.0.0:60000\n",
                      "127.0.0.1:70000\n"):
            with self.subTest(value=value),patch.object(qa,"_invoke",return_value=outcome([],value)):
                with self.assertRaisesRegex(qa.LocalQaDenied,"disposable_pg17_port_untrusted"):
                    qa._mapped_loopback_port("avuhz-system001-qa-disposable-aabbcc")
        with patch.object(qa,"_invoke",return_value=outcome([],"127.0.0.1:50011\n")):
            self.assertEqual(qa._mapped_loopback_port("avuhz-system001-qa-disposable-aabbcc"),50011)

    def test_qa_output_fails_closed_without_relaying_raw_cli(self):
        text="\n".join(sorted(qa._REQUIRED_MARKERS))
        qa._classify_certifier_output(text,0)
        for raw,code in (
            (text.replace(next(iter(qa._REQUIRED_MARKERS)),""),0),
            (text+"\nBLOCKED local fatal",0),
            (text+"\nQA_RUN_BLOCKED unexpected_safe_boundary",0),
            (text,1),
        ):
            with self.subTest(code=code,raw_len=len(raw)):
                with self.assertRaisesRegex(qa.LocalQaDenied,"contiguous_n8n_pg_certification_failed"):
                    qa._classify_certifier_output(raw,code)

    def test_one_explicit_run_binds_dynamic_local_port_and_always_removes_pg(self):
        name="avuhz-system001-qa-disposable-abcdef012345"
        live_calls=[]
        expected="\n".join(sorted(qa._REQUIRED_MARKERS))
        def proc(cmd,*,timeout=15,env=None):
            live_calls.append((cmd,env))
            if cmd[:2]==["docker","run"]:
                self.assertIn("--pull=never",cmd)
                self.assertIn("127.0.0.1::5432",cmd)
                self.assertNotIn("0.0.0.0",str(cmd))
                return outcome(cmd,"b"*64+"\n")
            if cmd[:2]==["docker","exec"]:
                return outcome(cmd,"accepting connections\n")
            if cmd[:2]==["docker","port"]:
                return outcome(cmd,"127.0.0.1:51442\n")
            if cmd[:2]==["docker","rm"]:
                return outcome(cmd,name+"\n")
            if cmd[:2]==["docker","ps"]:
                return outcome(cmd,"")
            if cmd[:2]==[qa.sys.executable,str(qa.CHILD)]:
                self.assertIsNotNone(env)
                self.assertEqual(env["AVUHZ_LOCAL_POSTGRES_CONTAINER"],name)
                self.assertEqual(env["AVUHZ_WORK_ITEM_TEST_LOCAL_DSN"],
                                 "host=127.0.0.1 port=51442 dbname="+qa.DSN_DATABASE+" user=postgres")
                return outcome(cmd,expected)
            raise AssertionError("unexpected external tool")

        with (
            patch.object(qa,"_require_local_only"),
            patch.object(qa,"_required_source_files"),
            patch.object(qa,"_require_pinned_qa_python"),
            patch.object(qa,"_image_present"),
            patch.object(qa,"_check_n8n_readonly") as n8n,
            patch.object(qa,"_invoke",side_effect=proc),
            patch.object(qa.secrets,"token_hex",return_value="abcdef012345"),
            patch.object(qa.time,"sleep"),
        ):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                qa.run_local_qa()
        self.assertEqual(n8n.call_count,3)
        self.assertIn("PASS contiguous fictional LOCAL",output.getvalue())
        self.assertEqual(sum(x[0][:2]==["docker","rm"] for x in live_calls),1)
        self.assertEqual(sum(x[0][:2]==["docker","run"] for x in live_calls),1)

    def test_failure_during_child_certification_removes_pg_and_never_reports_success(self):
        name="avuhz-system001-qa-disposable-abcdef012345"
        seen=[]
        def proc(cmd,*,timeout=15,env=None):
            seen.append(cmd)
            if cmd[:2]==["docker","run"]: return outcome(cmd,"b"*64+"\n")
            if cmd[:2]==["docker","exec"]: return outcome(cmd,"ready\n")
            if cmd[:2]==["docker","port"]: return outcome(cmd,"127.0.0.1:51442\n")
            if cmd[:2]==["docker","rm"]: return outcome(cmd,name+"\n")
            if cmd[:2]==["docker","ps"]: return outcome(cmd,"")
            if cmd[:2]==[qa.sys.executable,str(qa.CHILD)]:
                return outcome(cmd,"QA_RUN_BLOCKED unexpected_safe_boundary\n",0)
            raise AssertionError("unexpected tool")
        with (
            patch.object(qa,"_require_local_only"),
            patch.object(qa,"_required_source_files"),
            patch.object(qa,"_require_pinned_qa_python"),
            patch.object(qa,"_image_present"),
            patch.object(qa,"_check_n8n_readonly"),
            patch.object(qa,"_invoke",side_effect=proc),
            patch.object(qa.secrets,"token_hex",return_value="abcdef012345"),
            patch.object(qa.time,"sleep"),
        ):
            with self.assertRaisesRegex(qa.LocalQaDenied,"contiguous_n8n_pg_certification_failed"):
                qa.run_local_qa()
        self.assertIn(["docker","rm","-f",name],seen)
        self.assertEqual(sum(x[:2]==["docker","run"] for x in seen),1)


if __name__=="__main__":
    unittest.main()
