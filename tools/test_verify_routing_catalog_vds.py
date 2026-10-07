"""Offline guards for the authenticated GET-only deployment verifier."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit


def module():
    fake = types.ModuleType("paramiko")
    fake.SSHClient = object
    fake.SSHException = RuntimeError
    with mock.patch.dict(sys.modules, {"paramiko": fake}):
        spec = importlib.util.spec_from_file_location("catalog_verify_test", Path(__file__).with_name("verify-routing-catalog-vds.py"))
        value = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(value)
        return value


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.module = module()
        self.namespace = {"DEPLOY_SOURCE":"", "EXPECTED_BUILD":"2.2.1-routing.1", "MINIMUM_TARGETS":2884}
        exec(self.module.REMOTE_VERIFY,self.namespace)

        class Failed(Exception):
            pass

        def require(ok,label):
            if not ok:
                raise Failed(label)

        self.failed = Failed
        self.helpers = self.namespace["_helpers"]
        self.helpers.update({"require":require,"CheckFailed":Failed,
                             "environment":lambda:{"QV_ADMIN_USER":"secret-user","QV_ADMIN_PASSWORD":"secret-password"},
                             "db_snapshot":mock.Mock(return_value={"settings":"stable"}),
                             "key_snapshot":mock.Mock(return_value=("private-fingerprint","public-key")),
                             "public_snapshot":mock.Mock(return_value="verified-abi-and-signed-policies")})
        self.requests = []

        def get(env,path,authorization=None):
            self.requests.append((path,authorization))
            headers = {"cache-control":"no-store","content-type":"application/json; charset=utf-8"}
            if authorization is None:
                return 401,{},b""
            if path == "/operator/health":
                return 200,headers,json.dumps({"operator_api":"ok","panel_build":"2.2.1-routing.1","user":"do-not-print"}).encode()
            if path == "/operator?tab=routing":
                return 200,headers,b"routing-catalog-dialog data-catalog-open csrf-do-not-print"
            query = parse_qs(urlsplit(path).query)
            if query.get("kind") == ["invalid"]:
                return 400,headers,b'{}'
            offset = int(query.get("offset",["0"])[0])
            if query.get("q") == ["youtube"]:
                items,matched = [{"target":"youtube.com","kind":"domain"}],1
            elif query.get("kind") == ["ip"]:
                items,matched = [{"target":"1.1.1.1","kind":"ip"}],1
            else:
                items,matched = [{"target":f"target{index:04d}.example.com","kind":"domain"} for index in range(offset,offset + 50)],2900
            return 200,headers,json.dumps({"total":2900,"matched":matched,"offset":offset,"items":items}).encode()

        self.namespace["_get"] = get

    def test_aggregate_only_success_uses_existing_basic_and_checks_stable_snapshots(self):
        result = self.namespace["verify"]()
        self.assertTrue(result["ok"])
        self.assertEqual(result["catalog_total"],2900)
        self.assertEqual(result["second_page_size"],50)
        self.assertEqual(result["youtube_matches"],1)
        self.assertEqual(result["ip_matches"],1)
        serialized = json.dumps(result)
        for secret in ("secret-user","secret-password","do-not-print","csrf", "private-fingerprint", "public-key", "1.1.1.1"):
            self.assertNotIn(secret,serialized)
        self.assertEqual(self.helpers["db_snapshot"].call_count,2)
        self.assertEqual(self.helpers["key_snapshot"].call_count,2)
        self.assertEqual(self.helpers["public_snapshot"].call_count,2)
        self.assertEqual(sum(auth is None for _,auth in self.requests),1)
        self.assertTrue(all(auth is None or auth.startswith("Basic ") for _,auth in self.requests))

    def test_duplicate_page_and_settings_change_fail_with_fixed_labels(self):
        original = self.namespace["_get"]
        def repeated(env,path,auth=None):
            return original(env,path.replace("offset=50","offset=0"),auth)
        self.namespace["_get"] = repeated
        with self.assertRaisesRegex(self.failed,"catalog_second_page"):
            self.namespace["verify"]()
        self.namespace["_get"] = original
        self.helpers["db_snapshot"].side_effect = [{"settings":"stable"},{"settings":"changed"}]
        with self.assertRaisesRegex(self.failed,"public_settings_changed"):
            self.namespace["verify"]()

    def test_unsafe_cache_and_small_catalog_fail(self):
        original = self.namespace["_get"]
        def cached(env,path,auth=None):
            status,headers,body = original(env,path,auth)
            if path.startswith("/operator/routing/catalog"):
                headers["cache-control"] = "public"
            return status,headers,body
        self.namespace["_get"] = cached
        with self.assertRaisesRegex(self.failed,"catalog_cache_control"):
            self.namespace["verify"]()
        self.namespace["_get"] = original
        self.namespace["MINIMUM_TARGETS"] = 3000
        with self.assertRaisesRegex(self.failed,"catalog_seed_count"):
            self.namespace["verify"]()

    def test_remote_main_sanitizes_arbitrary_exception_text_and_limits_duration(self):
        def fail():
            raise ValueError("secret-password response-body api-key")
        self.namespace["verify"] = fail
        signal = types.SimpleNamespace(SIGALRM=1,signal=mock.Mock(),alarm=mock.Mock())
        self.namespace["signal"] = signal
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
            self.namespace["_catalog_main"]()
        self.assertEqual(json.loads(output.getvalue()),{"ok":False,"error":"ValueError"})
        self.assertEqual(signal.alarm.call_args_list,[mock.call(45),mock.call(0)])

    def test_script_reuses_helpers_without_running_deployment_or_importing_application(self):
        with mock.patch.object(self.module,"deploy_source",return_value="def main(): raise RuntimeError('must not run')"):
            script = self.module.script("2.2.1-routing.1",2884)
        compile(script,"catalog-verifier","exec")
        self.assertIn("catalog_verification_helpers",script)
        self.assertIn("connection.request('GET'",script)
        self.assertNotIn("connection.request('POST'",script)
        self.assertNotIn("import app",script)
        self.assertNotIn("sign_session",self.module.REMOTE_VERIFY)
        self.assertNotIn("Cookie",self.module.REMOTE_VERIFY)
        local = Path(self.module.__file__).read_text(encoding="utf-8")
        self.assertIn("paramiko.RejectPolicy()",local)
        self.assertIn('os.environ.get("QVPN_VDS_PASSWORD")',local)
        self.assertNotIn("open_sftp",local)


if __name__ == "__main__":
    unittest.main()
