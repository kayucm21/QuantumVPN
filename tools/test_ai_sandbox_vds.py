"""Offline sandbox preflight/transaction tests. No SSH or VDS is accessed."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

SPEC = importlib.util.spec_from_file_location("ai_sandbox_installer", Path(__file__).with_name("harden-ai-sandbox-vds.py"))
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)
REMOTE = {"RUN_REMOTE": False, "APPLY": False, "EXPECTED_UNIT_SHA256": ""}
with patch.dict(sys.modules, {"fcntl": Mock(LOCK_EX=2, LOCK_NB=4)}):
    exec(compile(installer.REMOTE, "<offline-ai-sandbox>", "exec"), REMOTE)


class SandboxTests(unittest.TestCase):
    def test_remote_is_valid_and_additive_fixed_scope(self):
        ast.parse(installer.REMOTE)
        self.assertEqual(REMOTE["SERVICE"], "quantumvpn-llama.service")
        self.assertEqual(REMOTE["DROPIN"].as_posix(), "/etc/systemd/system/quantumvpn-llama.service.d/50-quantumvpn-sandbox.conf")
        body = REMOTE["BODY"].decode()
        for rule in ("CapabilityBoundingSet=", "AmbientCapabilities=", "ProtectKernelLogs=yes",
                     "ProtectControlGroups=yes", "RestrictSUIDSGID=yes", "RestrictRealtime=yes",
                     "LockPersonality=yes", "SystemCallArchitectures=native"):
            self.assertIn(rule, body)
        for rule in ("ExecStart", "CPUQuota", "MemoryMax", "IPAddress", "Environment", "ReadWritePaths"):
            self.assertNotIn(rule, body)
        self.assertNotIn("os.replace", installer.REMOTE)
        self.assertIn("os.link(temp,DROPIN.name", installer.REMOTE)

    def test_sleeping_readiness_does_not_request_slots_or_wake(self):
        get = Mock(side_effect=[{"status": "ok"}, {"total_slots": 1, "is_sleeping": True}])
        with patch.dict(REMOTE, {"local_json": get}):
            value = REMOTE["readiness"](b"--no-slots")
        self.assertTrue(value["idle"])
        self.assertEqual([call.args[0] for call in get.call_args_list], ["/health", "/props"])

    def test_no_slots_awake_runtime_fails_idle_closed(self):
        get = Mock(side_effect=[{"status": "ok"}, {"total_slots": 1, "is_sleeping": False}])
        with patch.dict(REMOTE, {"local_json": get}):
            value = REMOTE["readiness"](b"--no-slots")
        self.assertFalse(value["idle"])
        self.assertEqual(value["idle_source"], "slots_disabled")
        self.assertEqual(get.call_count, 2)

    def test_awake_slots_require_explicit_unbusy_boolean(self):
        for slot, expected in (({"is_processing": False}, True), ({"is_processing": True}, False)):
            with patch.dict(REMOTE, {"local_json": Mock(side_effect=[{"status": "ok"}, {"total_slots": 1, "is_sleeping": False}, [slot]])}):
                self.assertEqual(REMOTE["readiness"](b"")["idle"], expected)
        for slots in ([], [{"is_processing": "false"}], ["wrong"]):
            with patch.dict(REMOTE, {"local_json": Mock(side_effect=[{"status": "ok"}, {"total_slots": 1, "is_sleeping": False}, slots])}):
                with self.assertRaisesRegex(REMOTE["Refused"], "slot_state_unknown"):
                    REMOTE["readiness"](b"")

    def test_post_restart_readiness_uses_only_no_wake_endpoints(self):
        get = Mock(side_effect=[{"status": "ok"}, {"total_slots": 1, "is_sleeping": False}])
        with patch.dict(REMOTE, {"local_json": get}):
            self.assertTrue(REMOTE["readiness"](b"", check_idle=False)["ready"])
        self.assertEqual(get.call_count, 2)

    def test_restart_and_rollback_readiness_wait_is_bounded_without_wake(self):
        ready = Mock(side_effect=[OSError("not ready"), {"ready": True}])
        with patch.dict(REMOTE, {"readiness": ready}), \
             patch.object(REMOTE["time"], "monotonic", side_effect=[0, 1]), \
             patch.object(REMOTE["time"], "sleep") as sleep:
            self.assertTrue(REMOTE["wait_readiness"](b"--no-slots")["ready"])
            sleep.assert_called_once_with(1)
            self.assertEqual([call.kwargs for call in ready.call_args_list], [{"check_idle": False}] * 2)
        with patch.dict(REMOTE, {"readiness": Mock(side_effect=OSError("secret raw error"))}), \
             patch.object(REMOTE["time"], "monotonic", side_effect=[0, 61]), \
             patch.object(REMOTE["time"], "sleep") as sleep:
            with self.assertRaisesRegex(REMOTE["Refused"], "^runtime_readiness_timeout$"):
                REMOTE["wait_readiness"](b"--no-slots")
            sleep.assert_not_called()

    def test_readiness_rejects_unknown_status_and_bool_slot_count(self):
        for props in ({}, {"total_slots": True, "is_sleeping": True}, {"total_slots": 9, "is_sleeping": False},
                      {"total_slots": 1, "is_sleeping": "true"}):
            with patch.dict(REMOTE, {"local_json": Mock(side_effect=[{"status": "ok"}, props])}):
                with self.assertRaises(REMOTE["Refused"]):
                    REMOTE["readiness"](b"--no-slots")

    def test_only_exact_owned_commands_are_allowed_and_raw_errors_hidden(self):
        run = Mock(return_value=SimpleNamespace(returncode=1, stdout="secret-value", stderr="password"))
        with patch.object(REMOTE["subprocess"], "run", run):
            for command in (["systemctl", "restart", "rospanel"], ["sh", "-c", "echo secret"],
                            ["systemctl", "stop", REMOTE["SERVICE"]], ["systemd-analyze", "verify", "/tmp/foreign"]):
                with self.assertRaisesRegex(REMOTE["Refused"], "command_not_allowlisted"):
                    REMOTE["command"](command)
            run.assert_not_called()
            with self.assertRaisesRegex(REMOTE["Refused"], "^system_command_failed$"):
                REMOTE["command"](["systemctl", "restart", REMOTE["SERVICE"]])
        self.assertEqual(run.call_args.kwargs["stderr"], REMOTE["subprocess"].DEVNULL)

    def test_runtime_http_rejects_nonlocal_or_inference_path(self):
        for path in ("/v1/chat/completions", "http://external/health", "/props?url=secret", "/sleep"):
            with self.assertRaisesRegex(REMOTE["Refused"], "runtime_endpoint_not_allowlisted"):
                REMOTE["local_json"](path)
        self.assertIsNone(REMOTE["NoRedirect"]().redirect_request(None, None, None, None, None, None))

    def test_kernel_properties_do_not_replace_process_enforcement_evidence(self):
        values = {**REMOTE["HARDENED"], "SystemCallArchitectures": "native", "MainPID": "123"}
        good = "NoNewPrivs:\t1\nSeccomp:\t2\n" + "".join(key + ":\t0000000000000000\n" for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        for raw in (good, good.replace("Seccomp:\t2", "Seccomp:\t0"), good.replace("CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001")):
            with patch.object(Path, "read_text", return_value=raw):
                if raw == good:
                    REMOTE["verify_hardening"](values)
                else:
                    with self.assertRaises(REMOTE["Refused"]):
                        REMOTE["verify_hardening"](values)

    @contextlib.contextmanager
    def transaction(self, *, apply=True, busy_at=None, failure=None, previous=None, expected=None, changed_identity=False):
        raw = b"--no-slots reviewed unit"
        base = {key: "preserved" for key in REMOTE["BASE_PROPERTIES"]}
        body = REMOTE["BODY"]
        written = {"value": previous}
        state = {"ready": True, "sleeping": True, "idle": True, "idle_source": "sleeping_props"}
        readiness_calls = {"count": 0}
        def ready(*args, **kwargs):
            readiness_calls["count"] += 1
            return {**state, "idle": readiness_calls["count"] != busy_at}
        def atomic(value):
            if failure == "write":
                raise OSError("private raw write error")
            written["value"] = value
            return (1, 20)
        def command(argv, timeout=15):
            if argv == ["systemctl", "--version"]:
                return "systemd 252 (fixture)\n"
            if failure == "verify" and argv[0] == "systemd-analyze":
                raise REMOTE["Refused"]("system_command_failed")
            return ""
        commands = Mock(side_effect=command)
        rollback = Mock()
        overrides = {"APPLY": apply, "EXPECTED_UNIT_SHA256": hashlib.sha256(raw).hexdigest() if expected is None else expected,
                     "verify_install": Mock(return_value=(raw, previous, base)), "identity": Mock(side_effect=[{"stable": 1}, {"stable": 2}] if changed_identity else None, return_value={"stable": 1}),
                     "readiness": Mock(side_effect=ready), "file_bytes": Mock(side_effect=lambda path, *args: written["value"]),
                     "command": commands, "recovery": Mock(return_value=Path("/private/recovery")),
                     "safe_directory": Mock(return_value=(1, 2)), "atomic_dropin": Mock(side_effect=atomic),
                     "rollback": rollback, "properties": Mock(return_value=base), "verify_base": Mock(),
                     "verify_hardening": Mock(side_effect=REMOTE["Refused"]("hardening_property_mismatch") if failure == "postflight" else None)}
        lock = Mock()
        lock.__enter__ = Mock(return_value=lock)
        lock.__exit__ = Mock(return_value=False)
        lock.fileno.return_value = 10
        file_stat = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1)
        output = io.StringIO()
        with patch.dict(REMOTE, overrides), patch.object(REMOTE["os"], "geteuid", return_value=0, create=True), \
             patch.object(REMOTE["os"], "O_NOFOLLOW", 0, create=True), patch.object(REMOTE["os"], "open", return_value=10), \
             patch.object(REMOTE["os"], "fdopen", return_value=lock), patch.object(REMOTE["os"], "fstat", return_value=file_stat), \
             patch.object(Path, "exists", return_value=False), patch.object(Path, "mkdir"), \
             patch.object(Path, "iterdir", return_value=iter(())), patch.object(Path, "rmdir") as rmdir, contextlib.redirect_stdout(output):
            yield overrides, commands, rollback, output, rmdir

    def test_default_read_only_never_writes_or_restarts(self):
        with self.transaction(apply=False) as (ops, commands, rollback, output, _):
            REMOTE["main_remote"]()
            self.assertEqual(json.loads(output.getvalue())["status"], "ReadOnly")
            commands.assert_not_called()
            ops["recovery"].assert_not_called()
            ops["atomic_dropin"].assert_not_called()
            rollback.assert_not_called()

    def test_expected_sha_and_busy_preflight_block_before_writes(self):
        for kwargs, reason in (({"expected": "a" * 64}, "expected_unit"), ({"busy_at": 1}, "inference_busy")):
            with self.transaction(**kwargs) as (ops, _, rollback, _, _):
                with self.assertRaisesRegex(REMOTE["Refused"], reason):
                    REMOTE["main_remote"]()
                ops["recovery"].assert_not_called()
                ops["atomic_dropin"].assert_not_called()
                rollback.assert_not_called()

    def test_preflight_concurrent_identity_change_prevents_writes(self):
        with self.transaction(changed_identity=True) as (ops, _, _, _, _):
            with self.assertRaisesRegex(REMOTE["Refused"], "preflight_changed"):
                REMOTE["main_remote"]()
            ops["recovery"].assert_not_called()
            ops["atomic_dropin"].assert_not_called()

    def test_existing_managed_dropin_verifies_without_restart(self):
        with self.transaction(previous=REMOTE["BODY"]) as (ops, commands, _, output, _):
            REMOTE["main_remote"]()
            self.assertEqual(json.loads(output.getvalue())["status"], "AlreadyHardened")
            ops["verify_hardening"].assert_called_once()
            commands.assert_not_called()

    def test_apply_restarts_only_llama_and_reports_no_bpf_proof(self):
        with self.transaction() as (ops, commands, rollback, output, _):
            REMOTE["main_remote"]()
            restarts = [call.args[0] for call in commands.call_args_list if call.args[0][:2] == ["systemctl", "restart"]]
            self.assertEqual(restarts, [["systemctl", "restart", "quantumvpn-llama.service"]])
            report = json.loads(output.getvalue())
            self.assertEqual(report["status"], "Hardened")
            self.assertEqual(report["network_bpf_enforcement"], "not_verified")
            self.assertFalse(report["network_policy_changed"])
            self.assertTrue(report["idle_check_not_atomic_with_callers"])
            ops["readiness"].assert_called_with(b"--no-slots reviewed unit", check_idle=False)
            rollback.assert_not_called()

    def test_busy_after_install_rolls_back_without_interrupting_inference(self):
        for busy_at in (3, 4):
            with self.transaction(busy_at=busy_at) as (_, commands, rollback, output, _):
                with self.assertRaisesRegex(REMOTE["Refused"], "inference_started"):
                    REMOTE["main_remote"]()
                rollback.assert_called_once_with(None, True, False, (1, 20))
                self.assertFalse(any(call.args[0][:2] == ["systemctl", "restart"] for call in commands.call_args_list))
                self.assertIn("RolledBack", output.getvalue())

    def test_postflight_failure_requires_rollback_of_only_owned_dropin(self):
        with self.transaction(failure="postflight") as (_, _, rollback, _, _):
            with self.assertRaisesRegex(REMOTE["Refused"], "hardening_property_mismatch"):
                REMOTE["main_remote"]()
            rollback.assert_called_once_with(None, True, True, (1, 20))

    def test_write_failure_removes_owned_empty_directory_not_foreign_files(self):
        with self.transaction(failure="write") as (_, _, rollback, _, rmdir):
            with self.assertRaises(OSError):
                REMOTE["main_remote"]()
            rmdir.assert_called_once()
            rollback.assert_not_called()

    def test_rollback_refuses_foreign_or_concurrently_changed_dropin(self):
        with patch.dict(REMOTE, {"file_bytes": Mock(return_value=b"foreign change"), "command": Mock()}):
            with self.assertRaisesRegex(REMOTE["Refused"], "concurrent_dropin_change"):
                REMOTE["rollback"](None, True, True, (1, 20))
            REMOTE["command"].assert_not_called()
        with patch.dict(REMOTE, {"file_bytes": Mock(return_value=REMOTE["BODY"]), "command": Mock()}):
            with self.assertRaisesRegex(REMOTE["Refused"], "rollback_existing_file_refused"):
                REMOTE["rollback"](b"original", True, True, (1, 20))

    def test_rollback_refuses_replaced_inode_even_when_body_is_identical(self):
        with patch.dict(REMOTE, {"file_bytes": Mock(return_value=REMOTE["BODY"]), "command": Mock()}), \
             patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_dev=1, st_ino=99)), \
             patch.object(Path, "unlink") as unlink:
            with self.assertRaisesRegex(REMOTE["Refused"], "concurrent_dropin_change"):
                REMOTE["rollback"](None, False, False, (1, 20))
            unlink.assert_not_called()
            REMOTE["command"].assert_not_called()

    @contextlib.contextmanager
    def atomic_files(self):
        stream = Mock()
        stream.fileno.return_value = 20
        opened = MagicMock()
        opened.__enter__.return_value = stream
        with patch.dict(REMOTE, {"safe_directory": Mock(return_value=(1, 2))}), \
             patch.object(REMOTE["os"], "O_DIRECTORY", 0, create=True), \
             patch.object(REMOTE["os"], "O_NOFOLLOW", 0, create=True), \
             patch.object(REMOTE["os"], "open", side_effect=[10, 20]), \
             patch.object(REMOTE["os"], "fdopen", return_value=opened), \
             patch.object(REMOTE["os"], "fchmod", create=True), \
             patch.object(REMOTE["os"], "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=20)), \
             patch.object(REMOTE["os"], "stat", return_value=SimpleNamespace(st_dev=1, st_ino=20)), \
             patch.object(REMOTE["os"], "fsync") as fsync, \
             patch.object(REMOTE["os"], "link") as link, \
             patch.object(REMOTE["os"], "unlink") as unlink, \
             patch.object(REMOTE["os"], "close") as close:
            yield link, unlink, fsync, close

    def test_atomic_install_never_overwrites_concurrent_target(self):
        with self.atomic_files() as (link, unlink, _, close):
            link.side_effect = FileExistsError("foreign root configuration")
            with self.assertRaises(FileExistsError):
                REMOTE["atomic_dropin"](REMOTE["BODY"])
            self.assertEqual(unlink.call_count, 1)
            self.assertTrue(unlink.call_args.args[0].startswith(".qvpn-sandbox-"))
            self.assertNotEqual(unlink.call_args.args[0], REMOTE["DROPIN"].name)
            close.assert_called_once_with(10)

    def test_atomic_cleanup_failure_removes_only_own_link_before_caller_success(self):
        with self.atomic_files() as (_, unlink, _, close):
            unlink.side_effect = [OSError("temporary unlink failed"), None, None]
            with self.assertRaises(OSError):
                REMOTE["atomic_dropin"](REMOTE["BODY"])
            self.assertEqual(unlink.call_args_list[1].args[0], REMOTE["DROPIN"].name)
            self.assertTrue(unlink.call_args_list[2].args[0].startswith(".qvpn-sandbox-"))
            close.assert_called_once_with(10)

    def test_atomic_success_returns_owned_inode_and_cleans_staging(self):
        with self.atomic_files() as (link, unlink, _, close):
            self.assertEqual(REMOTE["atomic_dropin"](REMOTE["BODY"]), (1, 20))
            self.assertEqual(link.call_args.args[1], REMOTE["DROPIN"].name)
            unlink.assert_called_once()
            self.assertTrue(unlink.call_args.args[0].startswith(".qvpn-sandbox-"))
            close.assert_called_once_with(10)

    def test_source_local_ssh_defaults_are_pinned_and_secret_never_in_argv(self):
        source = Path(installer.__file__).read_text(encoding="utf-8")
        self.assertIn("set_missing_host_key_policy(paramiko.RejectPolicy())", source)
        self.assertIn("C:/Users/Admin/.ssh/known_hosts", source)
        self.assertIn("client.connect('150.241.96.191'", source)
        self.assertIn("os.environ.get('QVPN_VDS_PASSWORD')", source)
        self.assertIn("exec_command('python3 -B -'", source)
        self.assertNotIn("AutoAddPolicy", source)
        self.assertNotIn("apt-get", source)
        self.assertNotIn("rmtree", source)


if __name__ == "__main__":
    unittest.main()
