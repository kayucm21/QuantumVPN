"""Offline installer tests; no VDS, SSH, systemd, or network operations."""
from __future__ import annotations

from contextlib import redirect_stdout
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location("install_refresh", Path(__file__).with_name("install-mtproto-refresh-vds.py"))
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def helpers():
    namespace = {"RUN_REMOTE": False, "SOURCE_SHA256": installer.SOURCE_SHA256}
    exec(compile(installer.REMOTE, "<refresh-installer-under-test>", "exec"), namespace)
    return namespace


class ContractTests(unittest.TestCase):
    def test_unit_is_daily_guarded_root_oneshot_with_exact_write_scope(self):
        remote = helpers()
        service, timer = remote["service_text"](), remote["timer_text"]()
        for value in ("Type=oneshot", "User=root", "Group=root", "python3 -B ", "--apply",
                      "TimeoutStartSec=240", "RuntimeMaxSec=240", "MemoryMax=128M", "CPUQuota=25%",
                      "Nice=10", "LimitCORE=0", "ProtectSystem=strict", "NoNewPrivileges=true",
                      "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "CapabilityBoundingSet=CAP_SYS_PTRACE",
                      "ReadWritePaths=/etc/quantumvpn-mtproto /var/lib/quantumvpn-operator/mtproto-upstream-backups",
                      "StandardOutput=null", "StandardError=null"):
            self.assertIn(value, service)
        self.assertEqual(len([line for line in service.splitlines() if line.startswith("ReadWritePaths=")]), 1)
        for value in ("OnCalendar=*-*-* 02:17:00 UTC", "RandomizedDelaySec=300", "Persistent=true",
                      "Unit=quantumvpn-mtproto-refresh.service", "WantedBy=timers.target"):
            self.assertIn(value, timer)
        self.assertNotIn("Wants=quantumvpn-mtproto.service", service)
        for value in ("nginx", "rospanel", "iptables", "ufw", "sysctl"):
            self.assertNotIn(value, installer.REMOTE)

    def test_trusted_source_is_pinned_and_loaded_without_running_cli(self):
        remote = helpers()
        source = Path(installer.__file__).with_name("refresh-mtproto-upstream.py").read_bytes()
        remote["SOURCE_B64"] = base64.b64encode(source).decode()
        self.assertEqual(installer.hashlib.sha256(source).hexdigest(), installer.SOURCE_SHA256)
        with patch("builtins.print") as output:
            data, module = remote["trusted_source"]()
        self.assertEqual(data, source)
        self.assertIn("owned_install", module)
        output.assert_not_called()
        remote["SOURCE_B64"] = base64.b64encode(b"untrusted").decode()
        with self.assertRaisesRegex(RuntimeError, "refresh_source_identity_mismatch"):
            remote["trusted_source"]()

    def test_command_suppresses_stderr_and_raw_errors(self):
        remote = helpers()
        with patch.object(remote["subprocess"], "run", return_value=Mock(returncode=1, stdout="private raw output")) as run:
            with self.assertRaisesRegex(RuntimeError, "^bounded_install_command_failed$"):
                remote["command"](["systemctl", "daemon-reload"])
        self.assertEqual(run.call_args.kwargs["stderr"], remote["subprocess"].DEVNULL)
        with patch.object(remote["subprocess"], "run", side_effect=OSError("private raw exception")), \
             self.assertRaisesRegex(RuntimeError, "^bounded_install_command_failed$"):
            remote["command"](["fixed"])

    def test_refresh_cli_accepts_only_bounded_trusted_success_json(self):
        remote = helpers()
        for raw in ("key material", '{"status":"Failed"}', '[]', "x" * 8193):
            remote["command"] = Mock(return_value=raw)
            with self.assertRaises(RuntimeError):
                remote["refresh_now"]({})
        remote["command"] = Mock(return_value='{"status":"Unchanged","changed":false}')
        self.assertEqual(remote["refresh_now"]({})["status"], "Unchanged")
        args = remote["command"].call_args.args
        self.assertEqual(args[0], ["/usr/bin/python3", "-B", str(remote["SCRIPT"]), "--apply"])
        self.assertEqual(args[1], 260)

    def test_local_ssh_rejects_unknown_host_and_never_places_credentials_in_command(self):
        password = "fixture private password"
        client = Mock()
        output = Mock()
        output.__iter__ = Mock(return_value=iter(['{"status":"ReadOnly","changed":false}\n']))
        output.channel.recv_exit_status.return_value = 0
        stdin, stderr = Mock(), Mock()
        client.exec_command.return_value = stdin, output, stderr
        paramiko = Mock()
        paramiko.SSHClient.return_value = client
        with patch.dict(sys.modules, {"paramiko": paramiko}), \
             patch.dict(installer.os.environ, {"QVPN_VDS_PASSWORD": password}), \
             patch.object(sys, "argv", ["install-refresh"]), redirect_stdout(io.StringIO()):
            installer.main()
        client.load_host_keys.assert_called_once_with("C:/Users/Admin/.ssh/known_hosts")
        client.set_missing_host_key_policy.assert_called_once_with(paramiko.RejectPolicy.return_value)
        self.assertEqual(client.connect.call_args.args[0], "150.241.96.191")
        self.assertEqual(client.connect.call_args.kwargs["password"], password)
        self.assertFalse(client.connect.call_args.kwargs["allow_agent"])
        self.assertFalse(client.connect.call_args.kwargs["look_for_keys"])
        client.exec_command.assert_called_once_with("python3 -B -", timeout=420)
        self.assertNotIn(password, stdin.write.call_args.args[0])
        self.assertTrue(stdin.write.call_args.args[0].startswith("APPLY=False\n"))
        client.close.assert_called_once()


class InstallerTransactionTests(unittest.TestCase):
    def setUp(self):
        self.remote = helpers()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        runtime, units = self.root / "runtime", self.root / "units"
        runtime.mkdir();units.mkdir()
        self.backups = self.root / "backups"
        self.remote.update(SCRIPT=runtime / "refresh-mtproto-upstream.py", UNIT_ROOT=units,
                           WANTED=units / "timers.target.wants" / self.remote["TIMER"], APPLY=True)
        # POSIX metadata checking is delegated to the already-tested pinned
        # refresh helpers. Keep real file writes/renames for transaction tests.
        self.remote["os"] = SimpleNamespace(**{**vars(os), "name": "posix", "geteuid": lambda: 0,
                                               "fchmod": getattr(os, "fchmod", lambda fd, mode: None)})
        self.source = b"trusted refresh fixture"
        self.install = {"module": {}}
        self.module = {"owned_install": Mock(return_value=self.install), "verify_service": Mock(),
                       "assert_install": Mock(), "proof": Mock(return_value={"ok": True, "method": "mtproto_req_pq_multi"}),
                       "inspect_or_refresh": Mock(return_value={"status": "ReadOnly", "would_change": False}),
                       "directory": Mock(), "read_file": lambda path, *args: path.read_bytes(),
                       "_metadata": Mock(), "_parents": Mock(), "_sync_dir": Mock(), "BACKUPS": self.backups,
                       "_private_store": Mock(side_effect=lambda: self.backups.mkdir(exist_ok=True))}
        self.remote["trusted_source"] = Mock(return_value=(self.source, self.module))
        self.enabled = False
        self.commands = []
        self.remote["command"] = Mock(side_effect=self.command)
        self.remote["unit_properties"] = Mock(side_effect=self.unit_properties)

    def command(self, args, *unused, **kwargs):
        self.commands.append(args)
        if args[:3] == ["systemctl", "enable", "--now"]:
            self.enabled = True
        if args[:3] == ["systemctl", "disable", "--now"]:
            self.enabled = False
        if args[0] == "/usr/bin/python3":
            return '{"status":"Unchanged","changed":false}'
        return ""

    def unit_properties(self, name):
        path = self.remote["UNIT_ROOT"] / name
        if not path.exists():
            return {"LoadState": "not-found", "FragmentPath": "", "DropInPaths": ""}
        return {"LoadState": "loaded", "FragmentPath": str(path), "DropInPaths": "", "NeedDaemonReload": "no",
                "ActiveState": "active" if self.enabled else "inactive", "UnitFileState": "enabled" if self.enabled else "disabled"}

    def run_main(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.remote["main"]()
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def expected(self):
        return self.remote["artifacts"](self.source)

    def create_existing(self):
        for path, data in self.expected().items():
            path.write_bytes(data)

    def test_default_inspection_writes_nothing_and_runs_no_mutating_command(self):
        self.remote["APPLY"] = False
        report = self.run_main()[0]
        self.assertEqual(report["status"], "ReadOnly")
        self.assertFalse(report["installed"])
        self.assertEqual(self.commands, [])
        self.module["_private_store"].assert_not_called()
        self.module["proof"].assert_not_called()
        self.assertFalse(self.backups.exists())
        self.assertTrue(all(not path.exists() for path in self.expected()))

    def test_fresh_apply_installs_three_exact_files_proves_and_enables_only_new_timer(self):
        report = self.run_main()[0]
        self.assertEqual(report["status"], "Installed")
        for path, data in self.expected().items():
            self.assertEqual(path.read_bytes(), data)
        self.assertEqual(self.module["proof"].call_count, 2)
        self.assertEqual([args for args in self.commands if args[:2] == ["systemctl", "enable"]],
                         [["systemctl", "enable", "--now", self.remote["TIMER"]]])
        self.assertFalse(any("quantumvpn-mtproto.service" in args for args in self.commands))

    def test_same_pinned_install_preserves_owner_disabled_and_stopped_timer(self):
        self.create_existing()
        report = self.run_main()[0]
        self.assertEqual(report["status"], "AlreadyInstalled")
        self.assertTrue(report["timer_state_preserved"])
        self.assertFalse(self.enabled)
        self.assertTrue(all(args[0] == "/usr/bin/python3" for args in self.commands))
        self.assertEqual(self.module["proof"].call_count, 2)

    def test_incomplete_or_unmanaged_existing_files_refused_without_changes(self):
        script = self.remote["SCRIPT"]
        script.write_bytes(b"owner content")
        with self.assertRaisesRegex(RuntimeError, "incomplete_existing_refresh_install_refused"):
            self.run_main()
        self.assertEqual(script.read_bytes(), b"owner content")
        self.create_existing()
        script.write_bytes(b"owner content")
        with self.assertRaisesRegex(RuntimeError, "unmanaged_refresh_artifact_refused"):
            self.run_main()
        self.assertEqual(script.read_bytes(), b"owner content")
        self.module["_private_store"].assert_not_called()
        self.assertEqual(self.commands, [])

    def test_unmanaged_runtime_unit_and_prechange_nonce_refused_before_writes(self):
        self.remote["unit_properties"].side_effect = None
        self.remote["unit_properties"].return_value = {"LoadState": "loaded", "FragmentPath": "/run/systemd/service", "DropInPaths": ""}
        with self.assertRaisesRegex(RuntimeError, "existing_refresh_runtime_unit_refused"):
            self.run_main()
        self.remote["unit_properties"].side_effect = self.unit_properties
        self.module["proof"].side_effect = RuntimeError("nonce proof failed")
        with self.assertRaises(RuntimeError):
            self.run_main()
        self.assertTrue(all(not path.exists() for path in self.expected()))
        self.assertEqual(self.commands, [])

    def test_failed_unit_validation_recovers_only_exact_new_files_and_keeps_source_bytes(self):
        def fail_verify(args, *unused, **kwargs):
            if args[0] == "systemd-analyze":
                raise RuntimeError("bounded_install_command_failed")
            return self.command(args, **kwargs)
        self.remote["command"].side_effect = fail_verify
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, "refresh_install_failed_new_artifacts_recovered"):
            self.remote["main"]()
        self.assertTrue(all(not path.exists() for path in self.expected()))
        recovery = list(self.backups.iterdir())
        self.assertEqual(len(recovery), 1)
        self.assertEqual({path.name: path.read_bytes() for path in recovery[0].iterdir()},
                         {path.name: data for path, data in self.expected().items()})
        self.assertFalse(any(args[:2] == ["systemctl", "disable"] for args in self.commands))

    def test_activation_failure_disables_only_new_timer_and_stops_only_new_oneshot_then_recovers(self):
        def fail_enable(args, *unused, **kwargs):
            if args[:2] == ["systemctl", "enable"]:
                self.enabled = True
                raise RuntimeError("bounded_install_command_failed")
            return self.command(args, **kwargs)
        self.remote["command"].side_effect = fail_enable
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, "refresh_install_failed_new_artifacts_recovered"):
            self.remote["main"]()
        self.assertIn(["systemctl", "disable", "--now", self.remote["TIMER"]], self.commands)
        self.assertIn(["systemctl", "stop", self.remote["SERVICE"]], self.commands)
        self.assertFalse(any("quantumvpn-mtproto.service" in args for args in self.commands))
        self.assertTrue(all(not path.exists() for path in self.expected()))

    def test_recovery_refuses_changed_inode_without_moving_foreign_file(self):
        path = self.remote["SCRIPT"]
        path.write_bytes(self.source)
        original = path.stat()
        path.rename(path.with_name("saved-original"))
        path.write_bytes(b"foreign new inode")
        with self.assertRaisesRegex(RuntimeError, "recovery_inode_changed_refused"):
            self.remote["recover_created"]([(path, original.st_dev, original.st_ino)], self.expected(), self.module, False)
        self.assertEqual(path.read_bytes(), b"foreign new inode")
        self.assertEqual(self.commands, [])

    def test_exclusive_creation_refuses_existing_path_and_never_overwrites(self):
        path = self.remote["SCRIPT"]
        path.write_bytes(b"owner script")
        created = []
        with self.assertRaises(FileExistsError):
            self.remote["create_file"](path, self.source, self.module, created)
        self.assertEqual(path.read_bytes(), b"owner script")
        self.assertEqual(created, [])


if __name__ == "__main__":
    unittest.main()
