"""Offline guards for source-only deployment and isolated dependency install."""
import ast
from contextlib import closing
import hashlib
import importlib.util
import io
import itertools
from pathlib import Path
import sys
import sqlite3
import tempfile
import types
import unittest
from unittest import mock
import urllib.parse
import urllib.request
import zipfile


TOOLS = Path(__file__).resolve().parent


def module(name):
    # Only CLI construction/remote source parsing is exercised here; no SSH.
    fake = types.ModuleType("paramiko")
    fake.SSHClient = object
    with mock.patch.dict(sys.modules, {"paramiko": fake}):
        spec = importlib.util.spec_from_file_location("deployment_test", TOOLS / name)
        value = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(value)
        return value


class DeploymentGuardsTests(unittest.TestCase):
    def setUp(self):
        self.deployer = module("deploy-aurora-panel.py")

    def args(self, *extra):
        return self.deployer.parser().parse_args(["--host", "example.invalid", "--expected-old-app-sha256", "a" * 64, *extra])

    def test_quality_upload_is_explicit_pinned_and_not_an_unchanged_companion(self):
        config, payloads = self.deployer.build_config(self.args("--with-quality", "--expected-old-quality-sha256", "b" * 64))
        self.assertTrue(config["with_quality"])
        self.assertEqual(config["files"]["quantumvpn_control_quality.py"]["old_sha256"], "b" * 64)
        self.assertIn("quantumvpn_control_quality.py", payloads)
        self.assertNotIn("quantumvpn_control_quality.py", config["companions"])
        self.assertIn("quantumvpn_resources.py", config["companions"])
        with self.assertRaises(ValueError):
            self.deployer.build_config(self.args("--expected-old-quality-sha256", "b" * 64))

    def test_bot_operations_is_explicit_fixed_allowlist_and_volatile_ledger(self):
        config, payloads = self.deployer.build_config(self.args("--with-bot-operations", "--expected-old-ai-knowledge-sha256", "b" * 64))
        self.assertTrue(config["with_bot_operations"])
        self.assertTrue(set(self.deployer.BOT_OPERATIONS_MODULES) <= set(payloads))
        self.assertEqual(config["files"]["quantumvpn_ai_knowledge.py"]["old_sha256"], "b" * 64)
        self.assertIsNone(config["files"]["quantumvpn_bot_operations.py"]["old_sha256"])
        with self.assertRaises(ValueError):
            self.deployer.build_config(self.args("--expected-old-ai-knowledge-sha256", "b" * 64))
        tree = ast.parse(self.deployer.REMOTE_SOURCE)
        volatile = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == 'VOLATILE' for target in node.targets))
        self.assertIn('bot_fact_state', volatile)
        self.assertNotIn('ai_advisor_enabled', volatile)
        self.assertNotIn('app_version', volatile)

    def test_default_never_adds_community_files(self):
        config, payloads = self.deployer.build_config(self.args())
        self.assertFalse(config["apply"])
        self.assertFalse(config["with_community"])
        self.assertFalse(config["with_bot_status"])
        self.assertFalse(config["with_network_ai"])
        self.assertFalse(config["with_local_ai"])
        self.assertFalse(config["with_pulse"])
        self.assertFalse(config["with_four_source"])
        self.assertNotIn("quantumvpn_community.py", payloads)
        self.assertNotIn("quantumvpn_bot_status.py", payloads)
        self.assertTrue(set(self.deployer.NETWORK_AI_MODULES).isdisjoint(payloads))
        self.assertTrue(set(self.deployer.LOCAL_AI_MODULES).isdisjoint(payloads))
        self.assertTrue(set(self.deployer.PULSE_MODULES).isdisjoint(payloads))
        self.assertTrue(set(self.deployer.FOUR_SOURCES).isdisjoint(payloads))
        self.assertEqual(set(self.deployer.COMPANIONS), set(config["companions"]))

    def test_four_plan_upload_is_explicit_pinned_and_removes_only_its_companions(self):
        config, payloads = self.deployer.build_config(self.args("--with-four-source", "--expected-old-four-catalog-sha256", "b" * 64))
        self.assertTrue(config["with_four_source"])
        self.assertTrue(set(self.deployer.FOUR_SOURCES) <= set(payloads))
        self.assertTrue(set(self.deployer.FOUR_SOURCES).isdisjoint(config["companions"]))
        self.assertEqual(config["files"]["quantumvpn_four_catalog.py"]["old_sha256"], "b" * 64)
        self.assertIsNone(config["files"]["quantumvpn_four_ui.py"]["old_sha256"])
        with self.assertRaises(ValueError):
            self.deployer.build_config(self.args("--expected-old-four-ui-sha256", "c" * 64))
        tree = ast.parse(self.deployer.REMOTE_SOURCE)
        allowed = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "FOUR_SOURCES" for target in node.targets))
        self.assertEqual(allowed, set(self.deployer.FOUR_SOURCES))

    def test_four_source_preflight_rejects_missing_scope_presence_and_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scope = self.remote_scope(root)
            config = {"files": {name: {"old_sha256": None} for name in
                                ("app.py", "quantumvpn_aurora.py", *self.deployer.FOUR_SOURCES)},
                      "companions": {}, "with_four_source": True}
            scope["environment"] = lambda: {"QV_DATA_DIR": str(root)}
            with mock.patch.object(scope["os"], "geteuid", return_value=0, create=True):
                self.assertEqual(set(config["files"]), set(scope["preflight"](config)[2]))
                for name in self.deployer.FOUR_SOURCES:
                    with self.subTest(name=name):
                        missing = {**config, "files": {key: value for key, value in config["files"].items() if key != name}}
                        with self.assertRaisesRegex(scope["CheckFailed"], "four_sources_missing"):
                            scope["preflight"](missing)
                        path = root / name
                        path.write_text("# an earlier helper\n")
                        with self.assertRaisesRegex(scope["CheckFailed"], "source_presence_" + name):
                            scope["preflight"](config)
                        config["files"][name]["old_sha256"] = "e" * 64
                        with self.assertRaisesRegex(scope["CheckFailed"], "source_hash_" + name):
                            scope["preflight"](config)
                        config["files"][name]["old_sha256"] = scope["digest"](path)
                        self.assertTrue(scope["preflight"](config)[2][name]["exists"])
                for flag, name in ((False, "quantumvpn_four_ui.py"), (True, "operator.db"),
                                   (True, "../quantumvpn_four_ui.py"), (True, "quantum-n8n.service")):
                    bad = {**config, "with_four_source": flag, "files": {**config["files"], name: {"old_sha256": None}}}
                    with self.subTest(flag=flag, name=name), self.assertRaisesRegex(scope["CheckFailed"], "source_allowlist"):
                        scope["preflight"](bad)

    def test_four_source_rollback_restores_only_verified_helper_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backup = root / "source-backup"
            backup.mkdir()
            scope = self.remote_scope(root)
            existing, introduced = (root / name for name in self.deployer.FOUR_SOURCES)
            old = b"# old catalogue\n"
            (backup / existing.name).write_bytes(old)
            for path in (existing, introduced):
                path.write_text("# installed helper\n")
            scope["CONFIG"] = {"files": {path.name: {"sha256": scope["digest"](path)} for path in (existing, introduced)},
                               "upload": "fixture-four"}
            states = {existing.name: {"exists": True, "sha256": hashlib.sha256(old).hexdigest(),
                                      "uid": 0, "gid": 0, "mode": 0o600},
                      introduced.name: {"exists": False}}
            protected = {"operator.db": b"live clients", "routing-ed25519.key": b"live identity",
                         "quantum-n8n.service": b"untouched automation service"}
            for name, data in protected.items():
                (root / name).write_bytes(data)
            introduced.write_text("# concurrent edit\n")
            with self.assertRaisesRegex(scope["CheckFailed"], "rollback_source_changed"):
                scope["restore"](states, backup, [existing.name, introduced.name])
            introduced.write_text("# installed helper\n")
            with mock.patch.object(scope["os"], "chown", create=True):
                scope["restore"](states, backup, [existing.name, introduced.name])
            self.assertEqual(old, existing.read_bytes())
            self.assertFalse(introduced.exists())
            for name, data in protected.items():
                self.assertEqual(data, (root / name).read_bytes())

    def test_explicit_community_is_exact_fixed_allowlist(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tools = root / "tools"
            tools.mkdir()
            for name in ("quantumvpn_operator_panel.py", "quantumvpn_aurora.py", *self.deployer.COMPANIONS, *self.deployer.COMMUNITY_MODULES):
                (tools / name).write_text("PANEL_BUILD='2.0.0-aurora.test'\n" if name == "quantumvpn_operator_panel.py" else "# safe source\n")
            with mock.patch.object(self.deployer, "ROOT", root):
                config, payloads = self.deployer.build_config(self.args("--with-community", "--expected-old-community-sha256", "b" * 64))
            self.assertTrue(config["with_community"])
            self.assertEqual({"app.py", "quantumvpn_aurora.py", *self.deployer.COMMUNITY_MODULES}, set(payloads))
            self.assertEqual("b" * 64, config["files"]["quantumvpn_community.py"]["old_sha256"])
            self.assertIsNone(config["files"]["quantumvpn_durak.py"]["old_sha256"])
            self.assertEqual(set(self.deployer.COMPANIONS), set(config["companions"]))

    def test_old_module_hash_cannot_silently_expand_default_scope(self):
        with self.assertRaises(ValueError):
            self.deployer.build_config(self.args("--expected-old-durak-sha256", "b" * 64))

    def test_catalog_is_opt_in_exact_allowlist_with_pinned_asset_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tools = root / "tools"
            (tools / "assets").mkdir(parents=True)
            for name in ("quantumvpn_operator_panel.py", "quantumvpn_aurora.py", *self.deployer.COMPANIONS, *self.deployer.CATALOG_SOURCES):
                (tools / name).write_text("PANEL_BUILD='2.2.1-routing.test'\n" if name == "quantumvpn_operator_panel.py" else "# source\n")
            with mock.patch.object(self.deployer, "ROOT", root):
                config, payloads = self.deployer.build_config(self.args("--with-catalog", "--expected-old-catalog-seed-sha256", "d" * 64))
            self.assertTrue(config["with_catalog"])
            self.assertEqual({"app.py", "quantumvpn_aurora.py", *self.deployer.CATALOG_SOURCES}, set(payloads))
            self.assertEqual("d" * 64, config["files"]["assets/routing-catalog-seed.json"]["old_sha256"])
            self.assertIsNone(config["files"]["quantumvpn_target_catalog.py"]["old_sha256"])
        with self.assertRaises(ValueError):
            self.deployer.build_config(self.args("--expected-old-catalog-sha256", "d" * 64))

    def test_explicit_bot_status_is_exact_fixed_allowlist(self):
        for community in (False, True):
            with self.subTest(community=community), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                tools = root / "tools"
                tools.mkdir()
                for name in ("quantumvpn_operator_panel.py", "quantumvpn_aurora.py",
                             *self.deployer.COMPANIONS, *self.deployer.COMMUNITY_MODULES,
                             self.deployer.BOT_STATUS_MODULE, "unrequested.py"):
                    (tools / name).write_text("PANEL_BUILD='2.0.0-aurora.test'\n" if name == "quantumvpn_operator_panel.py" else "# safe source\n")
                options = ["--with-bot-status", "--expected-old-bot-status-sha256", "c" * 64]
                if community:
                    options.append("--with-community")
                with mock.patch.object(self.deployer, "ROOT", root):
                    config, payloads = self.deployer.build_config(self.args(*options))
                expected = {"app.py", "quantumvpn_aurora.py", self.deployer.BOT_STATUS_MODULE}
                if community:
                    expected.update(self.deployer.COMMUNITY_MODULES)
                self.assertEqual(expected, set(payloads))
                self.assertTrue(config["with_bot_status"])
                self.assertEqual(community, config["with_community"])
                self.assertEqual("c" * 64, config["files"][self.deployer.BOT_STATUS_MODULE]["old_sha256"])
                self.assertEqual(set(self.deployer.COMPANIONS), set(config["companions"]))

    def test_bot_hash_cannot_expand_scope_without_flag(self):
        with self.assertRaisesRegex(ValueError, "requires --with-bot-status"):
            self.deployer.build_config(self.args("--expected-old-bot-status-sha256", "c" * 64))

    def test_legacy_namespace_has_no_bot_status_scope(self):
        args = self.args()
        del args.with_bot_status
        del args.expected_old_bot_status_sha256
        config, payloads = self.deployer.build_config(args)
        self.assertFalse(config["with_bot_status"])
        self.assertNotIn(self.deployer.BOT_STATUS_MODULE, payloads)

    def test_explicit_network_ai_is_exact_allowlist_and_combines_with_optional_scopes(self):
        for community, bot in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(community=community, bot=bot), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                tools = root / "tools"
                tools.mkdir()
                names = ("quantumvpn_operator_panel.py", "quantumvpn_aurora.py", *self.deployer.COMPANIONS,
                         *self.deployer.COMMUNITY_MODULES, self.deployer.BOT_STATUS_MODULE,
                         *self.deployer.NETWORK_AI_MODULES, "unrequested.py")
                for name in names:
                    (tools / name).write_text("PANEL_BUILD='2.0.0-aurora.test'\n" if name == "quantumvpn_operator_panel.py" else "# safe source\n")
                options = ["--with-network-ai", "--expected-old-gemini-sha256", "d" * 64]
                if community:
                    options.extend(("--with-community", "--expected-old-target-scan-sha256", "f" * 64))
                if bot:
                    options.extend(("--with-bot-status", "--expected-old-network-guard-sha256", "e" * 64))
                with mock.patch.object(self.deployer, "ROOT", root):
                    config, payloads = self.deployer.build_config(self.args(*options))
                expected = {"app.py", "quantumvpn_aurora.py", *self.deployer.NETWORK_AI_MODULES}
                if community:
                    expected.update(self.deployer.COMMUNITY_MODULES)
                if bot:
                    expected.add(self.deployer.BOT_STATUS_MODULE)
                self.assertEqual(expected, set(payloads))
                self.assertEqual(expected, set(config["files"]))
                self.assertTrue(config["with_network_ai"])
                self.assertEqual(community, config["with_community"])
                self.assertEqual(bot, config["with_bot_status"])
                self.assertEqual("d" * 64, config["files"]["quantumvpn_gemini.py"]["old_sha256"])
                self.assertEqual("e" * 64 if bot else None, config["files"]["quantumvpn_network_guard.py"]["old_sha256"])
                self.assertEqual("f" * 64 if community else None, config["files"]["quantumvpn_target_scan.py"]["old_sha256"])
                self.assertEqual(set(self.deployer.COMPANIONS), set(config["companions"]))
                for name in self.deployer.NETWORK_AI_MODULES:
                    self.assertEqual(hashlib.sha256(payloads[name]).hexdigest(), config["files"][name]["sha256"])
                    self.assertTrue(config["files"][name]["stage"].startswith(".aurora-upload-"))

    def test_network_ai_old_hashes_require_explicit_flag(self):
        for option in ("--expected-old-gemini-sha256", "--expected-old-network-guard-sha256", "--expected-old-target-scan-sha256"):
            with self.subTest(option=option), self.assertRaisesRegex(ValueError, "require --with-network-ai"):
                self.deployer.build_config(self.args(option, "d" * 64))

    def test_legacy_namespace_has_no_network_ai_scope(self):
        args = self.args()
        for attribute in ("with_network_ai", "expected_old_gemini_sha256", "expected_old_network_guard_sha256", "expected_old_target_scan_sha256"):
            delattr(args, attribute)
        config, payloads = self.deployer.build_config(args)
        self.assertFalse(config["with_network_ai"])
        self.assertTrue(set(self.deployer.NETWORK_AI_MODULES).isdisjoint(payloads))

    def test_network_ai_compiles_both_requested_sources_locally(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tools = root / "tools"
            tools.mkdir()
            for name in ("quantumvpn_operator_panel.py", "quantumvpn_aurora.py", *self.deployer.COMPANIONS,
                         *self.deployer.NETWORK_AI_MODULES):
                (tools / name).write_text("PANEL_BUILD='2.0.0-aurora.test'\n" if name == "quantumvpn_operator_panel.py" else "# safe source\n")
            for name in self.deployer.NETWORK_AI_MODULES:
                with self.subTest(name=name), mock.patch.object(self.deployer, "ROOT", root):
                    (tools / name).write_text("def broken(:\n")
                    with self.assertRaises(SyntaxError):
                        self.deployer.build_config(self.args("--with-network-ai"))
                    (tools / name).write_text("# safe source\n")

    def test_local_ai_exact_allowlist_combines_with_all_optional_scopes(self):
        for community, bot, network in itertools.product((False, True), repeat=3):
            with self.subTest(community=community, bot=bot, network=network), tempfile.TemporaryDirectory() as temp:
                root, tools = Path(temp), Path(temp) / "tools"
                tools.mkdir()
                for name in ("quantumvpn_operator_panel.py", "quantumvpn_aurora.py", *self.deployer.COMPANIONS,
                             *self.deployer.COMMUNITY_MODULES, self.deployer.BOT_STATUS_MODULE,
                             *self.deployer.NETWORK_AI_MODULES, *self.deployer.LOCAL_AI_MODULES,
                             "unrequested.py"):
                    (tools / name).write_text("PANEL_BUILD='2.1.2-local.test'\n" if name == "quantumvpn_operator_panel.py" else "# safe source\n")
                options = ["--with-local-ai", "--expected-old-llama-sha256", "b" * 64,
                           "--expected-old-autopilot-sha256", "c" * 64]
                if community: options.append("--with-community")
                if bot: options.append("--with-bot-status")
                if network: options.append("--with-network-ai")
                with mock.patch.object(self.deployer, "ROOT", root):
                    config, payloads = self.deployer.build_config(self.args(*options))
                expected = {"app.py", "quantumvpn_aurora.py", *self.deployer.LOCAL_AI_MODULES}
                if community: expected.update(self.deployer.COMMUNITY_MODULES)
                if bot: expected.add(self.deployer.BOT_STATUS_MODULE)
                if network: expected.update(self.deployer.NETWORK_AI_MODULES)
                self.assertEqual(expected, set(payloads))
                self.assertEqual(expected, set(config["files"]))
                self.assertTrue(config["with_local_ai"])
                self.assertEqual("b" * 64, config["files"]["quantumvpn_llama.py"]["old_sha256"])
                self.assertEqual("c" * 64, config["files"]["quantumvpn_autopilot.py"]["old_sha256"])
                self.assertIsNone(config["files"]["quantumvpn_maintenance.py"]["old_sha256"])
                self.assertEqual(set(self.deployer.COMPANIONS), set(config["companions"]))
                for name in self.deployer.LOCAL_AI_MODULES:
                    self.assertEqual(hashlib.sha256(payloads[name]).hexdigest(), config["files"][name]["sha256"])

    def test_local_ai_hashes_require_explicit_scope_and_legacy_namespace_is_safe(self):
        for option in ("--expected-old-llama-sha256", "--expected-old-autopilot-sha256", "--expected-old-maintenance-sha256"):
            with self.subTest(option=option), self.assertRaisesRegex(ValueError, "require --with-local-ai"):
                self.deployer.build_config(self.args(option, "d" * 64))
        args = self.args()
        for attribute in ("with_local_ai", "expected_old_llama_sha256", "expected_old_autopilot_sha256", "expected_old_maintenance_sha256"):
            delattr(args, attribute)
        config, payloads = self.deployer.build_config(args)
        self.assertFalse(config["with_local_ai"])
        self.assertTrue(set(self.deployer.LOCAL_AI_MODULES).isdisjoint(payloads))

    def test_local_ai_rejects_missing_and_invalid_local_sources_before_upload(self):
        with tempfile.TemporaryDirectory() as temp:
            root, tools = Path(temp), Path(temp) / "tools"
            tools.mkdir()
            for name in ("quantumvpn_operator_panel.py", "quantumvpn_aurora.py", *self.deployer.COMPANIONS,
                         *self.deployer.LOCAL_AI_MODULES):
                (tools / name).write_text("PANEL_BUILD='2.1.2-local.test'\n" if name == "quantumvpn_operator_panel.py" else "# safe source\n")
            with mock.patch.object(self.deployer, "ROOT", root):
                for name in self.deployer.LOCAL_AI_MODULES:
                    with self.subTest(name=name):
                        path = tools / name
                        path.unlink()
                        with self.assertRaises(FileNotFoundError):
                            self.deployer.build_config(self.args("--with-local-ai"))
                        path.write_text("def broken(:\n")
                        with self.assertRaises(SyntaxError):
                            self.deployer.build_config(self.args("--with-local-ai"))
                        path.write_text("# safe source\n")

    def test_local_ai_settings_guard_masks_only_runtime_observations(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            # Restore the real function, rather than the generic fixture stub.
            real = {"__name__": "offline_settings_fixture"}
            exec(self.deployer.REMOTE_SOURCE, real)
            database = root / "operator.db"
            with closing(sqlite3.connect(database)) as db:
                db.executescript("create table settings(key text,value text); create table resource_state(id integer, sequence integer,production text,staging text,percent integer); create table resource_bundles(id integer); insert into resource_state values(1,1,'fixture','fixture',100);")
                db.executemany("insert into settings values (?,?)", [("ai_engine", "ollama"), ("ai_autopilot_enabled", "0"), ("nodes_recommended", "fixture-node"), ("ai_autopilot_state", "{}"), ("ai_autopilot_last_run", "1"), ("ai_autopilot_last_status", "observing"), ("ai_autopilot_last_action", "")])
                db.commit()
            baseline = real["db_snapshot"](root)
            for key in ("ai_engine", "ai_autopilot_enabled", "nodes_recommended"):
                with self.subTest(stable=key), closing(sqlite3.connect(database)) as db:
                    old = db.execute("select value from settings where key=?", (key,)).fetchone()[0]
                    db.execute("update settings set value='changed' where key=?", (key,))
                    db.commit()
                    self.assertNotEqual(baseline, real["db_snapshot"](root))
                    db.execute("update settings set value=? where key=?", (old, key))
                    db.commit()
            for key in ("ai_autopilot_state", "ai_autopilot_last_run", "ai_autopilot_last_status", "ai_autopilot_last_action"):
                with self.subTest(volatile=key), closing(sqlite3.connect(database)) as db:
                    db.execute("update settings set value='new observation' where key=?", (key,))
                    db.commit()
                    self.assertEqual(baseline, real["db_snapshot"](root))

    def test_pulse_exact_allowlist_combines_with_local_ai_and_other_scopes(self):
        for local_ai, network_ai, bot in itertools.product((False, True), repeat=3):
            with self.subTest(local_ai=local_ai, network_ai=network_ai, bot=bot), tempfile.TemporaryDirectory() as temp:
                root, tools = Path(temp), Path(temp) / "tools"
                tools.mkdir()
                for name in ("quantumvpn_operator_panel.py", "quantumvpn_aurora.py", *self.deployer.COMPANIONS,
                             *self.deployer.PULSE_MODULES, *self.deployer.LOCAL_AI_MODULES,
                             *self.deployer.NETWORK_AI_MODULES, self.deployer.BOT_STATUS_MODULE,
                             "install-mtproto-vds.py", "proxy-secret"):
                    (tools / name).write_text("PANEL_BUILD='2.3.0-pulse.test'\n" if name == "quantumvpn_operator_panel.py" else "# safe source\n")
                options = ["--with-pulse", "--expected-old-network-center-sha256", "a" * 64,
                           "--expected-old-ai-journal-sha256", "b" * 64]
                if local_ai: options.append("--with-local-ai")
                if network_ai: options.append("--with-network-ai")
                if bot: options.append("--with-bot-status")
                with mock.patch.object(self.deployer, "ROOT", root):
                    config, payloads = self.deployer.build_config(self.args(*options))
                expected = {"app.py", "quantumvpn_aurora.py", *self.deployer.PULSE_MODULES}
                if local_ai: expected.update(self.deployer.LOCAL_AI_MODULES)
                if network_ai: expected.update(self.deployer.NETWORK_AI_MODULES)
                if bot: expected.add(self.deployer.BOT_STATUS_MODULE)
                self.assertEqual(expected, set(payloads))
                self.assertEqual(expected, set(config["files"]))
                self.assertTrue(config["with_pulse"])
                self.assertEqual("a" * 64, config["files"]["quantumvpn_network_center.py"]["old_sha256"])
                self.assertEqual("b" * 64, config["files"]["quantumvpn_ai_journal.py"]["old_sha256"])
                self.assertIsNone(config["files"]["quantumvpn_mtproto.py"]["old_sha256"])
                self.assertEqual(set(self.deployer.COMPANIONS), set(config["companions"]))
                for name in self.deployer.PULSE_MODULES:
                    self.assertEqual(hashlib.sha256(payloads[name]).hexdigest(), config["files"][name]["sha256"])
                    self.assertTrue(config["files"][name]["stage"].startswith(".aurora-upload-"))

    def test_pulse_hashes_require_explicit_scope_and_legacy_namespace_is_safe(self):
        for option in ("--expected-old-network-center-sha256", "--expected-old-ai-journal-sha256", "--expected-old-mtproto-sha256", "--expected-old-proxy-links-sha256", "--expected-old-webproxy-sha256"):
            with self.subTest(option=option), self.assertRaisesRegex(ValueError, "require --with-pulse"):
                self.deployer.build_config(self.args(option, "d" * 64))
        args = self.args()
        for attribute in ("with_pulse", "expected_old_network_center_sha256", "expected_old_ai_journal_sha256", "expected_old_mtproto_sha256", "expected_old_proxy_links_sha256", "expected_old_webproxy_sha256"):
            delattr(args, attribute)
        config, payloads = self.deployer.build_config(args)
        self.assertFalse(config["with_pulse"])
        self.assertTrue(set(self.deployer.PULSE_MODULES).isdisjoint(payloads))

    def test_pulse_rejects_missing_and_invalid_local_sources_before_upload(self):
        with tempfile.TemporaryDirectory() as temp:
            root, tools = Path(temp), Path(temp) / "tools"
            tools.mkdir()
            for name in ("quantumvpn_operator_panel.py", "quantumvpn_aurora.py", *self.deployer.COMPANIONS,
                         *self.deployer.PULSE_MODULES):
                (tools / name).write_text("PANEL_BUILD='2.3.0-pulse.test'\n" if name == "quantumvpn_operator_panel.py" else "# safe source\n")
            with mock.patch.object(self.deployer, "ROOT", root):
                for name in self.deployer.PULSE_MODULES:
                    with self.subTest(name=name):
                        path = tools / name
                        path.unlink()
                        with self.assertRaises(FileNotFoundError):
                            self.deployer.build_config(self.args("--with-pulse"))
                        path.write_text("def broken(:\n")
                        with self.assertRaises(SyntaxError):
                            self.deployer.build_config(self.args("--with-pulse"))
                        path.write_text("# safe source\n")

    def test_remote_pulse_requires_all_sources_and_verified_presence_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scope = self.remote_scope(root)
            config = {"files": {name: {"old_sha256": None} for name in ("app.py", "quantumvpn_aurora.py", *self.deployer.PULSE_MODULES)},
                      "companions": {}, "with_pulse": True}
            scope["environment"] = lambda: {"QV_DATA_DIR": str(root)}
            with mock.patch.object(scope["os"], "geteuid", return_value=0, create=True):
                self.assertEqual(set(config["files"]), set(scope["preflight"](config)[2]))
                for name in self.deployer.PULSE_MODULES:
                    with self.subTest(name=name):
                        missing = {**config, "files": {key: item for key, item in config["files"].items() if key != name}}
                        with self.assertRaisesRegex(scope["CheckFailed"], "pulse_sources_missing"):
                            scope["preflight"](missing)
                        path = root / name
                        path.write_text("# already installed\n")
                        with self.assertRaisesRegex(scope["CheckFailed"], "source_presence_" + name):
                            scope["preflight"](config)
                        config["files"][name]["old_sha256"] = "e" * 64
                        with self.assertRaisesRegex(scope["CheckFailed"], "source_hash_" + name):
                            scope["preflight"](config)
                        config["files"][name]["old_sha256"] = scope["digest"](path)
                        self.assertTrue(scope["preflight"](config)[2][name]["exists"])
                for flag, name in ((False, "quantumvpn_network_center.py"), (True, "unrequested.py"),
                                   (True, "../quantumvpn_mtproto.py"), (True, "install-mtproto-vds.py"),
                                   (True, "quantumvpn-mtproto.service"), (True, "client-secret")):
                    with self.subTest(flag=flag, name=name):
                        bad = {**config, "with_pulse": flag, "files": {**config["files"], name: {"old_sha256": None}}}
                        with self.assertRaisesRegex(scope["CheckFailed"], "source_allowlist"):
                            scope["preflight"](bad)

    def test_pulse_rollback_only_restores_sources_not_proxy_state_or_database(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backup = root / "source-backup"
            backup.mkdir()
            scope = self.remote_scope(root)
            existing, introduced = (root / name for name in ("quantumvpn_network_center.py", "quantumvpn_mtproto.py"))
            old = b"# previous network center\n"
            (backup / existing.name).write_bytes(old)
            for path in (existing, introduced): path.write_text("# installed Pulse source\n")
            scope["CONFIG"] = {"files": {path.name: {"sha256": scope["digest"](path)} for path in (existing, introduced)}, "upload": "fixture-pulse"}
            states = {existing.name: {"exists": True, "sha256": hashlib.sha256(old).hexdigest(), "uid": 0, "gid": 0, "mode": 0o600}, introduced.name: {"exists": False}}
            protected = {"operator.db": b"live users and settings", "client-secret": b"private client credential", "quantumvpn-mtproto.service": b"active proxy service unit"}
            for name, content in protected.items(): (root / name).write_bytes(content)
            introduced.write_text("# concurrent edit\n")
            with self.assertRaisesRegex(scope["CheckFailed"], "rollback_source_changed"):
                scope["restore"](states, backup, [existing.name, introduced.name])
            introduced.write_text("# installed Pulse source\n")
            with mock.patch.object(scope["os"], "chown", create=True):
                scope["restore"](states, backup, [existing.name, introduced.name])
            self.assertEqual(old, existing.read_bytes())
            self.assertFalse(introduced.exists())
            for name, content in protected.items(): self.assertEqual(content, (root / name).read_bytes())

    def test_pulse_policy_changes_remain_in_stable_configuration_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = {"__name__": "offline_settings_fixture"}
            exec(self.deployer.REMOTE_SOURCE, real)
            with closing(sqlite3.connect(root / "operator.db")) as db:
                db.executescript("create table settings(key text,value text); create table resource_state(id integer, sequence integer,production text,staging text,percent integer); create table resource_bundles(id integer); insert into resource_state values(1,1,'fixture','fixture',100);")
                db.executemany("insert into settings values (?,?)", [("ai_monitor_interval_seconds", "60"), ("ai_action_cooldown_seconds", "900"), ("ai_required_checks", "3")])
                db.commit()
            baseline = real["db_snapshot"](root)
            for key in ("ai_monitor_interval_seconds", "ai_action_cooldown_seconds", "ai_required_checks"):
                with self.subTest(key=key), closing(sqlite3.connect(root / "operator.db")) as db:
                    old = db.execute("select value from settings where key=?", (key,)).fetchone()[0]
                    db.execute("update settings set value='changed' where key=?", (key,))
                    db.commit()
                    self.assertNotEqual(baseline, real["db_snapshot"](root))
                    db.execute("update settings set value=? where key=?", (old, key))
                    db.commit()

    def test_remote_local_ai_requires_all_sources_exact_presence_and_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scope = self.remote_scope(root)
            config = {"files": {name: {"old_sha256": None} for name in ("app.py", "quantumvpn_aurora.py", *self.deployer.LOCAL_AI_MODULES)}, "companions": {}, "with_local_ai": True}
            scope["environment"] = lambda: {"QV_DATA_DIR": str(root)}
            with mock.patch.object(scope["os"], "geteuid", return_value=0, create=True):
                self.assertEqual(set(config["files"]), set(scope["preflight"](config)[2]))
                for name in self.deployer.LOCAL_AI_MODULES:
                    with self.subTest(name=name):
                        missing = {**config, "files": {key: item for key, item in config["files"].items() if key != name}}
                        with self.assertRaisesRegex(scope["CheckFailed"], "local_ai_sources_missing"):
                            scope["preflight"](missing)
                        path = root / name
                        path.write_text("# already installed\n")
                        with self.assertRaisesRegex(scope["CheckFailed"], "source_presence_" + name):
                            scope["preflight"](config)
                        config["files"][name]["old_sha256"] = "e" * 64
                        with self.assertRaisesRegex(scope["CheckFailed"], "source_hash_" + name):
                            scope["preflight"](config)
                        config["files"][name]["old_sha256"] = scope["digest"](path)
                        self.assertTrue(scope["preflight"](config)[2][name]["exists"])
                for flag, name in ((False, "quantumvpn_llama.py"), (True, "unrequested.py"), (True, "../quantumvpn_autopilot.py"), (True, "llama-server")):
                    with self.subTest(flag=flag, name=name):
                        bad = {**config, "with_local_ai": flag, "files": {**config["files"], name: {"old_sha256": None}}}
                        with self.assertRaisesRegex(scope["CheckFailed"], "source_allowlist"):
                            scope["preflight"](bad)

    def test_local_ai_rollback_only_restores_or_removes_verified_source_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backup = root / "source-backup"
            backup.mkdir()
            scope = self.remote_scope(root)
            existing, introduced = (root / name for name in ("quantumvpn_llama.py", "quantumvpn_maintenance.py"))
            old = b"# previous local adapter\n"
            (backup / existing.name).write_bytes(old)
            for path in (existing, introduced): path.write_text("# installed source\n")
            scope["CONFIG"] = {"files": {path.name: {"sha256": scope["digest"](path)} for path in (existing, introduced)}, "upload": "fixture-local-ai"}
            states = {existing.name: {"exists": True, "sha256": hashlib.sha256(old).hexdigest(), "uid": 0, "gid": 0, "mode": 0o600}, introduced.name: {"exists": False}}
            database = root / "operator.db"
            model = root / "qwen.gguf"
            database.write_bytes(b"live users and settings")
            model.write_bytes(b"previously installed model")
            introduced.write_text("# concurrent edit\n")
            with self.assertRaisesRegex(scope["CheckFailed"], "rollback_source_changed"):
                scope["restore"](states, backup, [existing.name, introduced.name])
            introduced.write_text("# installed source\n")
            with mock.patch.object(scope["os"], "chown", create=True):
                scope["restore"](states, backup, [existing.name, introduced.name])
            self.assertEqual(old, existing.read_bytes())
            self.assertFalse(introduced.exists())
            self.assertEqual(b"live users and settings", database.read_bytes())
            self.assertEqual(b"previously installed model", model.read_bytes())

    def remote_scope(self, root):
        namespace = {"__name__": "offline_deployment_fixture"}
        exec(self.deployer.REMOTE_SOURCE, namespace)
        namespace.update(ROOT=root, environment=lambda: {}, command=lambda *args, **kwargs: b"active",
                         db_snapshot=lambda _: {}, key_snapshot=lambda _: ("key", "public"),
                         importlib=types.SimpleNamespace(import_module=lambda _: None))
        return namespace

    def test_remote_bot_allowlist_presence_and_hash_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scope = self.remote_scope(root)
            config = {"files": {"app.py": {"old_sha256": None},
                                "quantumvpn_aurora.py": {"old_sha256": None},
                                "quantumvpn_bot_status.py": {"old_sha256": None}},
                      "companions": {}, "with_bot_status": True}
            scope["environment"] = lambda: {"QV_DATA_DIR": str(root)}
            with mock.patch.object(scope["os"], "geteuid", return_value=0, create=True):
                # A first install explicitly requires the module to be absent.
                states = scope["preflight"](config)[2]
                self.assertEqual({"exists": False}, states["quantumvpn_bot_status.py"])
                (root / "quantumvpn_bot_status.py").write_text("# existing module\n")
                with self.assertRaisesRegex(scope["CheckFailed"], "source_presence_quantumvpn_bot_status.py"):
                    scope["preflight"](config)
                config["files"]["quantumvpn_bot_status.py"]["old_sha256"] = "f" * 64
                with self.assertRaisesRegex(scope["CheckFailed"], "source_hash_quantumvpn_bot_status.py"):
                    scope["preflight"](config)
                config["files"]["quantumvpn_bot_status.py"]["old_sha256"] = scope["digest"](root / "quantumvpn_bot_status.py")
                states = scope["preflight"](config)[2]
                self.assertTrue(states["quantumvpn_bot_status.py"]["exists"])
                self.assertEqual(config["files"]["quantumvpn_bot_status.py"]["old_sha256"],
                                 states["quantumvpn_bot_status.py"]["sha256"])
                for flag, name, error in ((False, "quantumvpn_bot_status.py", "source_allowlist"),
                                          (True, "unrequested.py", "source_allowlist")):
                    with self.subTest(flag=flag, name=name):
                        bad = {**config, "with_bot_status": flag,
                               "files": {**config["files"], name: {"old_sha256": None}}}
                        with self.assertRaisesRegex(scope["CheckFailed"], error):
                            scope["preflight"](bad)
                missing = {**config, "files": {name: info for name, info in config["files"].items()
                                               if name != "quantumvpn_bot_status.py"}}
                with self.assertRaisesRegex(scope["CheckFailed"], "bot_status_source_missing"):
                    scope["preflight"](missing)

    def test_bot_rollback_is_source_only_and_checks_exact_installed_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backup = root / "source-backup"
            backup.mkdir()
            scope = self.remote_scope(root)
            path = root / "quantumvpn_bot_status.py"
            path.write_text("# newly installed\n")
            installed = scope["digest"](path)
            scope["CONFIG"] = {"files": {path.name: {"sha256": installed}}, "upload": "fixture"}
            # Existing modules are copied back; an introduced module alone is
            # removed. An unrelated live database never becomes a rollback target.
            database = root / "operator.db"
            database.write_bytes(b"wallet changes after deployment")
            states = {path.name: {"exists": False}}
            path.write_text("# concurrently changed\n")
            with self.assertRaisesRegex(scope["CheckFailed"], "rollback_source_changed"):
                scope["restore"](states, backup, [path.name])
            self.assertTrue(path.exists())
            path.write_text("# newly installed\n")
            scope["restore"](states, backup, [path.name])
            self.assertFalse(path.exists())
            self.assertEqual(b"wallet changes after deployment", database.read_bytes())

    def test_remote_network_ai_allowlist_presence_and_hash_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scope = self.remote_scope(root)
            names = ("app.py", "quantumvpn_aurora.py", *self.deployer.NETWORK_AI_MODULES, self.deployer.BOT_STATUS_MODULE)
            config = {"files": {name: {"old_sha256": None} for name in names}, "companions": {},
                      "with_network_ai": True, "with_bot_status": True}
            scope["environment"] = lambda: {"QV_DATA_DIR": str(root)}
            with mock.patch.object(scope["os"], "geteuid", return_value=0, create=True):
                states = scope["preflight"](config)[2]
                for name in self.deployer.NETWORK_AI_MODULES:
                    with self.subTest(name=name):
                        self.assertEqual({"exists": False}, states[name])
                        missing = {**config, "files": {key: value for key, value in config["files"].items() if key != name}}
                        with self.assertRaisesRegex(scope["CheckFailed"], "network_ai_sources_missing"):
                            scope["preflight"](missing)
                        path = root / name
                        path.write_text("# existing module\n")
                        with self.assertRaisesRegex(scope["CheckFailed"], "source_presence_" + name):
                            scope["preflight"](config)
                        config["files"][name]["old_sha256"] = "f" * 64
                        with self.assertRaisesRegex(scope["CheckFailed"], "source_hash_" + name):
                            scope["preflight"](config)
                        config["files"][name]["old_sha256"] = scope["digest"](path)
                        self.assertTrue(scope["preflight"](config)[2][name]["exists"])
                for flag, name in ((False, "quantumvpn_gemini.py"), (True, "unrequested.py"),
                                   (True, "../quantumvpn_gemini.py"), (True, "network_guard_setup.sh")):
                    with self.subTest(flag=flag, name=name):
                        bad = {**config, "with_network_ai": flag,
                               "files": {**config["files"], name: {"old_sha256": None}}}
                        with self.assertRaisesRegex(scope["CheckFailed"], "source_allowlist"):
                            scope["preflight"](bad)

    def test_network_ai_rollback_restores_only_exact_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backup = root / "source-backup"
            backup.mkdir()
            scope = self.remote_scope(root)
            existing, introduced = (root / name for name in ("quantumvpn_gemini.py", "quantumvpn_target_scan.py"))
            old = b"# previously deployed gemini module\n"
            (backup / existing.name).write_bytes(old)
            for path in (existing, introduced):
                path.write_text("# newly installed\n")
            installed = {path.name: {"sha256": scope["digest"](path)} for path in (existing, introduced)}
            scope["CONFIG"] = {"files": installed, "upload": "fixture-network-ai"}
            states = {existing.name: {"exists": True, "sha256": hashlib.sha256(old).hexdigest(),
                                     "uid": 0, "gid": 0, "mode": 0o640}, introduced.name: {"exists": False}}
            database = root / "operator.db"
            database.write_bytes(b"wallet changes after deployment")
            introduced.write_text("# concurrently changed\n")
            with self.assertRaisesRegex(scope["CheckFailed"], "rollback_source_changed"):
                scope["restore"](states, backup, [existing.name, introduced.name])
            self.assertEqual("# newly installed\n", existing.read_text())
            self.assertTrue(introduced.exists())
            introduced.write_text("# newly installed\n")
            with mock.patch.object(scope["os"], "chown", create=True):
                scope["restore"](states, backup, [existing.name, introduced.name])
            self.assertEqual(old, existing.read_bytes())
            self.assertFalse(introduced.exists())
            self.assertEqual(b"wallet changes after deployment", database.read_bytes())

    def test_remote_compiles_and_preserves_original_baseline_guards(self):
        compile(self.deployer.REMOTE_SOURCE, "remote-deployment", "exec")
        source = self.deployer.REMOTE_SOURCE
        for guard in ("source_allowlist", "source_hash_", "companion_hash_", "baseline_changed_before_replace",
                      "public_api_changed", "configuration_changed", "signing_changed", "runtime_configuration_changed",
                      "rollback_source_changed", "database_restoration", "'never'", "mode=ro", "community_webauthn_version"):
            self.assertIn(guard, source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("shell=True", source)
        self.assertIn("['systemctl', 'restart', SERVICE]", source)

    def test_update_snapshot_only_normalizes_absent_false_pause(self):
        namespace = {"__name__": "offline_deployment_fixture"}
        exec(self.deployer.REMOTE_SOURCE, namespace)
        # Isolate the actual snapshot function from HTTP/crypto/filesystem.
        def snapshot(pause="absent", changed=False):
            def fixture_request(env, path, timeout=8):
                if path.startswith('/api/client/update'):
                    value = {"version": "fixture", "sha256": "a" * 64}
                    if pause != "absent": value["rollout_paused"] = pause
                    if changed: value["sha256"] = "b" * 64
                    return 200, {}, __import__('json').dumps(value).encode()
                if path.startswith('/api/client/resources'): return 204, {}, b''
                return 200, {}, b'{}'
            namespace['request'] = fixture_request
            namespace['envelope'] = lambda value, public: value
            return namespace['public_snapshot']({}, 'fixture')
        baseline = snapshot()
        self.assertEqual(baseline, snapshot(False))
        self.assertNotEqual(baseline, snapshot(True))
        self.assertNotEqual(baseline, snapshot(0))
        self.assertNotEqual(baseline, snapshot(False, changed=True))

    def test_isolated_chain_selected_before_external_imports(self):
        # Global cryptography 41 is cached if imported before the isolated 50.x
        # package. WebAuthn then cannot find asymmetric.mldsa even with deps on
        # sys.path. Keep every external import after path selection; retain the
        # global cryptography/Pillow gate when --with-community is absent.
        tree = ast.parse(self.deployer.REMOTE_SOURCE)
        preflight = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "preflight")
        insertion = next(node for node in ast.walk(preflight) if isinstance(node, ast.Call)
                         and ast.unparse(node.func) == "sys.path.insert")
        external_imports = [node for node in ast.walk(preflight) if isinstance(node, ast.Call)
                            and ast.unparse(node.func) == "importlib.import_module"]
        self.assertTrue(external_imports)
        self.assertTrue(all(node.lineno > insertion.lineno for node in external_imports))
        global_gate = next(node for node in preflight.body if isinstance(node, ast.For)
                           and isinstance(node.iter, ast.Tuple))
        self.assertEqual(("cryptography", "PIL"), ast.literal_eval(global_gate.iter))
        community_gate = next(node for node in preflight.body if isinstance(node, ast.If)
                              and ast.unparse(node.test) == "config.get('with_community')")
        self.assertIn(insertion, list(ast.walk(community_gate)))

    def test_dependency_remote_compiles_and_only_uses_official_wheels(self):
        installer = module("install-control-next-deps.py")
        compile(installer.REMOTE, "remote-dependency-install", "exec")
        for item in ("webauthn==3.0.1", "https://pypi.org/simple", "https://pypi.org/pypi/", "files.pythonhosted.org",
                     "9927b2f530773bd1d7f8194cd643a2e634a20995ea31f2d8f7a3e70b11c93e31",
                     "--only-binary=:all:", "--target", "--no-index", "--no-deps", "dependency_changed_before_swap",
                     "dependency_baseline_changed", "rollback_target_changed", "cleanup_path"):
            self.assertIn(item, installer.REMOTE)
        self.assertNotIn("systemctl", installer.REMOTE)
        self.assertNotIn("sqlite", installer.REMOTE)
        self.assertNotIn("shell=True", installer.REMOTE)
        self.assertIn("paramiko.RejectPolicy()", (TOOLS / "install-control-next-deps.py").read_text())
        self.assertIn("pip_available", installer.REMOTE)
        self.assertIn("PIP_VERSION = '26.2.1'", installer.REMOTE)
        self.assertIn("71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e", installer.REMOTE)
        self.assertIn("pip_wheel_path", installer.REMOTE)
        self.assertNotIn("'-m', 'pip'", installer.REMOTE)

    def test_dependency_inspection_is_before_any_mutation_or_network(self):
        installer = module("install-control-next-deps.py")
        tree = ast.parse(installer.REMOTE)
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run")
        early = next(index for index, node in enumerate(run.body) if isinstance(node, ast.If) and any(isinstance(child, ast.Return) for child in ast.walk(node)))
        before_return = ast.unparse(ast.Module(body=run.body[:early + 1], type_ignores=[]))
        for forbidden in (".mkdir(", "command(", "official_metadata(", "os.replace(", "shutil.rmtree("):
            self.assertNotIn(forbidden, before_return)

    def bootstrap_scope(self, wheel_bytes):
        installer = module("install-control-next-deps.py")
        parsed = ast.parse(installer.REMOTE)
        functions = [node for node in parsed.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in {"CheckFailed", "require", "bootstrap_pip"}]
        scope = {"Path": Path, "hashlib": hashlib, "urllib": types.SimpleNamespace(parse=urllib.parse, request=urllib.request),
                 "zipfile": zipfile, "stat": __import__("stat"), "sys": sys, "PIP_VERSION": "26.2.1", "PIP_SHA256": hashlib.sha256(wheel_bytes).hexdigest()}
        filename = "pip-26.2.1-py3-none-any.whl"
        metadata = {"urls": [{"filename": filename, "packagetype": "bdist_wheel", "url": "https://files.pythonhosted.org/test/" + filename, "digests": {"sha256": scope["PIP_SHA256"]}}]}
        scope["official_metadata"] = lambda *_: metadata
        scope["verify_wheel"] = lambda _: {"name": "pip", "version": "26.2.1"}
        exec(compile(ast.Module(body=functions, type_ignores=[]), "bootstrap-offline", "exec"), scope)
        response = io.BytesIO(wheel_bytes)
        response.url = "https://files.pythonhosted.org/test/" + filename
        return scope, response

    def test_temporary_pip_bootstrap_has_no_global_install(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("pip/__main__.py", "# synthetic test fixture")
        scope, response = self.bootstrap_scope(stream.getvalue())
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(urllib.request, "urlopen", return_value=response):
            command = scope["bootstrap_pip"](Path(temp))
            self.assertTrue((Path(temp) / "pip-bootstrap/pip/__main__.py").is_file())
            self.assertEqual(sys.executable, command[0])
            self.assertIn("runpy.run_module", command[2])
            self.assertEqual(str(Path(temp) / "pip-bootstrap"), command[3])

    def test_temporary_pip_zip_escape_is_rejected(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("../escape.py", "# synthetic test fixture")
        scope, response = self.bootstrap_scope(stream.getvalue())
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(urllib.request, "urlopen", return_value=response):
            with self.assertRaises(scope["CheckFailed"]) as caught:
                scope["bootstrap_pip"](Path(temp))
            self.assertEqual("pip_wheel_path", str(caught.exception))

    def test_pip_checksum_failure_precedes_module_execution(self):
        scope, response = self.bootstrap_scope(b"not a wheel")
        response = io.BytesIO(b"changed in transit")
        response.url = "https://files.pythonhosted.org/test/pip.whl"
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(urllib.request, "urlopen", return_value=response):
            with self.assertRaises(scope["CheckFailed"]) as caught:
                scope["bootstrap_pip"](Path(temp))
            self.assertEqual("pip_download_checksum", str(caught.exception))
            self.assertEqual([], list(Path(temp).iterdir()))


if __name__ == "__main__":
    unittest.main()
