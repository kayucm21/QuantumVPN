"""Offline guards for source-only deployment and isolated dependency install."""
import ast
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
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

    def test_default_never_adds_community_files(self):
        config, payloads = self.deployer.build_config(self.args())
        self.assertFalse(config["apply"])
        self.assertFalse(config["with_community"])
        self.assertNotIn("quantumvpn_community.py", payloads)
        self.assertEqual(set(self.deployer.COMPANIONS), set(config["companions"]))

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
