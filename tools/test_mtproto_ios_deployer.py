"""Offline deployment contract; does not connect or change production."""
import ast
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('ios_deployer', Path(__file__).with_name('patch-mtproto-ios-vds.py'))
deployer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployer)


class DeploymentContractTests(unittest.TestCase):
    def test_read_only_default_and_valid_remote_program(self):
        source = deployer.program()
        ast.parse(source)
        self.assertTrue(source.startswith('RUN_REMOTE=False\nAPPLY=False\n'))
        self.assertNotIn('QVPN_VDS_PASSWORD', source)

    def test_apply_requires_explicit_option(self):
        self.assertTrue(deployer.program(True).startswith('RUN_REMOTE=False\nAPPLY=True\n'))

    def test_only_tls_unit_can_be_restarted(self):
        tree = ast.parse(deployer.REMOTE)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and
                 isinstance(node.func, ast.Name) and node.func.id == 'run']
        controls=[]
        for node in calls:
            arg=node.args[0]
            if isinstance(arg, ast.List) and arg.elts and isinstance(arg.elts[0],ast.Constant) and arg.elts[0].value=='systemctl':
                controls.append(ast.unparse(arg))
        self.assertEqual(controls, ["['systemctl', 'restart', SERVICE]", "['systemctl', 'restart', SERVICE]"])
        self.assertNotIn('daemon-reload',deployer.REMOTE)

    def test_durable_backup_and_guarded_rollback_exist(self):
        for token in ('old_binary', 'new_binary', 'old_config', 'new_config', 'pending_transactions',
                      'rollback_foreign_target_manual_review', "record['phase']='verified'",
                      'protected_identity()', 'source_fsck', 'compat.TREE'):
            self.assertIn(token,deployer.REMOTE)
        self.assertIn('atomic_replace(ROOT',deployer.REMOTE)

    def test_authentication_negative_proofs_are_mandatory(self):
        for token in ('wrong_hmac_rejected','old_timestamp_rejected','unknown_sni_rejected',
                      'malformed_envelope_rejected','fresh_hello_accepted','replayed_hello_rejected',
                      'post_patch_authentication_regression'):
            self.assertIn(token,deployer.REMOTE)


if __name__=='__main__':unittest.main()
