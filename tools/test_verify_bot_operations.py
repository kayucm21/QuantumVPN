import ast
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock


class BotVerificationTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('bot_verify', Path(__file__).with_name('verify-bot-operations-vds.py'))
        self.module = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {'paramiko': types.ModuleType('paramiko')}):
            spec.loader.exec_module(self.module)

    def valid(self):
        return {'ok': True,'build':'2.3.0-pulse.6','apk_unchanged':True,
                'proxy_scope':'server_to_telegram_not_client','client_without_vpn_tested':False,
                'blocker_cause_proven':False,'knowledge_installed':True}

    def test_only_fixed_safe_fields_printed(self):
        value = self.valid()
        self.assertEqual(self.module.safe_result(value), value)
        value['secret'] = 'DO_NOT_PRINT'
        with self.assertRaises(ValueError):self.module.safe_result(value)
        self.assertNotIn('DO_NOT_PRINT', json.dumps(self.module.safe_result({'ok':False,'error':'DO_NOT_PRINT'})))

    def test_strict_boolean_counts_and_nested_fields(self):
        for change in ({'ok':1}, {'build':'SECRET'}, {'client_without_vpn_tested':True},
                       {'proxies':{}}, {'analysis':{'ready':True,'local':True,'error_reason':'SECRET'}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.module.safe_result({**self.valid(), **change})

    def test_remote_compiles_and_action_scope_is_fixed(self):
        compile(self.module.REMOTE, '<remote>', 'exec')
        tree = ast.parse(self.module.REMOTE)
        actions = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name=='owner_action')
        source = ast.unparse(actions)
        self.assertIn("{'backup_now', 'run_ai_analysis'}", source)
        self.assertIn("'/operator/actions'", source)
        self.assertNotIn('restart', source)


if __name__ == '__main__':unittest.main()
