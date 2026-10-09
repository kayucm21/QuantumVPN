"""Offline scope and parsing checks; no VDS, proxy key or network calls."""
import ast
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest import mock


class DomainLinkProbeTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name('verify-panel-domain-links.py')
        fake = types.ModuleType('paramiko')
        with mock.patch.dict(sys.modules, {'paramiko': fake}):
            spec = importlib.util.spec_from_file_location('domain_probe', path)
            self.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.module)

    def test_probe_compiles_and_can_only_reveal_links_or_measure_web(self):
        source = self.module.PROBE_SOURCE
        ast.parse(source)
        self.assertIn("('mtproto','links',3443)", source)
        self.assertIn("('tls','tls_links',5443)", source)
        self.assertIn("('web','web_links',443)", source)
        self.assertIn("'web_probe'", source)
        for denied in ('systemctl', '.control(', 'restart', 'confirm', '--insecure', 'print(raw', 'print(value', 'print(secret', 'print(cookie'):
            self.assertNotIn(denied, source)
        self.assertIn("'Origin':PUBLIC", source)
        self.assertIn("'Sec-Fetch-Site':'same-origin'", source)

    def test_textarea_parser_decodes_entities_and_preserves_pair_fields(self):
        source = self.module.PROBE_SOURCE.split('\ndef post(', 1)[0]
        from html.parser import HTMLParser
        namespace = {'HTMLParser':HTMLParser}
        exec(source, namespace)
        parser = namespace['LinkFields']()
        parser.feed('<input name="csrf" value="token"><textarea id="proxy-mtproto-telegram-link">tg://proxy?server=pecaocek.ignorelist.com&amp;port=3443&amp;secret=opaque</textarea>')
        self.assertEqual(parser.csrf, ['token'])
        self.assertEqual(parser.fields['proxy-mtproto-telegram-link'], 'tg://proxy?server=pecaocek.ignorelist.com&port=3443&secret=opaque')


if __name__ == '__main__':
    unittest.main()
