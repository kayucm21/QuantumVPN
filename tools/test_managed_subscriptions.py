"""Upstream admission format regressions; no live URL, account or reserve key."""
import base64
import importlib.util
import io
import os
from pathlib import Path
import unittest
from unittest import mock


with mock.patch.dict(os.environ, {"QV_ADMIN_USER": "fixture", "QV_ADMIN_PASSWORD": "fixture",
                                 "QV_SUBSCRIPTION_UPSTREAM": "https://example.invalid/sub"}):
    spec = importlib.util.spec_from_file_location("subscription_admission_test_panel", Path(__file__).with_name("quantumvpn_operator_panel.py"))
    PANEL = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(PANEL)


class SubscriptionAdmissionTests(unittest.TestCase):
    def test_error_pages_never_become_reserve_only_or_admitted(self):
        for body in (b'<html><a href="https://example.invalid/login">Sign in</a></html>',
                     b'<html>vless://private@example.invalid:443</html>',
                     b'https://example.invalid/login', b'Access denied'):
            with self.subTest(body=body), mock.patch.object(PANEL, "urlopen", return_value=io.BytesIO(body)), mock.patch.object(PANEL, "reserve_profile_uri") as reserve:
                served, appended = PANEL.managed_subscription({}, {"reserve_profile_enabled": "1"})
                self.assertEqual(served, body)
                self.assertFalse(appended)
                self.assertIsNone(PANEL.admitted_subscription_text(served))
                reserve.assert_not_called()

    def test_plain_and_base64_uri_lists_append_reserve_once(self):
        body = b'vless://fixture@example.invalid:443#Fixture\nhysteria2://fixture@example.invalid:444\n'
        for wire in (body, base64.b64encode(body)):
            with self.subTest(encoded=wire != body), mock.patch.object(PANEL, "urlopen", return_value=io.BytesIO(wire)), mock.patch.object(PANEL, "reserve_profile_uri", return_value='trojan://fixture@reserve.example.invalid:443'):
                served, appended = PANEL.managed_subscription({}, {"reserve_profile_enabled": "1"})
                self.assertTrue(appended)
                self.assertEqual(len(PANEL.admitted_subscription_text(served).splitlines()), 3)

    def test_native_formats_remain_unmodified(self):
        for body in (b'{"outbounds":[{"type":"vless","server":"example.invalid"}]}',
                     b'[Interface]\nPrivateKey=fixture\n[Peer]\nPublicKey=fixture\nEndpoint=example.invalid:444\n'):
            with self.subTest(body=body), mock.patch.object(PANEL, "urlopen", return_value=io.BytesIO(body)), mock.patch.object(PANEL, "reserve_profile_uri") as reserve:
                self.assertIsNotNone(PANEL.admitted_subscription_text(body))
                self.assertEqual(PANEL.managed_subscription({}, {}), (body, False))
                reserve.assert_not_called()

    def test_malformed_native_or_mixed_body_is_not_admitted(self):
        for body in (b'{"outbounds":null}', b'{"outbounds":"vless://fixture"}',
                     b'{"error":"https://login.invalid"}', b'vless://fixture@host:443\nhttps://login.invalid'):
            self.assertIsNone(PANEL.admitted_subscription_text(body))


if __name__ == '__main__':
    unittest.main()
