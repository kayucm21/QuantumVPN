"""Offline legacy iOS envelope guards: no network or production changes."""
import unittest
from unittest.mock import patch

import quantumvpn_mtproto_ios_compat as compat
import quantumvpn_mtproto_tls_protocol as protocol


class IosCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.wire = protocol.build_client_hello('ab' * 16, client_profile=protocol.IOS_LEGACY_BROKEN_SNI)

    def test_accepts_only_legacy_single_configured_hostname(self):
        self.assertTrue(compat.matches_legacy_envelope(self.wire, protocol.DOMAIN))
        for count in (0, 2, 99):
            self.assertFalse(compat.matches_legacy_envelope(self.wire, protocol.DOMAIN, configured_domains=count))
        self.assertFalse(compat.matches_legacy_envelope(self.wire, 'other.example'))

    def test_standard_and_modern_sni_are_not_compat_fallbacks(self):
        for profile in ('standard', protocol.IOS_MODERN_SAFARI):
            wire = protocol.build_client_hello('ab' * 16, client_profile=profile)
            self.assertFalse(compat.matches_legacy_envelope(wire, protocol.DOMAIN))

    def test_bad_lengths_types_padding_and_truncations_fail_closed(self):
        for size in range(len(self.wire)):
            self.assertFalse(compat.matches_legacy_envelope(self.wire[:size], protocol.DOMAIN))
        for index in (0, 3, 6, 43, 76, 77, 120, 122, 125, 126, 127, 128, 129, 130, 131, 132, 516):
            with self.subTest(index=index):
                wire = bytearray(self.wire); wire[index] ^= 128
                self.assertFalse(compat.matches_legacy_envelope(bytes(wire), protocol.DOMAIN))
        self.assertFalse(compat.matches_legacy_envelope(self.wire + b'\0', protocol.DOMAIN))

    def test_envelope_does_not_claim_authentication(self):
        wire = bytearray(self.wire); wire[11] ^= 1
        self.assertTrue(compat.matches_legacy_envelope(bytes(wire), protocol.DOMAIN))
        # Its existing native HMAC gate, unchanged by patch_source, must deny it.
        self.assertIn('original HMAC/time/replay checks', compat.HELPER)

    def test_unknown_or_modified_source_is_never_patched(self):
        with self.assertRaisesRegex(RuntimeError, 'pinned_net_source_identity_required'):
            compat.patch_source(b'untrusted source')


if __name__ == '__main__':
    unittest.main()
