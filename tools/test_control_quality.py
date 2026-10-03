import base64
import io
import json
import os
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tools.quantumvpn_control_quality import dependency_evidence, explain_route, subscription_evidence, validate_backup


class QualityTests(unittest.TestCase):
    def policy(self, **rules):
        return {"enabled": True, "revision": 9, "profile": "proxy_all", "rules": rules,
                "adblock": {"enabled": True}, "dns": {"resolver": "https://dns.adguard-dns.com/dns-query"}}

    def test_subscription_report_never_contains_keys_names_or_links(self):
        raw = b"vless://private-password@hidden.example:443#Personal-name\nhysteria2://secret@private.example:444\namneziawg://never-show-this"
        report = subscription_evidence(base64.b64encode(raw))
        self.assertEqual(report["protocols"], {"vless": 1, "hysteria2": 1, "amneziawg": 1})
        self.assertEqual(report["unsupported_schemes"], ["amneziawg"])
        rendered = json.dumps(report)
        for secret in ("private-password", "hidden.example", "Personal-name", "private.example", "never-show-this"):
            self.assertNotIn(secret, rendered)

    def test_native_awg_configuration_recognized(self):
        report = subscription_evidence(b"[Interface]\nPrivateKey=not-public\nJc=8\n[Peer]\nPublicKey=public\nEndpoint=hidden:59333")
        self.assertEqual(report["protocols"], {"amneziawg": 1})
        self.assertTrue(report["has_awg"])
        self.assertEqual(report["unsupported_schemes"], [])

    def test_json_subscription_only_exposes_types(self):
        raw = json.dumps({"outbounds": [{"type": "direct"}, {"type": "selector"},
              {"type": "vless", "uuid": "private-uuid", "server": "secret.example"}],
              "endpoints": [{"type": "wireguard", "amnezia": {"jc": 8}, "private_key": "not-public"}]}).encode()
        report = subscription_evidence(raw)
        self.assertEqual(report["protocols"], {"vless": 1, "amneziawg": 1})
        self.assertNotIn("private-uuid", json.dumps(report))

    def test_json_array_is_not_claimed_apk_compatible(self):
        report = subscription_evidence(b'[{"protocol":"vless"}]')
        self.assertIn("требуется конвертация", report["encoding"])
        self.assertEqual(report["protocols"], {})

    def test_overlarge_subscription_rejected(self):
        with self.assertRaises(ValueError):
            subscription_evidence(b"x" * (4 * 1024 * 1024 + 1))

    def test_block_precedes_explicit_direct_and_proxy(self):
        result = explain_route(self.policy(block_domains=["example.com"], direct_domains=["example.com"], proxy_domains=["example.com"]), "https://sub.example.com/path")
        self.assertEqual(result["direction"], "Блокировка")
        self.assertEqual(result["matched"], "example.com")

    def test_ads_block_is_flag_dependent(self):
        policy = self.policy()
        self.assertEqual(explain_route(policy, "ads.doubleclick.net")["direction"], "Блокировка")
        policy["adblock"]["enabled"] = False
        self.assertEqual(explain_route(policy, "ads.doubleclick.net")["direction"], "Через выбранный VPN")

    def test_direct_and_lan_precede_proxy(self):
        self.assertEqual(explain_route(self.policy(direct_domains=["example.com"], proxy_domains=["example.com"]), "example.com")["direction"], "Напрямую")
        self.assertEqual(explain_route(self.policy(proxy_cidrs=["192.168.0.0/16"]), "192.168.1.2")["direction"], "Напрямую")
        self.assertEqual(explain_route(self.policy(proxy_cidrs=["100.64.0.0/10"]), "100.64.1.2")["direction"], "Напрямую")
        self.assertEqual(explain_route(self.policy(direct_cidrs=["8.8.8.0/24"]), "8.8.8.8")["direction"], "Напрямую")

    def test_balanced_does_not_guess_ru_membership(self):
        policy = self.policy(proxy_domains=["example.com"])
        policy["profile"] = "balanced"
        self.assertEqual(explain_route(policy, "example.com")["direction"], "Зависит от RU-списка APK")
        policy["enabled"] = False
        self.assertEqual(explain_route(policy, "example.com")["direction"], "Профиль устройства")

    def test_invalid_target_rejected_without_network_io(self):
        for value in ("", "https://user:password@example.com", "ftp://example.com", "bad/host", "a..com", "a.-com", "<script>", "bad host"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                explain_route(self.policy(), value)
        self.assertEqual(explain_route(self.policy(), "[::1]")["direction"], "Напрямую")

    def test_dependency_map_uses_database_records_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / "rospanel.db")
            db = sqlite3.connect(path)
            db.executescript("""
                create table settings(host,master_label,awg_enabled,awg_port);
                insert into settings values ('actual.example','Main',1,59333);
                create table users(id,enabled); insert into users values(1,1),(2,0);
                create table nodes(id,name,host,enabled,last_seen,awg_enabled,deleted_at);
                insert into nodes values(10,'Node','other.example',0,0,1,0);
                insert into nodes values(11,'Deleted','deleted.example',1,0,0,100);
                create table inbounds(id,server_id,name,protocol,port,enabled,sort);
                insert into inbounds values(1,0,'VPN','vless',443,1,1);
            """)
            db.commit(); db.close()
            result = dependency_evidence(path)
            self.assertTrue(result["available"])
            self.assertEqual(result["users"], 1)
            self.assertEqual([r["id"] for r in result["nodes"]], [0, 10])
            self.assertEqual(len(result["protocols"]), 3)
            self.assertNotIn("deleted.example", json.dumps(result))

    def backup_fixture(self, invalid_schema=False, extras=None):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "operator.db"
            db = sqlite3.connect(path)
            db.executescript("create table settings(key,value);" + ("" if invalid_schema else "create table events(ts);create table device_flags(device);"))
            db.commit(); db.close()
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr("operator.db", path.read_bytes())
                archive.writestr("backup-info.json", '{"panel_build":"test"}')
                for name, value in (extras or {}).items():
                    archive.writestr(name, value)
            key, nonce = os.urandom(32), os.urandom(12)
            return b"QVBK1" + nonce + AESGCM(key).encrypt(nonce, stream.getvalue(), b"QuantumControl backup v1"), key

    def test_restore_validation_checks_db_and_reports_missing_files(self):
        archive, key = self.backup_fixture(extras={"session.secret": b"s" * 32})
        result = validate_backup(archive, key, AESGCM)
        self.assertTrue(result["ok"])
        self.assertEqual(result["databases"], ["operator.db"])
        self.assertNotIn("session.secret", result["missing"])
        self.assertIn("rospanel.db", result["missing"])
        self.assertNotIn("s" * 32, json.dumps(result))

    def test_bad_tag_and_wrong_key_fail_closed(self):
        archive, key = self.backup_fixture()
        with self.assertRaises(Exception):
            validate_backup(archive[:-1] + bytes([archive[-1] ^ 1]), key, AESGCM)
        with self.assertRaises(Exception):
            validate_backup(archive, os.urandom(32), AESGCM)

    def test_missing_schema_rejected(self):
        archive, key = self.backup_fixture(invalid_schema=True)
        with self.assertRaises(ValueError):
            validate_backup(archive, key, AESGCM)

    def test_path_traversal_member_is_not_extracted(self):
        archive, key = self.backup_fixture(extras={"../../outside": "never extracted"})
        result = validate_backup(archive, key, AESGCM)
        self.assertTrue(result["ok"])
        self.assertNotIn("outside", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
