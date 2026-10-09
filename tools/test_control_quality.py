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
from tools.quantumvpn_control_quality import (
    CLIENT_QUALITY_LIMIT, client_quality_summary, dependency_evidence, explain_route,
    quality_snapshot, render_client_quality, render_quality, subscription_evidence, validate_backup,
)


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


class ClientQualityTests(unittest.TestCase):
    NOW = 200000

    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("""create table community_quality(
            id integer primary key, device text, ts integer, node_key text, protocol text,
            network text, app_version text, ping_ms, success integer)""")
        self.addCleanup(self.db.close)

    def report(self, device, ping=30, *, ts=None, node="main", protocol="vless", network="wifi", success=1, version="5.11.3"):
        self.db.execute("insert into community_quality(device,ts,node_key,protocol,network,app_version,ping_ms,success) values(?,?,?,?,?,?,?,?)",
                        (device, self.NOW if ts is None else ts, node, protocol, network, version, ping, success))

    def cohort(self, **values):
        for index, ping in enumerate((10, 20, 30, 40, 50)):
            self.report(f"private-device-{index}", ping, **values)

    def summary(self):
        return client_quality_summary(self.db, self.NOW)

    def test_empty_and_missing_schema_are_honest(self):
        result = self.summary()
        self.assertTrue(result["available"])
        self.assertEqual(result["groups"], [])
        self.assertIn("замеры не поступили", render_client_quality(result))
        self.db.execute("drop table community_quality")
        missing = self.summary()
        self.assertFalse(missing["available"])
        self.assertIn("пока недоступны", render_client_quality(missing))

    def test_minimum_five_devices_never_leaks_raw_reports(self):
        for index in range(4):
            self.report(f"private-device-{index}")
        hidden = self.summary()
        self.assertEqual(hidden["suppressed_groups"], 1)
        self.assertEqual(hidden["groups"], [])
        self.assertIn("минимум 5", render_client_quality(hidden))
        self.report("private-device-4")
        result = self.summary()
        self.assertEqual(result["groups"][0]["devices"], 5)
        rendered = json.dumps(result) + render_client_quality(result)
        self.assertNotIn("private-device", rendered)
        self.assertNotIn('"reports":', rendered)
        self.assertFalse(result["recommendations_available"])

    def test_successful_positive_pings_only_and_nearest_rank(self):
        self.cohort()
        self.report("private-failed", 1, success=0)
        self.report("private-zero", 0)
        self.report("private-unknown", None)
        self.report("private-invalid", "not-a-measurement")
        self.report("private-overlarge", 60001)
        result = self.summary()
        group = result["groups"][0]
        self.assertEqual((group["ping_p50_ms"], group["ping_p95_ms"]), (30, 50))
        self.assertEqual(group["ping_devices"], 5)
        self.assertEqual(group["success_percent"], 90)
        self.assertEqual(result["missing_ping_samples"], 5)

    def test_valid_ping_cohort_itself_must_have_five_devices(self):
        for index in range(5):
            self.report(f"private-device-{index}", 20 if index < 4 else 0)
        group = self.summary()["groups"][0]
        self.assertEqual(group["ping_devices"], 4)
        self.assertIsNone(group["ping_p50_ms"])
        self.assertIsNone(group["ping_p95_ms"])

    def test_latest_per_device_group_not_heavy_reporters(self):
        self.cohort(ts=self.NOW - 10)
        for _ in range(30):
            self.report("private-device-0", 500)
        self.report("private-device-0", 0, success=0)  # same timestamp; latest ID wins
        result = self.summary()
        self.assertEqual(result["reports_considered"], 36)
        self.assertEqual(result["devices"], 5)
        self.assertEqual(result["device_group_samples"], 5)
        self.assertEqual(result["groups"][0]["success_percent"], 80)
        self.assertEqual(result["groups"][0]["ping_devices"], 4)
        self.assertIsNone(result["groups"][0]["ping_p95_ms"])

    def test_groups_are_node_protocol_network_not_version(self):
        self.cohort()
        self.cohort(node="reserve")
        self.cohort(protocol="trojan")
        self.cohort(network="mobile")
        self.report("private-device-0", 60, version="5.11.4")
        result = self.summary()
        self.assertEqual(result["devices"], 5)
        self.assertEqual(result["device_group_samples"], 20)
        self.assertEqual(len(result["groups"]), 4)
        self.assertTrue(all(group["devices"] == 5 for group in result["groups"]))
        self.assertNotIn("version", json.dumps(result))

    def test_stale_and_future_reports_are_excluded_exactly(self):
        self.cohort(ts=self.NOW - 86400)
        self.cohort(ts=self.NOW - 86401, node="stale")
        self.cohort(ts=self.NOW + 1, node="future")
        result = self.summary()
        self.assertEqual(result["reports_considered"], 5)
        self.assertEqual([group["node"] for group in result["groups"]], ["main"])
        self.assertEqual(result["window_end"], self.NOW)

    def test_last_two_thousand_cap_is_explicit(self):
        for index in range(CLIENT_QUALITY_LIMIT + 1):
            self.report(f"private-{index}", 50, ts=self.NOW - index)
        result = self.summary()
        self.assertEqual(result["reports_considered"], CLIENT_QUALITY_LIMIT)
        self.assertEqual(result["devices"], CLIENT_QUALITY_LIMIT)
        self.assertTrue(result["limit_reached"])
        self.assertIn("может не охватывать все 24 часа", render_client_quality(result))

    def test_invalid_stored_group_values_never_appear_in_output(self):
        self.cohort(node="<script>ip 1.2.3.4</script>", protocol="<img>", network="private-ip")
        result = self.summary()
        self.assertEqual(result["groups"][0]["node"], "")
        rendered = json.dumps(result) + render_client_quality(result)
        for forbidden in ("<script>", "<img>", "1.2.3.4", "private-ip"):
            self.assertNotIn(forbidden, rendered)
        self.assertIn("Не сообщена", rendered)

    def test_summary_query_is_read_only_and_render_distinguishes_vds(self):
        self.cohort()
        statements = []
        self.db.set_trace_callback(statements.append)
        result = self.summary()
        self.db.set_trace_callback(None)
        self.assertTrue(all(statement.lstrip().lower().startswith("select ") for statement in statements))
        rendered = render_client_quality(result)
        for phrase in ("Качество клиентов", "не ping с VDS", "не доказывает ТСПУ", "P50", "P95"):
            self.assertIn(phrase, rendered)
        self.assertNotIn("<form", rendered)

    def test_quality_page_uses_summary_without_changing_existing_controls(self):
        self.cohort()
        self.db.executescript("""
            create table server_health(target,ok,latency_ms,ts);
            create table delivery_evidence(device,version_code,policy_at,update_at,download_at,install_at,notification_permission);
            create table ai_observations(id,ts,trigger,status,advice,telegram_sent,before_json);
        """)
        snapshot = quality_snapshot(self.db, {}, "missing-rospanel.db")
        self.assertIn("client_quality", snapshot)
        # Fixture times are intentionally old relative to the real wall clock.
        snapshot["client_quality"] = self.summary()
        rendered = render_quality(snapshot, {})
        self.assertIn("Качество клиентов", rendered)
        self.assertIn("value=verify_backup", rendered)
        self.assertIn("value=inspect_subscription", rendered)
        self.assertNotIn("private-device", rendered)
        del snapshot["client_quality"]
        self.assertIn("пока недоступны", render_quality(snapshot, {}))


if __name__ == "__main__":
    unittest.main()
