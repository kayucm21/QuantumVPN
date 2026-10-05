import base64
import hashlib
import json
import sqlite3
import unittest

from tools import quantumvpn_control_next as controls
from tools import quantumvpn_community as community


NOW = 100000
ORIGIN = "https://panel.example.com:8443"
BINDING = "unpredictable-browser-session-nonce-1234567890"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript("create table settings(key text primary key,value text); create table admin_users(username text primary key,role text,enabled integer);")
        self.s = {"config_revision": "12", "routing_revision": "8", "app_version": "5.11.3", "app_version_code": "501103000",
                  "routing_profile": "balanced", "routing_enabled": "1", "routing_dns_mode": "vpn_only", "routing_dns_resolver": "https://dns.example.com/dns-query",
                  "routing_adblock_enabled": "1", "routing_direct_domains": "", "routing_proxy_domains": "youtube.com", "routing_block_domains": "",
                  "routing_direct_cidrs": "", "routing_proxy_cidrs": "", "rollout_percent": "100", "update_rollout_paused": "0"}
        self.db.executemany("insert into settings values (?,?)", self.s.items())
        self.db.execute("insert into admin_users values ('admin','owner',1)")
        controls.migrate(self.db)
        community.migrate(self.db)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def current(self):
        return dict(self.db.execute("select key,value from settings"))

    def apply(self, db, values, scope):
        for key, value in values.items():
            db.execute("insert into settings values (?,?) on conflict(key) do update set value=excluded.value", (key, value))
        db.execute("update settings set value=cast(value as integer)+1 where key='config_revision'")

    def test_migration_does_not_change_production_settings(self):
        before = self.current()
        controls.migrate(self.db)
        self.assertEqual(before, self.current())

    def test_migration_does_not_commit_callers_transaction(self):
        self.db.execute("update settings set value='14' where key='config_revision'")
        controls.migrate(self.db)
        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        self.assertEqual(self.current()["config_revision"], "12")

    def test_rollback_new_opt_in_flag_restores_disabled_default(self):
        preview = controls.preview_settings(self.db, self.current(), {"release_guard_enabled": "1"}, "admin", "release", "owner", NOW)
        result = controls.apply_preview(self.db, preview["preview_id"], preview["digest"], self.current(), "admin", "owner", self.apply, NOW)
        rollback = controls.rollback_preview(self.db, result["snapshot_id"], self.current(), "admin", "owner", NOW)
        self.assertEqual(rollback["diff"][0]["after"], "0")

    def test_preview_apply_snapshot_and_guarded_rollback(self):
        preview = controls.preview_settings(self.db, self.current(), {"routing_profile": "proxy_all"}, "admin", "routing", now=NOW)
        self.assertEqual(self.current()["routing_profile"], "balanced")
        result = controls.apply_preview(self.db, preview["preview_id"], preview["digest"], self.current(), "admin", "owner", self.apply, now=NOW + 1)
        self.assertEqual(self.current()["routing_profile"], "proxy_all")
        self.assertEqual(self.current()["config_revision"], "13")
        rollback = controls.rollback_preview(self.db, result["snapshot_id"], self.current(), "admin", "owner", now=NOW + 2)
        self.assertEqual(rollback["diff"], [{"key": "routing_profile", "before": "proxy_all", "after": "balanced"}])
        controls.apply_preview(self.db, rollback["preview_id"], rollback["digest"], self.current(), "admin", "owner", self.apply, now=NOW + 3)
        self.assertEqual(self.current()["routing_profile"], "balanced")

    def test_previews_reject_scope_secret_version_shell_and_viewer(self):
        for key in ("totp_secret", "telegram_bot_token", "app_version", "scheduled_release_publish_at", "xray_config", "command"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                controls.preview_settings(self.db, self.current(), {key: "private"}, "admin", "routing", now=NOW)
        with self.assertRaises(PermissionError):
            controls.preview_settings(self.db, self.current(), {"routing_enabled": "0"}, "viewer", "routing", "viewer", NOW)
        with self.assertRaises(PermissionError):
            controls.preview_settings(self.db, self.current(), {"rollout_percent": "50"}, "operator", "release", "operator", NOW)

    def test_bad_candidate_values_fail_closed(self):
        for values in ({"routing_profile": "magic"}, {"routing_enabled": "true"}, {"routing_proxy_domains": "https://credential@example.com"},
                       {"routing_dns_resolver": "https://user:secret@dns.example.com"}, {"routing_dns_resolver": "http://dns.example.com"},
                       {"routing_dns_resolver": "https://127.0.0.1/dns-query"}, {"routing_dns_resolver": "https://localhost/dns-query"}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                controls.validate_values("routing", values)
        self.assertEqual(controls.validate_values("routing", {"routing_proxy_domains": "YouTube.COM,googlevideo.com youtube.com", "routing_direct_cidrs": "192.168.1.2/24"}),
                         {"routing_proxy_domains": "youtube.com,googlevideo.com", "routing_direct_cidrs": "192.168.1.0/24"})

    def test_node_coordinates_addresses_and_existing_strategy(self):
        self.assertEqual(controls.validate_values("nodes", {"load_balancer_strategy": "stable"}), {"load_balancer_strategy": "stable"})
        for item in ("Node|127.0.0.1:443|10|10|Place", "Node|good.example:443|NaN|10|Place", "Node|good.example:443|91|10|Place", "Node|https://good.example:443|10|10|Place"):
            with self.subTest(item=item), self.assertRaises(ValueError):
                controls.validate_values("nodes", {"node_map_config": item})
        controls.validate_values("nodes", {"node_map_config": "Node|public.example:443|48.8|2.3|Paris"})

    def test_preview_expiry_actor_digest_and_duplicate(self):
        preview = controls.preview_settings(self.db, self.current(), {"routing_enabled": "0"}, "admin", "routing", now=NOW)
        for actor, digest, moment in (("other", preview["digest"], NOW), ("admin", "bad", NOW), ("admin", preview["digest"], NOW + 601)):
            with self.subTest(actor=actor, moment=moment), self.assertRaises(ValueError):
                controls.apply_preview(self.db, preview["preview_id"], digest, self.current(), actor, "owner", self.apply, now=moment)
        controls.apply_preview(self.db, preview["preview_id"], preview["digest"], self.current(), "admin", "owner", self.apply, now=NOW)
        with self.assertRaises(ValueError):
            controls.apply_preview(self.db, preview["preview_id"], preview["digest"], self.current(), "admin", "owner", self.apply, now=NOW)

    def test_concurrent_changes_reject_stale_preview_and_rollback(self):
        preview = controls.preview_settings(self.db, self.current(), {"routing_profile": "proxy_all"}, "admin", "routing", now=NOW)
        self.db.execute("update settings set value='9' where key='routing_revision'")
        with self.assertRaises(ValueError):
            controls.apply_preview(self.db, preview["preview_id"], preview["digest"], self.s, "admin", "owner", self.apply, now=NOW)
        preview = controls.preview_settings(self.db, self.current(), {"routing_profile": "proxy_all"}, "admin", "routing", now=NOW)
        result = controls.apply_preview(self.db, preview["preview_id"], preview["digest"], self.current(), "admin", "owner", self.apply, now=NOW)
        self.db.execute("update settings set value='whitelist' where key='routing_profile'")
        with self.assertRaises(ValueError):
            controls.rollback_preview(self.db, result["snapshot_id"], self.current(), "admin", "owner", now=NOW)

    def test_callback_failure_rolls_back_all_settings_and_consumption(self):
        preview = controls.preview_settings(self.db, self.current(), {"routing_enabled": "0"}, "admin", "routing", now=NOW)
        def failing(db, values, scope):
            self.apply(db, values, scope)
            raise ValueError("test")
        with self.assertRaises(ValueError):
            controls.apply_preview(self.db, preview["preview_id"], preview["digest"], self.current(), "admin", "owner", failing, now=NOW)
        self.assertEqual(self.current(), self.s)
        self.assertEqual(self.db.execute("select state from control_previews").fetchone()[0], "pending")
        self.assertEqual(self.db.execute("select count(*) from control_config_snapshots").fetchone()[0], 0)

    def test_callback_that_does_not_save_is_not_success(self):
        preview = controls.preview_settings(self.db, self.current(), {"routing_enabled": "0"}, "admin", "routing", now=NOW)
        with self.assertRaises(ValueError):
            controls.apply_preview(self.db, preview["preview_id"], preview["digest"], self.current(), "admin", "owner", lambda *args: None, now=NOW)

    def populate_quality(self, devices=20, bad=6, version="5.11.3", stage="app_started", moment=NOW):
        for index in range(devices):
            device = f"{index:016x}"
            community.record_quality(self.db, device, {"consent": True, "event_id": f"quality-{index:08d}", "node_key": "main", "protocol": "vless", "network": "wifi", "app_version": version,
                "connect_ms": 100 + index, "ping_ms": 30 + index, "disconnects": 3 if index < bad else 0, "success": index >= bad}, moment)
            community.record_delivery(self.db, device, {"event_id": f"delivery-{index:08d}", "stage": stage, "version_code": 501103000}, moment)

    def test_quality_empty_unknown_and_small_cohorts_hidden(self):
        snap = controls.dashboard_snapshot(self.db, self.current(), NOW)
        self.assertFalse(snap["quality"]["available"])
        self.assertNotIn("reports", snap["quality"])
        self.assertIn("—", controls.render_dashboard(snap))
        self.populate_quality(2, 0)
        quality = controls.client_quality(self.db, NOW)
        self.assertEqual(quality["devices"], 2)
        self.assertEqual(quality["groups"], [])

    def test_quality_latest_per_device_and_no_zero_ms_from_unknown(self):
        self.populate_quality(3, 0)
        community.record_quality(self.db, "0000000000000000", {"consent": True, "event_id": "new-quality-0001", "node_key": "main", "protocol": "vless", "network": "wifi", "app_version": "5.11.3", "success": True}, NOW + 1)
        snap = controls.dashboard_snapshot(self.db, self.current(), NOW + 1)
        group = snap["quality"]["groups"][0]
        self.assertEqual(group["devices"], 3)
        self.assertEqual(group["connect_p95_ms"], 102)
        self.assertEqual(group["ping_p50_ms"], 31)
        self.assertNotIn("0000000000000000", json.dumps(snap))

    def test_install_handoff_never_counts_as_install_or_guard_population(self):
        self.populate_quality(20, 20, stage="install_handoff")
        funnel = controls.delivery_funnel(self.db, 501103000, NOW)
        self.assertEqual(funnel["stages"]["app_started"], 0)
        self.assertEqual(funnel["stages"]["install_handoff"], 20)
        guard = controls.release_guard_decision(controls.client_quality(self.db, NOW), funnel, "5.11.3", NOW)
        self.assertFalse(guard["pause_recommended"])
        self.assertEqual(guard["devices"], 0)

    def test_guard_broad_recent_exact_version_and_owner_only_pause(self):
        self.populate_quality()
        decision = controls.pause_rollout(self.db, self.current(), "admin", "owner", NOW)
        self.assertTrue(decision["pause_recommended"])
        self.assertEqual(self.current()["update_rollout_paused"], "1")
        self.assertEqual(self.current()["app_version"], "5.11.3")
        with self.assertRaises(PermissionError):
            controls.pause_rollout(self.db, self.current(), "operator", "operator", NOW)
        snapshot = controls.dashboard_snapshot(self.db, self.current(), NOW + 3601)
        self.assertFalse(snapshot["guard"]["pause_recommended"])

    def test_guard_does_not_mix_old_version_or_duplicate_device(self):
        self.populate_quality(30, 30, version="5.11.2")
        self.assertFalse(controls.dashboard_snapshot(self.db, self.current(), NOW)["guard"]["pause_recommended"])

    def test_render_escapes_threads_and_diffs(self):
        rendered = controls.render_support([{"id": 1, "subject": "<script>bad</script>", "state": "open", "messages": [{"sender": "user", "body": "<img onerror=evil>", "diagnostic_json": '{"summary":"<script>x</script>"}'}]}])
        self.assertNotIn("<img", rendered)
        self.assertNotIn("<script>bad", rendered)
        self.assertIn("&lt;script&gt;bad", rendered)
        self.assertIn("/operator/community/reply", rendered)

    def test_secure_json_request_rejects_foreign_null_missing_and_bad_csrf(self):
        headers = {"Origin": ORIGIN, "Content-Type": "application/json", "X-QV-Request": "1", "X-QV-CSRF": "correct"}
        self.assertTrue(controls.secure_json_request(headers, ORIGIN, "correct"))
        for key, value in (("Origin", "https://evil.example"), ("Origin", "null"), ("Origin", ""), ("Origin", "https://panel.example.com"), ("X-QV-Request", ""), ("X-QV-CSRF", "bad"), ("Sec-Fetch-Site", "cross-site")):
            with self.subTest(key=key, value=value):
                self.assertFalse(controls.secure_json_request({**headers, key: value}, ORIGIN, "correct"))

    def test_public_origin_requires_configured_https_domain(self):
        for value in ("http://panel.example.com", "https://127.0.0.1", "https://localhost", "https://secret:password@panel.example.com", "https://panel.example.com/path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                controls.public_origin(value)
        self.assertEqual(controls.public_origin(ORIGIN), (ORIGIN, "panel.example.com"))


@unittest.skipUnless(controls.passkey_available(), "Optional official webauthn package not installed")
class PasskeyTests(unittest.TestCase):
    """A virtual authenticator signs real test credentials; no crypto mocks."""
    def setUp(self):
        ControlTests.setUp(self)
        from cryptography.hazmat.primitives.asymmetric import ec
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = b"unit-test-only-credential-identity"
        self.manager = controls.WebAuthnManager(ORIGIN)

    def tearDown(self):
        ControlTests.tearDown(self)

    def client_data(self, kind, challenge, origin=ORIGIN, cross=False):
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": cross}, separators=(",", ":")).encode()

    def register_credential(self, begin, origin=ORIGIN, cross=False):
        import cbor2
        numbers = self.private.public_key().public_numbers()
        public_key = {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}
        authenticator_data = hashlib.sha256(b"panel.example.com").digest() + bytes([0x45]) + (0).to_bytes(4, "big") + bytes(16) + len(self.credential_id).to_bytes(2, "big") + self.credential_id + cbor2.dumps(public_key)
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": authenticator_data})
        client = self.client_data("webauthn.create", begin["options"]["challenge"], origin, cross)
        return {"id": b64(self.credential_id), "rawId": b64(self.credential_id), "type": "public-key", "response": {"clientDataJSON": b64(client), "attestationObject": b64(attestation)}}

    def register(self):
        begin = self.manager.begin_registration(self.db, "admin", BINDING, True, NOW)
        result = self.manager.finish_registration(self.db, "admin", BINDING, begin["ceremony_id"], self.register_credential(begin), now=NOW + 1)
        self.db.commit()
        self.assertTrue(result["registered"])
        return begin

    def authenticate_credential(self, begin, count=1, origin=ORIGIN, user_handle=None, uv=True):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        data = hashlib.sha256(b"panel.example.com").digest() + bytes([0x05 if uv else 0x01]) + count.to_bytes(4, "big")
        client = self.client_data("webauthn.get", begin["options"]["challenge"], origin)
        signature = self.private.sign(data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        response = {"clientDataJSON": b64(client), "authenticatorData": b64(data), "signature": b64(signature)}
        if user_handle is not None:
            response["userHandle"] = b64(user_handle)
        return {"id": b64(self.credential_id), "rawId": b64(self.credential_id), "type": "public-key", "response": response}

    def test_real_registration_and_authentication_library_checks(self):
        self.register()
        begin = self.manager.begin_authentication(self.db, "admin", BINDING, NOW + 2)
        self.assertEqual(begin["options"]["userVerification"], "required")
        user_handle = self.db.execute("select user_handle from control_passkey_users").fetchone()[0]
        result = self.manager.finish_authentication(self.db, BINDING, begin["ceremony_id"], self.authenticate_credential(begin, user_handle=user_handle), NOW + 3)
        self.assertEqual(result, {"username": "admin", "role": "owner"})
        self.assertEqual(self.db.execute("select sign_count from control_passkeys").fetchone()[0], 1)
        with self.assertRaises(PermissionError):
            self.manager.finish_authentication(self.db, BINDING, begin["ceremony_id"], self.authenticate_credential(begin), NOW + 4)

    def test_registration_requires_reauthentication_and_rejects_cross_origin(self):
        with self.assertRaises(PermissionError):
            self.manager.begin_registration(self.db, "admin", BINDING, now=NOW)
        begin = self.manager.begin_registration(self.db, "admin", BINDING, True, NOW)
        with self.assertRaises(ValueError):
            self.manager.finish_registration(self.db, "admin", BINDING, begin["ceremony_id"], self.register_credential(begin, cross=True), now=NOW + 1)
        self.assertEqual(self.db.execute("select count(*) from control_passkeys").fetchone()[0], 0)

    def test_registration_wrong_origin_and_reused_challenge_rejected(self):
        begin = self.manager.begin_registration(self.db, "admin", BINDING, True, NOW)
        with self.assertRaises(ValueError):
            self.manager.finish_registration(self.db, "admin", BINDING, begin["ceremony_id"], self.register_credential(begin, origin="https://evil.example"), now=NOW + 1)
        with self.assertRaises(PermissionError):
            self.manager.finish_registration(self.db, "admin", BINDING, begin["ceremony_id"], self.register_credential(begin), now=NOW + 2)

    def test_parallel_browser_ceremonies_do_not_invalidate_each_other(self):
        first = self.manager.begin_registration(self.db, "admin", BINDING, True, NOW)
        self.manager.begin_registration(self.db, "admin", BINDING + "-other-browser", True, NOW)
        result = self.manager.finish_registration(self.db, "admin", BINDING, first["ceremony_id"], self.register_credential(first), now=NOW + 1)
        self.assertTrue(result["registered"])

    def test_auth_expiry_binding_role_revocation_and_user_verification(self):
        self.register()
        begin = self.manager.begin_authentication(self.db, "admin", BINDING, NOW + 2)
        with self.assertRaises(PermissionError):
            self.manager.finish_authentication(self.db, BINDING + "wrong", begin["ceremony_id"], self.authenticate_credential(begin), NOW + 3)
        with self.assertRaises(PermissionError):
            self.manager.finish_authentication(self.db, BINDING, begin["ceremony_id"], self.authenticate_credential(begin), NOW + 123)
        begin = self.manager.begin_authentication(self.db, "admin", BINDING, NOW + 4)
        with self.assertRaises(ValueError):
            self.manager.finish_authentication(self.db, BINDING, begin["ceremony_id"], self.authenticate_credential(begin, uv=False), NOW + 5)
        begin = self.manager.begin_authentication(self.db, "admin", BINDING, NOW + 6)
        self.db.execute("update admin_users set role='viewer' where username='admin'")
        result = self.manager.finish_authentication(self.db, BINDING, begin["ceremony_id"], self.authenticate_credential(begin), NOW + 7)
        self.assertEqual(result["role"], "viewer")
        controls.revoke_passkey(self.db, "admin", b64(self.credential_id), True, NOW + 8)
        with self.assertRaises(PermissionError):
            self.manager.begin_authentication(self.db, "admin", BINDING, NOW + 9)

    def test_auth_rejects_wrong_userhandle_signature_and_disabled_admin(self):
        self.register()
        begin = self.manager.begin_authentication(self.db, "admin", BINDING, NOW + 2)
        with self.assertRaises(PermissionError):
            self.manager.finish_authentication(self.db, BINDING, begin["ceremony_id"], self.authenticate_credential(begin, user_handle=b"other-user"), NOW + 3)
        begin = self.manager.begin_authentication(self.db, "admin", BINDING, NOW + 4)
        credential = self.authenticate_credential(begin)
        credential["response"]["signature"] = b64(b"not-a-signature")
        with self.assertRaises(ValueError):
            self.manager.finish_authentication(self.db, BINDING, begin["ceremony_id"], credential, NOW + 5)
        begin = self.manager.begin_authentication(self.db, "admin", BINDING, NOW + 6)
        self.db.execute("update admin_users set enabled=0 where username='admin'")
        with self.assertRaises(PermissionError):
            self.manager.finish_authentication(self.db, BINDING, begin["ceremony_id"], self.authenticate_credential(begin), NOW + 7)


if __name__ == "__main__":
    unittest.main()
