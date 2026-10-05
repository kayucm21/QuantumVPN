"""Real loopback HTTP tests for private support and durable notifications.

Only managed upstream admission is replaced by a fixture; handlers, SQLite,
credential binding, operator authorization and request limits run unchanged.
No production URL, user device or live subscription is accessed.
"""

import base64
from contextlib import closing
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class CommunityHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="quantum-community-http-")
        fixture_environment = {
            "QV_DATA_DIR": cls.tmp.name, "QV_DOWNLOAD_ROOT": cls.tmp.name,
            "QV_ADMIN_USER": "community-test", "QV_ADMIN_PASSWORD": "community-test",
            "QV_SUBSCRIPTION_UPSTREAM": "https://example.invalid/sub",
        }
        cls.previous_environment = {key: os.environ.get(key) for key in fixture_environment}
        os.environ.update(fixture_environment)
        spec = importlib.util.spec_from_file_location("community_http_panel", Path(__file__).with_name("quantumvpn_operator_panel.py"))
        cls.panel = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.panel)
        for abi in cls.panel.REQUIRED_RELEASE_ABIS:
            apk = Path(cls.tmp.name) / cls.panel.VERSION / f"QuantumVPN-{cls.panel.VERSION}-operator-debug-{abi}.apk"
            apk.parent.mkdir(exist_ok=True)
            apk.write_bytes(b"offline-test-apk-" + abi.encode())
        cls.server = cls.panel.OperatorHTTPServer(("127.0.0.1", 0), cls.panel.App)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=5)
        cls.tmp.cleanup()
        for key, previous in cls.previous_environment.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous

    def setUp(self):
        with closing(self.panel.conn()) as db:
            for table in ("community_credentials", "community_threads", "community_messages", "community_events",
                          "community_reads", "community_quality", "community_delivery"):
                db.execute("delete from " + table)
            self.panel.set_settings(db, {"subscription_main_enabled": "1", "rate_limit_per_min": "120"})
            db.commit()
        with self.panel._RATE_LOCK:
            self.panel._RATE.clear()

    def request(self, path, *, hwid="", token="", payload=None, raw=None, headers=None, content_type="application/json"):
        headers = dict(headers or {})
        if hwid:
            headers["X-HWID"] = hwid
        if token:
            headers[self.panel.community.TOKEN_HEADER] = token
        if payload is not None:
            raw = json.dumps(payload).encode()
        if raw is not None:
            headers.setdefault("Content-Type", content_type)
        with urlopen(Request(self.base + path, data=raw, headers=headers), timeout=10) as response:
            data = response.read()
            return json.loads(data) if response.headers.get_content_type() == "application/json" else data

    def admitted(self, hwid="http-client-one"):
        body = b"vless://00000000-0000-0000-0000-000000000001@vpn.example.invalid:443?security=tls&type=tcp#OfflineFixture\n"
        with mock.patch.object(self.panel, "managed_subscription", return_value=(body, False)) as upstream:
            with urlopen(Request(self.base + "/api/v1/subscription", headers={"X-HWID": hwid}), timeout=10) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), body)
                token = response.headers.get(self.panel.community.TOKEN_HEADER)
        self.assertEqual(upstream.call_count, 1)
        self.assertTrue(token)
        return hwid, token

    def assertHTTP(self, status, path, **kwargs):
        with self.assertRaises(HTTPError) as caught:
            self.request(path, **kwargs)
        self.assertEqual(caught.exception.code, status)
        raw = caught.exception.read()
        if caught.exception.headers.get_content_type() == "application/json":
            try:
                return json.loads(raw)
            except ValueError:
                # Legacy origin denials have a text body with the old JSON
                # content type. Status assertions still apply to those replies.
                pass
        return raw

    def create_thread(self, hwid, token, request_id="http-thread-create01", **overrides):
        return self.request("/api/client/community/support", hwid=hwid, token=token,
                            payload={"subject": "YouTube тормозит", "body": "Пожалуйста, проверьте соединение",
                                     "request_id": request_id, **overrides})["thread"]

    def operator(self, path, form, *, user="community-test", password="community-test"):
        authorization = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        binding = hashlib.sha256((authorization + ":" + user).encode()).hexdigest()
        csrf = self.panel.control_next.csrf_token(self.panel.session_secret(), binding)
        return self.request(path, raw=urlencode({**form, "csrf": csrf}).encode(),
                            headers={"Authorization": authorization, "Origin": self.panel.PUBLIC_BASE},
                            content_type="application/x-www-form-urlencoded")

    def test_support_writes_require_exact_origin_and_fresh_session_bound_csrf(self):
        hwid, token = self.admitted()
        thread = self.create_thread(hwid, token)
        now = int(self.panel.time.time())
        session = self.panel.sign_session({"u": "community-test", "exp": now + 600, "n": self.panel.secrets.token_hex(16)})
        other_session = self.panel.sign_session({"u": "community-test", "exp": now + 600, "n": self.panel.secrets.token_hex(16)})
        csrf = self.panel.control_next.csrf_token(self.panel.session_secret(), hashlib.sha256(session.encode()).hexdigest())
        cookie = self.panel.SESSION_COOKIE + "=" + session
        with closing(self.panel.conn()) as db:
            rendered = self.panel.control_next.render_support(self.panel.community.operator_threads(db)["threads"], csrf=csrf)
        self.assertEqual(rendered.count("name=csrf value='" + csrf + "'"), 2)
        cases = ((self.panel.PUBLIC_BASE, None, cookie), (self.panel.PUBLIC_BASE, "wrong", cookie),
                 ("", csrf, cookie), ("null", csrf, cookie), ("https://evil.example", csrf, cookie),
                 (self.panel.PUBLIC_BASE, csrf, self.panel.SESSION_COOKIE + "=" + other_session))
        for action in ("reply", "state"):
            form = {"thread_id": thread["id"], "state": "closed", "body": "Подтверждённый ответ", "request_id": "http-csrf-support01"}
            for origin, submitted, test_cookie in cases:
                body = dict(form)
                if submitted is not None:
                    body["csrf"] = submitted
                self.assertHTTP(403, "/operator/community/" + action, raw=urlencode(body).encode(),
                                headers={"Cookie": test_cookie, "Origin": origin}, content_type="application/x-www-form-urlencoded")
            unchanged = self.request(f"/api/client/community/support/{thread['id']}", hwid=hwid, token=token)["thread"]
            self.assertEqual(unchanged["state"], "open")
            self.assertEqual(len(unchanged["messages"]), 1)
        for action in ("reply", "state"):
            self.request("/operator/community/" + action,
                         raw=urlencode({"thread_id": thread["id"], "state": "closed", "body": "Подтверждённый ответ", "request_id": "http-csrf-support01", "csrf": csrf}).encode(),
                         headers={"Cookie": cookie, "Origin": self.panel.PUBLIC_BASE}, content_type="application/x-www-form-urlencoded")
        updated = self.request(f"/api/client/community/support/{thread['id']}", hwid=hwid, token=token)["thread"]
        self.assertEqual(updated["state"], "closed")
        self.assertEqual(len(updated["messages"]), 2)

    def test_corrupt_card_state_requests_support_without_resetting_bank_or_game(self):
        raw_hwid = "corrupt-card-review-fixture"
        device, table_id = self.panel.device_id(raw_hwid), "abcdef123456"
        now = int(self.panel.time.time())
        saved_game = '{"phase":"playing","stake_q_coins":25,"stake_settled":false}'
        with closing(self.panel.conn()) as db:
            db.execute("insert into card_tables values (?,?,?,?,?,?,?,?,?,?)",
                       (table_id, now, now, "playing", device, "Игрок", "9876543210abcdef", "Соперник", "Сохранено", saved_game))
            db.execute("insert into card_wallets values (?,?,?,?,?)", (device, "Игрок", 1175, now, now))
            db.commit()
        ticket = self.panel.card_game_ticket(device, table_id)
        response = self.request("/api/client/cards/state?ticket=" + ticket, hwid=raw_hwid)
        self.assertEqual(response["game_phase"], "unavailable")
        self.assertIn("поддержку", response["message"])
        self.assertNotIn("Создайте", response["message"])
        with closing(self.panel.conn()) as db:
            self.assertEqual(tuple(db.execute("select state,game_json from card_tables where id=?", (table_id,)).fetchone()), ("playing", saved_game))
            self.assertEqual(db.execute("select q_coins from card_wallets where device=?", (device,)).fetchone()[0], 1175)
            for broken_json in ("{", "", "[]"):
                db.execute("update card_tables set game_json=? where id=?", (broken_json, table_id))
                db.commit()
                unavailable = self.request("/api/client/cards/state?ticket=" + ticket, hwid=raw_hwid)
                self.assertEqual(unavailable["game_phase"], "unavailable")
                self.assertIn("поддержку", unavailable["message"])
                self.assertEqual(db.execute("select game_json from card_tables where id=?", (table_id,)).fetchone()[0], broken_json)
                self.assertEqual(db.execute("select q_coins from card_wallets where device=?", (device,)).fetchone()[0], 1175)

    def test_only_admitted_subscription_issues_hashed_device_bound_credential(self):
        hwid, token = self.admitted()
        self.assertEqual(self.request("/api/client/community/support", hwid=hwid, token=token), {"threads": []})
        with closing(self.panel.conn()) as db:
            rows = db.execute("select token_hash,device from community_credentials").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], hashlib.sha256(token.encode()).hexdigest())
        self.assertEqual(rows[0][1], hashlib.sha256(hwid.encode()).hexdigest()[:16])
        self.assertNotIn(token, str(rows))
        self.assertNotIn(hwid, str(rows))

    def test_failed_or_non_subscription_admission_issues_no_credential(self):
        with mock.patch.object(self.panel, "managed_subscription", side_effect=PermissionError("fixture denied")):
            self.assertHTTP(502, "/api/v1/subscription", hwid="denied-fixture")
        with mock.patch.object(self.panel, "managed_subscription", return_value=(b"<html>login</html>", False)):
            self.request("/api/v1/subscription", hwid="html-fixture")
        with closing(self.panel.conn()) as db:
            self.assertEqual(db.execute("select count(*) from community_credentials").fetchone()[0], 0)

    def test_upstream_html_with_https_link_never_appends_reserve_or_issues_credential(self):
        html = b'<html>Access denied. <a href="https://example.invalid/login">Sign in</a></html>'
        with closing(self.panel.conn()) as db:
            self.panel.set_settings(db, {"reserve_profile_enabled": "1"})
            db.commit()
        with mock.patch.object(self.panel, "urlopen", return_value=io.BytesIO(html)), \
                mock.patch.object(self.panel, "reserve_profile_uri", return_value="trojan://offline-fixture-token@vpn.example.invalid:443") as reserve:
            with urlopen(Request(self.base + "/api/v1/subscription", headers={"X-HWID": "unadmitted-html-device"}), timeout=10) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), html)
                self.assertIsNone(response.headers.get(self.panel.community.TOKEN_HEADER))
        reserve.assert_not_called()
        with closing(self.panel.conn()) as db:
            self.assertEqual(db.execute("select count(*) from community_credentials").fetchone()[0], 0)

    def test_spoofed_device_header_and_stolen_token_fail_closed(self):
        error = self.assertHTTP(401, "/api/client/community/support", headers={"X-Device-Id": "victim-device"})
        self.assertEqual(error["error"], "client_authentication_required")
        hwid, token = self.admitted()
        self.assertHTTP(401, "/api/client/community/support", hwid="other-hwid", token=token,
                        headers={"X-Device-Id": hashlib.sha256(hwid.encode()).hexdigest()[:16]})
        self.assertHTTP(401, "/api/client/community/support", hwid=hwid, token="invalid-token")
        self.assertHTTP(401, "/api/client/community/support", hwid=hwid)

    def test_cross_device_thread_read_and_write_are_404(self):
        owner, owner_token = self.admitted("http-owner")
        visitor, visitor_token = self.admitted("http-visitor")
        thread = self.create_thread(owner, owner_token)
        self.assertEqual(self.request("/api/client/community/support", hwid=visitor, token=visitor_token), {"threads": []})
        path = f"/api/client/community/support/{thread['id']}"
        self.assertHTTP(404, path, hwid=visitor, token=visitor_token)
        self.assertHTTP(404, path + "/messages", hwid=visitor, token=visitor_token,
                        payload={"body": "Чужой ответ", "request_id": "visitor-message01"})

    def test_create_send_reply_inbox_read_and_idempotence(self):
        hwid, token = self.admitted()
        outsider, outsider_token = self.admitted("http-other-inbox")
        first = self.create_thread(hwid, token)
        second = self.create_thread(hwid, token)
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(len(second["messages"]), 1)
        path = f"/api/client/community/support/{first['id']}/messages"
        message = {"body": "Ошибка повторилась", "request_id": "http-message-retry01"}
        for _ in range(2):
            thread = self.request(path, hwid=hwid, token=token, payload=message)["thread"]
        self.assertEqual(len(thread["messages"]), 2)
        reply = {"thread_id": first["id"], "body": "Проверили сервер, переподключите VPN", "request_id": "http-operator-reply01"}
        for _ in range(2):
            self.operator("/operator/community/reply", reply)
        thread = self.request(f"/api/client/community/support/{first['id']}", hwid=hwid, token=token)["thread"]
        self.assertEqual([entry["sender"] for entry in thread["messages"]], ["user", "user", "operator"])
        inbox = self.request("/api/client/community/inbox", hwid=hwid, token=token)
        self.assertEqual(len(inbox["events"]), 1)
        self.assertEqual(inbox["events"][0]["kind"], "support_reply")
        self.assertEqual(inbox["unread"], 1)
        self.assertEqual(self.request("/api/client/community/inbox", hwid=outsider, token=outsider_token)["events"], [])
        mark = self.request("/api/client/community/inbox/read", hwid=hwid, token=token,
                            payload={"event_id": inbox["cursor"]})
        self.assertEqual(mark["read_through"], inbox["cursor"])
        self.assertEqual(self.request("/api/client/community/inbox", hwid=hwid, token=token)["unread"], 0)
        self.operator("/operator/community/state", {"thread_id": first["id"], "state": "closed"})
        self.assertHTTP(409, path, hwid=hwid, token=token,
                        payload={"body": "Закрыто", "request_id": "http-closed-message01"})

    def test_malformed_oversized_and_wrong_content_type_do_not_create_messages(self):
        hwid, token = self.admitted()
        path = "/api/client/community/support"
        self.assertEqual(self.assertHTTP(400, path, hwid=hwid, token=token, raw=b"{")["error"], "invalid_json")
        self.assertHTTP(400, path, hwid=hwid, token=token, payload=[])
        self.assertHTTP(413, path, hwid=hwid, token=token, raw=b"x" * (self.panel.community.MAX_REQUEST_BYTES + 1))
        self.assertHTTP(415, path, hwid=hwid, token=token, raw=b"{}", content_type="text/plain")
        with closing(self.panel.conn()) as db:
            self.assertEqual(db.execute("select count(*) from community_threads").fetchone()[0], 0)
            self.assertEqual(db.execute("select count(*) from community_messages").fetchone()[0], 0)

    def test_diagnostics_require_consent_and_server_redacts_private_material(self):
        hwid, token = self.admitted()
        diagnostic = {"app_version": "fixture", "summary": "token=fixture-secret 192.0.2.99",
                      "logs": "vless://fixture@vpn.example.invalid", "subscription": "must-not-persist", "hardware_id": hwid}
        self.assertHTTP(400, "/api/client/community/support", hwid=hwid, token=token,
                        payload={"subject": "Диагностика", "body": "Проверка", "request_id": "http-diag-no-consent",
                                 "diagnostic": diagnostic})
        thread = self.create_thread(hwid, token, request_id="http-diag-with-consent", diagnostic=diagnostic,
                                    diagnostic_consent=True)
        self.assertTrue(thread["messages"][0]["has_diagnostic"])
        self.assertNotIn("diagnostic_json", thread["messages"][0])
        with closing(self.panel.conn()) as db:
            saved = db.execute("select diagnostic_json from community_messages").fetchone()[0]
        for private in ("fixture-secret", "192.0.2.99", "vless://", "must-not-persist", hwid):
            self.assertNotIn(private, saved)

    def test_quality_requires_opt_in_and_delivery_records_not_installation_claim(self):
        hwid, token = self.admitted()
        quality = {"consent": False, "event_id": "http-quality-report01", "node_key": "node-fixture", "protocol": "vless",
                   "network": "wifi", "app_version": "fixture", "connect_ms": 500, "ping_ms": 32, "success": True}
        self.assertHTTP(400, "/api/client/community/quality", hwid=hwid, token=token, payload=quality)
        quality["consent"] = True
        first = self.request("/api/client/community/quality", hwid=hwid, token=token, payload=quality)
        retry = self.request("/api/client/community/quality", hwid=hwid, token=token, payload=quality)
        self.assertFalse(first["duplicate"])
        self.assertTrue(retry["duplicate"])
        delivery = {"event_id": "http-delivery-handoff01", "version_code": 501103000, "stage": "install_handoff"}
        self.request("/api/client/community/delivery", hwid=hwid, token=token, payload=delivery)
        with closing(self.panel.conn()) as db:
            snapshot = self.panel.community.delivery_snapshot(db)
        self.assertEqual(snapshot["stages"]["install_handoff"], 1)
        self.assertEqual(snapshot["stages"]["app_started"], 0)
        self.assertFalse(snapshot["handoff_is_installation"])

    def test_viewer_cannot_reply_or_close_private_support(self):
        hwid, token = self.admitted()
        thread = self.create_thread(hwid, token)
        with closing(self.panel.conn()) as db:
            now = int(self.panel.time.time())
            db.execute("insert into admin_users(username,password_hash,role,enabled,created_at,updated_at) values (?,?,?,?,?,?) "
                       "on conflict(username) do update set role='viewer',enabled=1",
                       ("fixture-viewer", self.panel.password_hash("fixture-viewer"), "viewer", 1, now, now))
            db.commit()
        authorization = "Basic " + base64.b64encode(b"fixture-viewer:fixture-viewer").decode()
        for path, form in (("reply", {"thread_id": thread["id"], "body": "Не разрешено", "request_id": "http-viewer-reply01"}),
                           ("state", {"thread_id": thread["id"], "state": "closed"})):
            self.assertHTTP(403, "/operator/community/" + path, raw=urlencode(form).encode(),
                            headers={"Authorization": authorization}, content_type="application/x-www-form-urlencoded")
        unchanged = self.request(f"/api/client/community/support/{thread['id']}", hwid=hwid, token=token)["thread"]
        self.assertEqual(unchanged["state"], "open")
        self.assertEqual(len(unchanged["messages"]), 1)


if __name__ == "__main__":
    unittest.main()
