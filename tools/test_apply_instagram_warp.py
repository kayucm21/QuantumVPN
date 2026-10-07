"""Offline regression tests for the guarded Instagram/WARP routing repair."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import types
import unittest
from unittest import mock

from tools.apply_instagram_warp import REMOTE


INSTAGRAM_DOMAINS = [
    "instagram.com", "cdninstagram.com", "facebook.com", "facebook.net",
    "fbcdn.net", "fbsbx.com", "ig.me",
]


def remote_helpers():
    # No remote entry point, SSH, network, service or server filesystem call runs.
    namespace = {"RUN_REMOTE": False}
    exec(compile(REMOTE, "<instagram-warp-offline>", "exec"), namespace)
    return namespace


def routing_settings():
    return {
        "warp_domains": ["existing.example", "geosite:google", "instagram.com"],
        "warp_ips": ["1.1.1.0/24"],
        "direct_domains": ["local.example"],
        "blocked_ips": ["geoip:private"],
        "strategy": "IPIfNonMatch",
        "unknown_future_setting": {"enabled": True, "values": [1, None, "kept"]},
    }


def generated_config(settings):
    domains = [value if ":" in value else "domain:" + value
               for value in settings["warp_domains"]]
    return {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api", "services": ["HandlerService"]},
        "dns": {"servers": ["https://dns.example/dns-query"], "hosts": {"local": "127.0.0.1"}},
        "inbounds": [
            {"tag": "client", "protocol": "vless", "port": 443,
             "settings": {"clients": [{"id": "synthetic-client-secret", "email": "client@example"}]},
             "streamSettings": {"realitySettings": {"privateKey": "synthetic-reality-secret"}}},
        ],
        "outbounds": [
            {"tag": "warp", "protocol": "wireguard",
             "settings": {"secretKey": "synthetic-warp-secret",
                          "address": ["172.16.0.2/32", "2606:4700:110:1234::2/128"],
                          "peers": [{"publicKey": "synthetic-peer-key",
                                     "endpoint": "warp.example:2408", "allowedIPs": ["0.0.0.0/0", "::/0"]}]}},
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "balancers": [{"tag": "warp-out", "selector": ["warp"], "fallbackTag": "warp"}],
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
                {"type": "field", "domain": ["domain:blocked.example"], "outboundTag": "block"},
                {"type": "field", "domain": domains, "balancerTag": "warp-out"},
                {"type": "field", "ip": list(settings["warp_ips"]), "balancerTag": "warp-out"},
                {"type": "field", "domain": list(domains), "outboundTag": "direct"},
                {"type": "field", "ip": list(settings["warp_ips"]), "outboundTag": "direct"},
                {"type": "field", "domain": list(domains), "balancerTag": "warp-out", "inboundTag": ["special"]},
                {"type": "field", "ip": list(settings["warp_ips"]), "balancerTag": "warp-out", "inboundTag": ["special"]},
                {"type": "field", "domain": ["domain:other.example"], "balancerTag": "warp-out"},
            ],
        },
    }


class InstagramWarpRoutingTests(unittest.TestCase):
    def setUp(self):
        self.helpers = remote_helpers()
        self.old = routing_settings()
        self.raw = json.dumps(self.old, indent=2)

    def test_proposed_appends_missing_values_and_preserves_unrelated_settings(self):
        before = copy.deepcopy(self.old)
        result = self.helpers["proposed"](self.raw)
        self.assertEqual(self.old["warp_domains"] + INSTAGRAM_DOMAINS[1:], result["warp_domains"])
        self.assertEqual(["1.1.1.0/24", "2000::/3"], result["warp_ips"])
        self.assertEqual(before, self.old)
        self.assertEqual({key: value for key, value in before.items() if not key.startswith("warp_")},
                         {key: value for key, value in result.items() if not key.startswith("warp_")})
        for domain in INSTAGRAM_DOMAINS:
            self.assertEqual(1, result["warp_domains"].count(domain))

    def test_proposed_is_idempotent_and_only_adds_public_ipv6_range(self):
        first = self.helpers["proposed"](self.raw)
        second = self.helpers["proposed"](json.dumps(first))
        self.assertEqual(first, second)
        self.assertEqual("2000::/3", self.helpers["IPV6"])
        self.assertEqual({"2000::/3"}, set(first["warp_ips"]) - set(self.old["warp_ips"]))
        self.assertNotIn("::/0", first["warp_ips"])

    def test_unexpected_routing_schema_is_rejected(self):
        for stored_key in ("warp_domains", "warp_ips"):
            for invalid in (None, "not-a-list", {}, ["valid", 7], [False]):
                with self.subTest(key=stored_key, value=invalid):
                    value = {**self.old, stored_key: invalid}
                    with self.assertRaisesRegex(RuntimeError, "routing list schema"):
                        self.helpers["proposed"](json.dumps(value))
            with self.subTest(key=stored_key, value="missing"):
                value = {key: item for key, item in self.old.items() if key != stored_key}
                with self.assertRaisesRegex(RuntimeError, "routing list schema"):
                    self.helpers["proposed"](json.dumps(value))
        for value in ([], None, "not-an-object"):
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, "routing object"):
                self.helpers["proposed"](json.dumps(value))

    def test_generated_candidate_changes_only_the_two_matching_warp_rules(self):
        config = generated_config(self.old)
        original = copy.deepcopy(config)
        desired = self.helpers["proposed"](self.raw)
        result = self.helpers["generated_candidate"](config, self.old, desired)
        expected = copy.deepcopy(original)
        expected["routing"]["rules"][3]["domain"] = [
            "domain:existing.example", "geosite:google",
            *["domain:" + value for value in INSTAGRAM_DOMAINS],
        ]
        expected["routing"]["rules"][4]["ip"] = ["1.1.1.0/24", "2000::/3"]
        self.assertEqual(expected, result)
        self.assertEqual(original, config, "The input config must not be mutated")
        for section in ("api", "inbounds", "outbounds", "dns"):
            self.assertEqual(original[section], result[section], section)
        self.assertNotIn("::/0", result["routing"]["rules"][4]["ip"])
        self.assertIn("::/0", result["outbounds"][0]["settings"]["peers"][0]["allowedIPs"])

    def test_missing_ambiguous_or_mismatched_warp_rules_are_rejected(self):
        desired = self.helpers["proposed"](self.raw)
        for key, index in (("domain", 3), ("ip", 4)):
            for condition in ("missing", "ambiguous", "mismatched", "inbound-restricted"):
                with self.subTest(key=key, condition=condition):
                    config = generated_config(self.old)
                    rules = config["routing"]["rules"]
                    if condition == "missing":
                        del rules[index]
                    elif condition == "ambiguous":
                        rules.append(copy.deepcopy(rules[index]))
                    elif condition == "mismatched":
                        rules[index][key].append("domain:unexpected.example" if key == "domain" else "8.8.8.8/32")
                    else:
                        rules[index]["inboundTag"] = ["special"]
                    original = copy.deepcopy(config)
                    with self.assertRaisesRegex(RuntimeError, "WARP rules differ"):
                        self.helpers["generated_candidate"](config, self.old, desired)
                    self.assertEqual(original, config)

    def test_api_and_block_guards_must_precede_both_warp_rules(self):
        desired = self.helpers["proposed"](self.raw)
        for condition in ("no-guards", "domain-before-block", "ip-before-block", "block-after-warp", "api-after-warp"):
            with self.subTest(condition=condition):
                config = generated_config(self.old)
                rules = config["routing"]["rules"]
                if condition == "no-guards":
                    for rule in rules:
                        if rule.get("outboundTag") in ("api", "block"):
                            rule["outboundTag"] = "direct"
                elif condition == "domain-before-block":
                    rules[2], rules[3] = rules[3], rules[2]
                elif condition == "ip-before-block":
                    rules[2], rules[4] = rules[4], rules[2]
                else:
                    rules.append({"type": "field", "outboundTag": "api" if condition == "api-after-warp" else "block"})
                with self.assertRaisesRegex(RuntimeError, "WARP rule ordering"):
                    self.helpers["generated_candidate"](config, self.old, desired)


class InstagramWarpDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.helpers = remote_helpers()
        self.temp = tempfile.TemporaryDirectory(prefix="instagram-warp-offline-")
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "test.db"
        self.connection = sqlite3.connect(self.db)
        self.addCleanup(self.connection.close)
        self.writer = sqlite3.connect(self.db)
        self.addCleanup(self.writer.close)
        self.raw = json.dumps(routing_settings(), indent=2)
        self.desired = json.dumps(self.helpers["proposed"](self.raw), separators=(",", ":"))
        self.connection.executescript("""
            CREATE TABLE settings (
                id INTEGER PRIMARY KEY, routing_config TEXT, config_revision INTEGER,
                updated_at INTEGER, warp_enabled INTEGER, last_config_error TEXT,
                subscription_secret TEXT, operator_setting TEXT
            );
            CREATE TABLE users (id INTEGER PRIMARY KEY, client_secret TEXT, traffic INTEGER);
            CREATE TABLE audit (id INTEGER PRIMARY KEY, event TEXT);
        """)
        self.connection.executemany("INSERT INTO settings VALUES (?,?,?,?,?,?,?,?)", [
            (1, self.raw, 10, 100, 1, "", "synthetic-subscription-secret", "old-setting"),
            (2, "unrelated-row", 90, 50, 0, "unrelated-error", "other-secret", "other-setting"),
        ])
        self.connection.execute("INSERT INTO users VALUES (1,?,?)", ("synthetic-existing-user", 100))
        self.connection.execute("INSERT INTO audit VALUES (1,?)", ("before-snapshot",))
        self.connection.commit()
        self.helpers["time"] = types.SimpleNamespace(time=lambda: 1234567890)

    def snapshot(self):
        return {table: self.connection.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
                for table in ("settings", "users", "audit")}

    def test_cas_updates_only_routing_revision_and_timestamp_and_keeps_new_data(self):
        raw, revision = self.helpers["read_settings"](self.connection)
        # A separate connection commits user/table changes after the routing snapshot.
        self.writer.execute("UPDATE users SET traffic=traffic+75 WHERE id=1")
        self.writer.execute("INSERT INTO users VALUES (2,?,?)", ("synthetic-new-user", 250))
        self.writer.execute("INSERT INTO audit VALUES (2,?)", ("concurrent-event",))
        self.writer.execute("UPDATE settings SET operator_setting=? WHERE id=1", ("concurrent-setting",))
        self.writer.commit()
        before = self.snapshot()
        self.helpers["cas"](self.connection, raw, revision, self.desired)
        expected = copy.deepcopy(before)
        settings = list(expected["settings"][0])
        settings[1:4] = [self.desired, revision + 1, 1234567890]
        expected["settings"][0] = tuple(settings)
        self.assertEqual(expected, self.snapshot())
        self.assertFalse(self.connection.in_transaction)

    def test_cas_rejects_concurrent_revision_change_and_rolls_back(self):
        self.assert_concurrent_change_rejected("config_revision=config_revision+1", ())

    def test_cas_rejects_concurrent_raw_change_even_with_same_revision_and_rolls_back(self):
        # Semantically identical but differently serialized routing is still a conflict.
        self.assert_concurrent_change_rejected("routing_config=?", (json.dumps(routing_settings()),))

    def assert_concurrent_change_rejected(self, assignment, values):
        raw, revision = self.helpers["read_settings"](self.connection)
        self.writer.execute("UPDATE settings SET " + assignment + " WHERE id=1", values)
        self.writer.execute("INSERT INTO users VALUES (2,?,?)", ("synthetic-concurrent-user", 500))
        self.writer.commit()
        before = self.snapshot()
        statements = []
        self.connection.set_trace_callback(statements.append)
        with self.assertRaisesRegex(RuntimeError, "changed concurrently; update refused"):
            self.helpers["cas"](self.connection, raw, revision, self.desired)
        self.assertFalse(self.connection.in_transaction)
        self.assertEqual("BEGIN IMMEDIATE", statements[0])
        self.assertEqual("ROLLBACK", statements[-1])
        self.assertNotIn("COMMIT", statements)
        self.assertEqual(before, self.snapshot())

    def test_cas_rolls_back_on_sqlite_failure(self):
        self.connection.execute("""
            CREATE TRIGGER refuse_routing_update BEFORE UPDATE ON settings
            BEGIN SELECT RAISE(ABORT, 'synthetic update failure'); END
        """)
        self.connection.commit()
        before = self.snapshot()
        statements = []
        self.connection.set_trace_callback(statements.append)
        with self.assertRaises(sqlite3.IntegrityError):
            self.helpers["cas"](self.connection, self.raw, 10, self.desired)
        self.assertFalse(self.connection.in_transaction)
        self.assertEqual("ROLLBACK", statements[-1])
        self.assertEqual(before, self.snapshot())

    def test_inspect_reconcile_and_verify_committed_database_connections_are_read_only(self):
        self.helpers["DB"] = self.db
        for mode in ("inspect", "reconcile", "verify_committed"):
            with self.subTest(mode=mode):
                self.helpers["MODE"] = mode
                with contextlib.closing(self.helpers["db_connect"]()) as connection:
                    self.assertEqual((self.raw, 10), self.helpers["read_settings"](connection))
                    with self.assertRaisesRegex(sqlite3.OperationalError, "readonly"):
                        connection.execute("UPDATE settings SET config_revision=config_revision+1 WHERE id=1")
        self.assertEqual((self.raw, 10), self.helpers["read_settings"](self.connection))

    def test_apply_and_rollback_database_connections_allow_the_guarded_write(self):
        self.helpers["DB"] = self.db
        for mode in ("apply", "rollback"):
            with self.subTest(mode=mode):
                self.helpers["MODE"] = mode
                with contextlib.closing(self.helpers["db_connect"]()) as connection:
                    raw, revision = self.helpers["read_settings"](connection)
                    self.helpers["cas"](connection, raw, revision, self.desired)
        self.assertEqual((self.desired, 12), self.helpers["read_settings"](self.connection))

    def test_read_only_database_connection_never_creates_a_missing_database(self):
        self.helpers["DB"] = self.db.with_name("missing.db")
        self.helpers["MODE"] = "inspect"
        with self.assertRaises(sqlite3.OperationalError):
            self.helpers["db_connect"]()
        self.assertFalse(self.helpers["DB"].exists())

    def test_rollback_can_restore_routing_when_the_panel_reports_a_config_error_or_disabled_warp(self):
        self.helpers["restart_and_check"] = mock.Mock()
        self.helpers["service"] = mock.Mock(return_value="active")
        self.helpers["probes"] = mock.Mock(return_value={"healthy": True})
        config = generated_config(routing_settings())
        self.helpers["config"] = mock.Mock(return_value=config)
        state = {"desired_raw": self.desired, "desired_revision": 11, "previous_raw": self.raw,
                 "previous_config_sha256": self.helpers["digest"](config)}
        for warp_enabled, error in ((0, ""), (1, "synthetic config error"), (0, "synthetic config error")):
            with self.subTest(warp_enabled=warp_enabled, error=error):
                self.writer.execute("UPDATE settings SET routing_config=?,config_revision=11,warp_enabled=?,last_config_error=? WHERE id=1",
                                    (self.desired, warp_enabled, error))
                self.writer.commit()
                with self.assertRaisesRegex(RuntimeError, "WARP not enabled/healthy"):
                    self.helpers["read_settings"](self.connection)
                before = self.snapshot()
                self.helpers["rollback"](state, self.connection)
                expected = copy.deepcopy(before)
                settings = list(expected["settings"][0])
                settings[1:4] = [self.raw, 12, 1234567890]
                expected["settings"][0] = tuple(settings)
                self.assertEqual(expected, self.snapshot())
                self.assertEqual((self.raw, 12), self.helpers["read_settings"](self.connection, require_health=False))
        self.assertEqual(3, self.helpers["restart_and_check"].call_count)
        self.assertEqual(3, self.helpers["probes"].call_count)
        self.helpers["service"].assert_has_calls([mock.call("quantumvpn-operator")] * 3)

    def test_rollback_does_not_claim_success_if_regenerated_config_has_concurrent_client_changes(self):
        self.writer.execute("UPDATE settings SET routing_config=?,config_revision=11 WHERE id=1", (self.desired,))
        self.writer.commit()
        self.helpers["restart_and_check"] = mock.Mock()
        self.helpers["probes"] = mock.Mock()
        previous = generated_config(routing_settings())
        changed = copy.deepcopy(previous)
        changed["inbounds"][0]["settings"]["clients"].append({"id": "synthetic-new-client"})
        self.helpers["config"] = mock.Mock(return_value=changed)
        state = {"desired_raw": self.desired, "desired_revision": 11, "previous_raw": self.raw,
                 "previous_config_sha256": self.helpers["digest"](previous)}
        with self.assertRaisesRegex(RuntimeError, "Rollback config differs; concurrent client changes are not overwritten"):
            self.helpers["rollback"](state, self.connection)
        self.assertEqual((self.raw, 12), self.helpers["read_settings"](self.connection))
        self.assertEqual(changed, self.helpers["config"]())
        self.helpers["probes"].assert_not_called()

    def test_unhealthy_rollback_still_refuses_concurrent_routing_changes(self):
        self.writer.execute("UPDATE settings SET last_config_error=?,config_revision=12 WHERE id=1", ("synthetic config error",))
        self.writer.commit()
        before = self.snapshot()
        self.helpers["restart_and_check"] = mock.Mock()
        self.helpers["probes"] = mock.Mock()
        state = {"desired_raw": self.desired, "desired_revision": 11, "previous_raw": self.raw}
        with self.assertRaisesRegex(RuntimeError, "Concurrent routing update; rollback refused"):
            self.helpers["rollback"](state, self.connection)
        self.assertEqual(before, self.snapshot())
        self.helpers["restart_and_check"].assert_not_called()
        self.helpers["probes"].assert_not_called()

    def adoption_fixture(self):
        directory = Path(self.temp.name) / "private-transaction"
        directory.mkdir()
        with contextlib.closing(sqlite3.connect(directory / "rospanel.db")) as backup:
            self.connection.backup(backup)
        # Track the real read-only snapshot handles so Windows can remove the
        # temporary test directory even though sqlite context exit only commits.
        def tracked_connect(*args, **kwargs):
            connection = sqlite3.connect(*args, **kwargs)
            self.addCleanup(connection.close)
            return connection
        self.helpers["sqlite3"] = types.SimpleNamespace(connect=tracked_connect)
        self.helpers["private_json"] = mock.Mock()
        return directory, {"phase": "committed", "desired_raw": self.desired,
                           "previous_revision": 10, "desired_revision": 11}

    def test_generator_adoption_keeps_the_expected_revision_without_state_or_database_writes(self):
        directory, state = self.adoption_fixture()
        self.writer.execute("UPDATE settings SET routing_config=?,config_revision=11 WHERE id=1", (self.desired,))
        self.writer.commit()
        previous_state = copy.deepcopy(state)
        before = self.snapshot()
        self.helpers["adopt_generated_revision"](state, self.connection, directory)
        self.assertEqual(previous_state, state)
        self.assertEqual(before, self.snapshot())
        self.helpers["private_json"].assert_not_called()

    def test_generator_adoption_accepts_one_increment_and_keeps_concurrent_user_data(self):
        directory, state = self.adoption_fixture()
        self.writer.execute("UPDATE settings SET routing_config=?,config_revision=12,updated_at=999,last_config_error=? WHERE id=1",
                            (self.desired, "synthetic generator status"))
        self.writer.execute("INSERT INTO users VALUES (2,?,?)", ("synthetic-post-backup-user", 900))
        self.writer.execute("INSERT INTO audit VALUES (2,?)", ("post-backup-event",))
        self.writer.commit()
        before = self.snapshot()
        self.helpers["adopt_generated_revision"](state, self.connection, directory)
        self.assertEqual({"phase": "committed", "desired_raw": self.desired,
                          "previous_revision": 10, "desired_revision": 12,
                          "generator_revision_increment": 1}, state)
        self.helpers["private_json"].assert_called_once_with(directory / "state.json", state)
        self.assertEqual(before, self.snapshot())

    def test_generator_adoption_rejects_extra_revision_and_raw_mismatch_without_writes(self):
        directory, initial = self.adoption_fixture()
        for revision, raw in ((13, self.desired), (10, self.desired),
                              (12, json.dumps(json.loads(self.desired), indent=2))):
            with self.subTest(revision=revision, raw_matches=raw == self.desired):
                self.writer.execute("UPDATE settings SET routing_config=?,config_revision=? WHERE id=1", (raw, revision))
                self.writer.commit()
                before = self.snapshot()
                state = copy.deepcopy(initial)
                with self.assertRaisesRegex(RuntimeError, "Unexpected routing/generator revision; no overwrite"):
                    self.helpers["adopt_generated_revision"](state, self.connection, directory)
                self.assertEqual(initial, state)
                self.assertEqual(before, self.snapshot())
                self.helpers["private_json"].assert_not_called()

    def test_generator_adoption_cannot_accept_a_second_increment_on_a_later_call(self):
        directory, state = self.adoption_fixture()
        state.update(desired_revision=12, generator_revision_increment=1)
        self.writer.execute("UPDATE settings SET routing_config=?,config_revision=13 WHERE id=1", (self.desired,))
        self.writer.commit()
        before = self.snapshot()
        previous_state = copy.deepcopy(state)
        with self.assertRaisesRegex(RuntimeError, "Unexpected routing/generator revision; no overwrite"):
            self.helpers["adopt_generated_revision"](state, self.connection, directory)
        self.assertEqual(previous_state, state)
        self.assertEqual(before, self.snapshot())
        self.helpers["private_json"].assert_not_called()

    def test_generator_adoption_rejects_changed_protected_settings_without_writes(self):
        directory, initial = self.adoption_fixture()
        for protected_column, new_value in (("operator_setting", "changed"),
                                            ("subscription_secret", "changed-secret"),
                                            ("warp_enabled", 0)):
            with self.subTest(column=protected_column):
                self.writer.execute("UPDATE settings SET routing_config=?,config_revision=12,operator_setting=?,subscription_secret=?,warp_enabled=1 WHERE id=1",
                                    (self.desired, "old-setting", "synthetic-subscription-secret"))
                self.writer.execute("UPDATE settings SET " + protected_column + "=? WHERE id=1", (new_value,))
                self.writer.commit()
                before = self.snapshot()
                state = copy.deepcopy(initial)
                with self.assertRaisesRegex(RuntimeError, "Other panel settings changed; generator revision not adopted"):
                    self.helpers["adopt_generated_revision"](state, self.connection, directory)
                self.assertEqual(initial, state)
                self.assertEqual(before, self.snapshot())
                self.helpers["private_json"].assert_not_called()


class InstagramWarpReconcileTests(unittest.TestCase):
    def setUp(self):
        self.helpers = remote_helpers()
        self.connection = sqlite3.connect(":memory:")
        self.addCleanup(self.connection.close)
        self.helpers.update({
            "MODE": "reconcile", "BACKUP": "/synthetic/instagram-transaction",
            "assert_paths": mock.Mock(), "db_connect": mock.Mock(return_value=self.connection),
            "load_state": mock.Mock(), "confirm": mock.Mock(return_value={"healthy": True}),
        })
        self.mutations = {}
        for name in ("cas", "rollback", "restart_and_check", "private_json", "validate_config"):
            self.mutations[name] = mock.Mock(side_effect=AssertionError("Reconcile must not call " + name))
            self.helpers[name] = self.mutations[name]

    def test_reconcile_refuses_every_unverified_phase_without_retry_or_write(self):
        for phase in (None, "prepared", "committed", "failed", "rolled_back"):
            with self.subTest(phase=phase):
                self.helpers["load_state"].return_value = {} if phase is None else {"phase": phase}
                output = io.StringIO()
                with contextlib.redirect_stdout(output), self.assertRaisesRegex(RuntimeError, "completion not confirmed; no retry"):
                    self.helpers["main"]()
                self.assertEqual("", output.getvalue())
                self.helpers["confirm"].assert_not_called()
        for mutation in self.mutations.values():
            mutation.assert_not_called()

    def test_reconcile_verified_phase_still_requires_confirm_and_only_reports_success(self):
        state = {"phase": "verified"}
        self.helpers["load_state"].return_value = state
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.helpers["main"]()
        self.helpers["confirm"].assert_called_once_with(state, self.connection)
        self.assertEqual({"status": "AppliedConfirmedAfterReconnect",
                          "backup_path": str(Path("/synthetic/instagram-transaction")), "checks": {"healthy": True}},
                         json.loads(output.getvalue()))
        for mutation in self.mutations.values():
            mutation.assert_not_called()

    def test_reconcile_cannot_report_success_when_confirmation_fails(self):
        self.helpers["load_state"].return_value = {"phase": "verified"}
        self.helpers["confirm"].side_effect = RuntimeError("Persistent routing changed")
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaisesRegex(RuntimeError, "Persistent routing changed"):
            self.helpers["main"]()
        self.assertEqual("", output.getvalue())
        for mutation in self.mutations.values():
            mutation.assert_not_called()

    def test_verify_committed_requires_committed_phase_before_adoption_or_marker_write(self):
        self.helpers["MODE"] = "verify_committed"
        self.helpers["adopt_generated_revision"] = mock.Mock()
        marker = mock.Mock()
        self.helpers["private_json"] = marker
        for phase in (None, "prepared", "verified", "failed", "rolled_back"):
            with self.subTest(phase=phase):
                self.helpers["load_state"].return_value = {} if phase is None else {"phase": phase}
                output = io.StringIO()
                with contextlib.redirect_stdout(output), self.assertRaisesRegex(RuntimeError, "Only a committed transaction can be verified"):
                    self.helpers["main"]()
                self.assertEqual("", output.getvalue())
        self.helpers["adopt_generated_revision"].assert_not_called()
        self.helpers["confirm"].assert_not_called()
        marker.assert_not_called()
        for mutation in self.mutations.values():
            mutation.assert_not_called()

    def test_verify_committed_marks_verified_only_after_adoption_and_confirmation(self):
        self.helpers["MODE"] = "verify_committed"
        state = {"phase": "committed", "desired_revision": 11}
        self.helpers["load_state"].return_value = state
        def adopt(current, connection, directory):
            current["desired_revision"] = 12
        self.helpers["adopt_generated_revision"] = mock.Mock(side_effect=adopt)
        self.helpers["private_json"] = mock.Mock()
        calls = mock.Mock()
        calls.attach_mock(self.helpers["adopt_generated_revision"], "adopt")
        calls.attach_mock(self.helpers["confirm"], "confirm")
        calls.attach_mock(self.helpers["private_json"], "marker")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.helpers["main"]()
        directory = Path(self.helpers["BACKUP"])
        self.assertEqual([mock.call.adopt(state, self.connection, directory),
                          mock.call.confirm(state, self.connection),
                          mock.call.marker(directory / "state.json", state)], calls.mock_calls)
        self.assertEqual("verified", state["phase"])
        self.assertEqual({"status": "AppliedVerifiedAfterReconnect", "backup_path": str(directory),
                          "revision": 12, "protected_config_unchanged": True, "checks": {"healthy": True}},
                         json.loads(output.getvalue()))
        for mutation in self.mutations.values():
            mutation.assert_not_called()

    def test_verify_committed_confirmation_failure_never_marks_verified_or_restarts(self):
        self.helpers["MODE"] = "verify_committed"
        state = {"phase": "committed", "desired_revision": 11}
        self.helpers["load_state"].return_value = state
        self.helpers["adopt_generated_revision"] = mock.Mock()
        self.helpers["private_json"] = mock.Mock()
        self.helpers["confirm"].side_effect = RuntimeError("synthetic confirmation failed")
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaisesRegex(RuntimeError, "confirmation failed"):
            self.helpers["main"]()
        self.assertEqual("committed", state["phase"])
        self.assertEqual("", output.getvalue())
        self.helpers["private_json"].assert_not_called()
        for mutation in self.mutations.values():
            mutation.assert_not_called()


if __name__ == "__main__":
    unittest.main()
