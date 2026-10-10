"""Release-scheduling regression checks; no SSH, real APK build or network writes."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest import mock
import zipfile


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


DEPLOY = module("release_deployer_tests", "deploy-local-apk-release.py")
with mock.patch.dict(os.environ, {"QV_ADMIN_USER": "fixture", "QV_ADMIN_PASSWORD": "fixture",
                                 "QV_SUBSCRIPTION_UPSTREAM": "https://example.invalid/sub"}):
    PANEL = module("release_panel_tests", "quantumvpn_operator_panel.py")
SIGNER = "4" * 64
VERSION = "5.11.2"
CODE = 501102099
OLD_VERSION = "5.11.1"
OLD_CODE = 501101099


class ScheduleParsingTests(unittest.TestCase):
    def test_midnight_has_exact_utc_conversion(self):
        now = int(datetime(2026, 10, 3, 16, tzinfo=timezone.utc).timestamp())
        target = DEPLOY.parse_schedule("2026-10-04T00:00:00+03:00", now=now)
        self.assertEqual(target, int(datetime(2026, 10, 3, 21, tzinfo=timezone.utc).timestamp()))

    def test_seven_moscow_is_four_utc_not_local_pc_time(self):
        now = int(datetime(2026, 10, 10, 14, tzinfo=timezone.utc).timestamp())
        target = DEPLOY.parse_schedule("2026-10-11T07:00:00+03:00", now=now)
        self.assertEqual(target, int(datetime(2026, 10, 11, 4, tzinfo=timezone.utc).timestamp()))

    def test_every_whole_moscow_hour_is_explicit_and_exact(self):
        now = int(datetime(2026, 10, 9, tzinfo=timezone.utc).timestamp())
        for hour in range(24):
            text = f"2026-10-11T{hour:02}:00:00+03:00"
            expected = datetime.fromisoformat(text).timestamp()
            self.assertEqual(DEPLOY.parse_schedule(text, now=now), int(expected))

    def test_non_hour_and_invalid_hour_are_rejected(self):
        now = int(datetime(2026, 10, 9, tzinfo=timezone.utc).timestamp())
        for clock in ("24:00:00", "07:01:00", "07:00:01", "7:00:00", "07:00:00.000"):
            with self.subTest(clock=clock), self.assertRaises(ValueError):
                DEPLOY.parse_schedule(f"2026-10-11T{clock}+03:00", now=now)

    def test_ambiguous_non_midnight_or_past_dates_rejected(self):
        now = int(datetime(2026, 10, 3, 16, tzinfo=timezone.utc).timestamp())
        for value in ("2026-10-04T00:00:00", "2026-10-04T00:00:00Z", "2026-10-04T00:00:00+08:00",
                      "2026-10-04T00:01:00+03:00", "2026-10-03T00:00:00+03:00"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                DEPLOY.parse_schedule(value, now=now)

    def test_no_auto_add_ssh_policy(self):
        source = Path(DEPLOY.__file__).read_text(encoding="utf-8")
        self.assertIn("paramiko.RejectPolicy()", source)
        self.assertNotIn("paramiko.AutoAddPolicy", source)


class JavaPropertiesTests(unittest.TestCase):
    def read(self, text):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.properties"
            path.write_text(text, encoding="utf-8")
            return DEPLOY.properties(path)

    def test_escaped_windows_drive_sdk_path(self):
        values = self.read(r"sdk.dir=C\:\\Users\\Admin\\Android\\Sdk" + "\n")
        self.assertEqual(values["sdk.dir"], r"C:\Users\Admin\Android\Sdk")

    def test_unc_sdk_path_and_unicode_are_not_double_decoded(self):
        text = r"sdk.dir=\\\\host\\share\\\u0410\u043d\u0434\u0440\u043e\u0438\u0434" + "\n"
        values = self.read(text + "literal=Андроид впн\n")
        self.assertEqual(values["sdk.dir"], "\\\\host\\share\\Андроид")
        self.assertEqual(values["literal"], "Андроид впн")

    def test_comments_separators_continuations_and_escaped_keys(self):
        text = ("  # ignored=value\n\t! ignored=also\n"
                " ANDROID_BUILD_TOOLS : 36.0.0\n"
                "plain value\nempty\n"
                "sdk.dir=C\\:\\\\Android\\\n\t\\\\Sdk\n"
                "escaped\\=key=value\\:suffix\n"
                "duplicate=old\nduplicate=new\n")
        values = self.read(text)
        self.assertEqual(values["ANDROID_BUILD_TOOLS"], "36.0.0")
        self.assertEqual(values["plain"], "value")
        self.assertEqual(values["empty"], "")
        self.assertEqual(values["sdk.dir"], r"C:\Android\Sdk")
        self.assertEqual(values["escaped=key"], "value:suffix")
        self.assertEqual(values["duplicate"], "new")
        self.assertEqual(len(values), 6)

    def test_malformed_unicode_escape_fails_closed(self):
        for value in (r"sdk.dir=C\:\\SDK\u12", r"sdk.dir=C\:\\SDK\uXXXX"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "Malformed Java properties"):
                self.read(value)


class ReleaseFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.data = self.root / "data"
        self.downloads = self.root / "downloads"
        self.data.mkdir(); self.downloads.mkdir()
        self.database = self.data / "operator.db"
        self.db = sqlite3.connect(str(self.database))
        self.db.executescript("""
            create table settings(key text primary key,value text not null);
            create table events(ts integer,kind text,device text,ip text,detail text);
            create table device_flags(device text primary key,force_banner text not null default '',
                request_diagnostic integer not null default 0,note text not null default '',updated_at integer not null default 0);
            create table client_keys(device text primary key,key text);
        """)
        PANEL.community.migrate(self.db)
        self.db.execute("insert into client_keys values ('preserved-client','fixture-key')")
        self.now = int(time.time())
        self.db.execute("insert into events values (?,?,?,?,?)", (self.now, "policy", "known-device", "", ""))
        self.metadata = self.write_matrix(self.downloads / VERSION)
        old = self.downloads / OLD_VERSION
        old.mkdir()
        old_meta = {**self.metadata, "version_name": OLD_VERSION, "version_code": OLD_CODE}
        (old / "release-metadata.json").write_text(json.dumps(old_meta), encoding="utf-8")
        self.set_values({"app_version": OLD_VERSION, "app_version_code": str(OLD_CODE),
                         "config_revision": "8", "update_notifications_enabled": "0",
                         "release_schedule_enabled": "1", "release_publish_at": str(self.now - 1),
                         "scheduled_app_version": VERSION, "scheduled_app_version_code": str(CODE),
                         "scheduled_expected_app_version": OLD_VERSION,
                         "scheduled_expected_app_version_code": str(OLD_CODE),
                         "scheduled_release_metadata_sha256": DEPLOY.digest(self.downloads / VERSION / "release-metadata.json")})
        self.patch_downloads = mock.patch.object(PANEL, "DOWNLOAD_ROOT", str(self.downloads))
        self.patch_telegram = mock.patch.object(PANEL, "telegram_send")
        self.patch_webhook = mock.patch.object(PANEL, "webhook_emit")
        self.patch_downloads.start(); self.telegram = self.patch_telegram.start(); self.patch_webhook.start()
        self.remote = {}
        exec(DEPLOY.REMOTE_SOURCE, self.remote)
        self.remote["paths"] = lambda config: (self.data, self.downloads, self.database, {})
        self.remote["preflight"] = lambda config: (self.data, self.downloads, self.database, {})
        self.config = {"version": VERSION, "metadata": self.metadata,
                       "files": {p.name: DEPLOY.digest(p) for p in (self.downloads / VERSION).iterdir()},
                       "expected_version": OLD_VERSION, "expected_code": OLD_CODE,
                       "publish_at": self.now + 3600, "mode": "schedule", "upload_id": "fixture-stage", "notes": "2.0 UI"}
        self.stage = self.data / "release-staging" / self.config["upload_id"]
        self.stage.mkdir(parents=True)
        for name in self.config["files"]:
            (self.stage / name).write_bytes((self.downloads / VERSION / name).read_bytes())

    def tearDown(self):
        self.patch_downloads.stop(); self.patch_telegram.stop(); self.patch_webhook.stop()
        self.db.close(); self.tmp.cleanup()

    def write_matrix(self, folder):
        folder.mkdir()
        artifacts = []
        for abi in DEPLOY.ABIS:
            name = f"QuantumVPN-{VERSION}-operator-debug-{abi}.apk"
            path = folder / name
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(f"lib/{abi}/libbox.so", "fixture native library")
            checksum = DEPLOY.digest(path)
            (folder / (name + ".sha256")).write_text(checksum + "  " + name + "\n", encoding="ascii")
            artifacts.append({"abi": abi, "apk_file": name, "apk_size": path.stat().st_size, "apk_sha256": checksum})
        metadata = {"schema": 2, "version_name": VERSION, "version_code": CODE,
                    "application_id": DEPLOY.PACKAGE, "signer_sha256": SIGNER, "artifacts": artifacts}
        (folder / "release-metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        (folder / "build-info.json").write_text(json.dumps({"version_name": VERSION, "version_code": CODE,
            "artifacts": artifacts, "local_build": True, "git_commit": "a" * 40}), encoding="utf-8")
        return metadata

    def set_values(self, values):
        self.db.executemany("insert or replace into settings values (?,?)", values.items())
        self.db.commit()

    def state(self):
        return dict(self.db.execute("select key,value from settings"))


class GuardedPromotionTests(ReleaseFixture):
    def test_future_schedule_never_promotes(self):
        self.set_values({"release_publish_at": str(self.now + 100)})
        self.assertFalse(PANEL.promote_scheduled_release(self.db, self.now))
        self.assertEqual(self.state()["app_version"], OLD_VERSION)
        self.telegram.assert_not_called()
        self.assertEqual(self.db.execute("select count(*) from community_events where kind='release'").fetchone()[0], 0)

    def test_verified_matrix_promotes_atomically_once(self):
        self.assertTrue(PANEL.promote_scheduled_release(self.db, self.now))
        self.assertEqual(self.state()["app_version"], VERSION)
        self.assertEqual(self.state()["app_version_code"], str(CODE))
        self.assertEqual(self.state()["update_notifications_enabled"], "1")
        self.assertEqual(self.state()["release_schedule_enabled"], "0")
        self.assertIn(VERSION, self.db.execute("select force_banner from device_flags where device='known-device'").fetchone()[0])
        self.assertEqual(self.db.execute("select count(*) from events where kind='release_promoted'").fetchone()[0], 1)
        self.assertFalse(PANEL.promote_scheduled_release(self.db, self.now))
        self.assertEqual(self.telegram.call_count, 1)
        self.assertEqual(self.db.execute("select key from client_keys").fetchone()[0], "fixture-key")
        self.assertEqual(self.db.execute("select count(*) from community_events where kind='release'").fetchone()[0], 1)

    def test_stale_baseline_and_downgrades_defer(self):
        for values in ({"app_version_code": str(OLD_CODE + 1)},
                       {"scheduled_app_version_code": str(OLD_CODE)},
                       {"scheduled_expected_app_version": "5.10.12"}):
            with self.subTest(values=values):
                baseline = self.state()
                self.set_values(values)
                self.assertFalse(PANEL.promote_scheduled_release(self.db, self.now))
                self.assertEqual(self.state()["app_version"], OLD_VERSION)
                self.set_values(baseline)
        self.telegram.assert_not_called()

    def test_legacy_unverified_schedule_fails_closed(self):
        self.set_values({"scheduled_release_metadata_sha256": ""})
        self.assertFalse(PANEL.promote_scheduled_release(self.db, self.now))
        self.assertFalse(PANEL.promote_scheduled_release(self.db, self.now))
        self.assertEqual(self.db.execute("select count(*) from events where kind='release_promotion_deferred'").fetchone()[0], 1)
        self.assertEqual(self.state()["release_schedule_enabled"], "1")

    def test_mutated_apk_checksum_or_manifest_is_not_published(self):
        for name in (self.metadata["artifacts"][0]["apk_file"],
                     self.metadata["artifacts"][1]["apk_file"] + ".sha256", "release-metadata.json"):
            with self.subTest(name=name):
                path = self.downloads / VERSION / name
                original = path.read_bytes()
                path.write_bytes(original + b"changed")
                self.assertFalse(PANEL.promote_scheduled_release(self.db, self.now))
                self.assertEqual(self.state()["app_version"], OLD_VERSION)
                path.write_bytes(original)

    def test_signer_change_fails_even_with_rehashed_manifest(self):
        changed = {**self.metadata, "signer_sha256": "7" * 64}
        path = self.downloads / VERSION / "release-metadata.json"
        path.write_text(json.dumps(changed), encoding="utf-8")
        self.set_values({"scheduled_release_metadata_sha256": DEPLOY.digest(path)})
        self.assertFalse(PANEL.promote_scheduled_release(self.db, self.now))

    def test_banner_insert_error_rolls_back_version_and_all_changes(self):
        self.db.execute("create trigger deny_banner before insert on device_flags begin select raise(abort,'fixture failure'); end")
        self.db.commit()
        original = self.state()
        with self.assertRaises(sqlite3.IntegrityError):
            PANEL.promote_scheduled_release(self.db, self.now)
        self.assertEqual(self.state(), original)
        self.assertEqual(self.db.execute("select count(*) from events where kind='release_promoted'").fetchone()[0], 0)
        self.assertEqual(self.db.execute("select count(*) from community_events where kind='release'").fetchone()[0], 0)
        self.telegram.assert_not_called()

    def test_schedule_changed_during_hashing_is_not_promoted(self):
        before = self.state()
        # A previously absent control added during verification must also CAS-fail.
        changed = {**before, "scheduled_rollout_percent": "25"}
        with mock.patch.object(PANEL, "settings", side_effect=[before, changed]):
            self.assertFalse(PANEL.promote_scheduled_release(self.db, self.now))
        self.assertEqual(self.state(), before)
        self.assertFalse(self.db.in_transaction)
        self.telegram.assert_not_called()

    def test_download_remains_embargoed_after_due_time_when_promotion_failed(self):
        handler = object.__new__(PANEL.App)
        handler.connection_db = lambda: self.db
        handler.reply = mock.Mock(return_value="embargoed")
        name = self.metadata["artifacts"][0]["apk_file"]
        self.assertEqual(handler.download_file(f"/downloads/{VERSION}/{name}", head=True), "embargoed")
        self.assertEqual(handler.reply.call_args.args[:2], (404, "Not found"))

    def test_dot_components_cannot_bypass_pending_release_embargo(self):
        handler = object.__new__(PANEL.App)
        handler.connection_db = mock.Mock(return_value=self.db)
        handler.reply = mock.Mock(return_value="embargoed")
        for artifact in self.metadata["artifacts"]:
            name = artifact["apk_file"]
            for relative in (f"{OLD_VERSION}/../{VERSION}/{name}",
                             f"./{VERSION}/{name}", f"{VERSION}/./{name}"):
                for head in (False, True):
                    with self.subTest(path=relative, head=head):
                        handler.reply.reset_mock()
                        self.assertEqual(handler.download_file("/downloads/" + relative, head=head), "embargoed")
                        self.assertEqual(handler.reply.call_args.args[:2], (404, "Not found"))
        # Reject lexical dot components before any policy/DB lookup.
        handler.connection_db.assert_not_called()

    def test_in_root_symlink_uses_resolved_version_for_embargo(self):
        link = self.downloads / OLD_VERSION / "pending-alias"
        try:
            link.symlink_to(self.downloads / VERSION, target_is_directory=True)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"Directory symlinks unavailable on this platform: {type(error).__name__}")
        handler = object.__new__(PANEL.App)
        handler.connection_db = mock.Mock(return_value=self.db)
        handler.reply = mock.Mock(return_value="embargoed")
        for artifact in self.metadata["artifacts"]:
            name = artifact["apk_file"]
            for head in (False, True):
                with self.subTest(abi=artifact["abi"], head=head):
                    self.assertEqual(handler.download_file(
                        f"/downloads/{OLD_VERSION}/pending-alias/{name}", head=head), "embargoed")
                    self.assertEqual(handler.reply.call_args.args[:2], (404, "Not found"))
        self.assertEqual(handler.connection_db.call_count, len(self.metadata["artifacts"]) * 2)


class DeploymentTransactionTests(ReleaseFixture):
    def local_bundle(self):
        (self.root / "artifacts").mkdir()
        folder = self.root / "artifacts" / VERSION
        self.write_matrix(folder)
        sdk = self.root / "Андроид SDK"
        encoded = str(sdk).replace("\\", "\\\\").replace(":", "\\:")
        (self.root / "local.properties").write_text("sdk.dir=" + encoded + "\n", encoding="utf-8")
        (self.root / "core.properties").write_text("ANDROID_BUILD_TOOLS=36.0.0\n", encoding="utf-8")
        return folder, sdk

    def test_local_verification_uses_decoded_sdk_path(self):
        _, sdk = self.local_bundle()
        checker = mock.Mock()
        original = self.state()
        folder, metadata, files = DEPLOY.verified_local_release(VERSION, SIGNER, root=self.root, checker=checker)
        self.assertEqual(folder, self.root / "artifacts" / VERSION)
        self.assertEqual(metadata["version_code"], CODE)
        self.assertEqual(len(files), 6)
        self.assertEqual(checker.call_count, 2)
        self.assertTrue(all(call.args[3] == sdk / "build-tools" / "36.0.0" for call in checker.call_args_list))
        self.assertEqual(self.state(), original)

    def test_scheduled_local_bundle_requires_exact_verified_publication_epoch(self):
        folder, _ = self.local_bundle()
        path = folder / "build-info.json"
        build = json.loads(path.read_text(encoding="utf-8"))
        expected = int(datetime(2026, 10, 5, 21, tzinfo=timezone.utc).timestamp())
        build["publish_at_epoch"] = expected
        path.write_text(json.dumps(build), encoding="utf-8")
        result = DEPLOY.verified_local_release(
            VERSION, SIGNER, root=self.root, checker=mock.Mock(),
            expected_publish_at=expected)
        self.assertEqual(result[0], folder)
        for different in (expected - 86400, expected + 86400):
            with self.subTest(epoch=different), self.assertRaisesRegex(
                    ValueError, "Publication time differs"):
                DEPLOY.verified_local_release(
                    VERSION, SIGNER, root=self.root, checker=mock.Mock(),
                    expected_publish_at=different)

    def test_scheduled_local_bundle_rejects_missing_or_non_integer_epoch(self):
        folder, _ = self.local_bundle()
        path = folder / "build-info.json"
        build = json.loads(path.read_text(encoding="utf-8"))
        expected = int(datetime(2026, 10, 5, 21, tzinfo=timezone.utc).timestamp())
        for value in (None, str(expected), float(expected), True):
            with self.subTest(epoch=value):
                if value is None:
                    build.pop("publish_at_epoch", None)
                else:
                    build["publish_at_epoch"] = value
                path.write_text(json.dumps(build), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "Publication time differs"):
                    DEPLOY.verified_local_release(
                        VERSION, SIGNER, root=self.root, checker=mock.Mock(),
                        expected_publish_at=expected)

    def test_unscheduled_legacy_local_bundle_does_not_require_publication_epoch(self):
        folder, _ = self.local_bundle()
        result = DEPLOY.verified_local_release(
            VERSION, SIGNER, root=self.root, checker=mock.Mock())
        self.assertEqual(result[0], folder)

    def test_default_staging_never_changes_version_or_public_files(self):
        self.config["mode"] = "stage"
        original = self.state()
        before = set(self.downloads.iterdir())
        result = self.remote["finalize"](self.config)
        self.assertTrue(result["production_unchanged"])
        self.assertFalse(result["notification_signal"])
        self.assertEqual(self.state(), original)
        self.assertEqual(set(self.downloads.iterdir()), before)
        self.assertFalse((self.data / "release-backups").exists())

    def test_schedule_backups_database_and_preserves_current_release(self):
        self.set_values({"release_schedule_enabled": "0"})
        result = self.remote["finalize"](self.config)
        self.assertEqual(result["scheduled"], VERSION)
        self.assertFalse(result["private_staging_retained"])
        self.assertFalse(self.stage.exists())
        self.assertTrue((self.downloads / VERSION / "release-metadata.json").exists())
        self.assertEqual(self.state()["app_version"], OLD_VERSION)
        self.assertEqual(self.state()["update_notifications_enabled"], "1")
        self.assertEqual(self.state()["release_publish_at"], str(self.config["publish_at"]))
        with closing(sqlite3.connect(result["backup"])) as backup:
            values = dict(backup.execute("select key,value from settings"))
            self.assertEqual(values["release_schedule_enabled"], "0")
            self.assertEqual(backup.execute("select key from client_keys").fetchone()[0], "fixture-key")
        self.assertEqual(self.db.execute("select count(*) from events where kind='release_promoted'").fetchone()[0], 0)

    def test_stale_cas_rolls_back_schedule_after_backup(self):
        self.set_values({"app_version_code": str(OLD_CODE + 1), "release_schedule_enabled": "0"})
        original = self.state()
        with self.assertRaisesRegex(ValueError, "CAS"):
            self.remote["schedule"](self.config, self.database, self.data)
        self.assertEqual(self.state(), original)

    def immediate_config(self):
        self.set_values({'release_schedule_enabled': '0'})
        return {**self.config, 'mode': 'promote', 'publish_at': 0}

    def test_immediate_promotion_adds_one_redacted_broadcast_inbox_release(self):
        config = {**self.immediate_config(), 'notes': 'Aurora UI token=fixture-release-secret vless://fixture@vpn.example.invalid'}
        result = self.remote['finalize'](config)
        self.assertEqual(result['promoted'], VERSION)
        self.assertTrue(result['notification_signal'])
        self.assertEqual(self.state()['app_version'], VERSION)
        self.assertEqual(self.state()['app_version_code'], str(CODE))
        event = self.db.execute('select device,kind,title,body,dedupe_key from community_events').fetchone()
        self.assertEqual(event[:3], ('', 'release', 'Обновление QuantumVPN ' + VERSION))
        self.assertEqual(event[4], 'release:' + str(CODE))
        self.assertIn('Aurora UI', event[3])
        self.assertNotIn('fixture-release-secret', event[3])
        self.assertNotIn('vless://', event[3])
        for device in ('0123456789abcdef', 'fedcba9876543210'):
            inbox = PANEL.community.inbox(self.db, device)
            self.assertEqual(inbox['unread'], 1)
            self.assertEqual(inbox['events'][0]['key'], event[4])
        self.assertEqual(self.db.execute('select key from client_keys').fetchone()[0], 'fixture-key')
        with self.assertRaisesRegex(ValueError, 'CAS'):
            self.remote['promote'](config, self.database, self.data, {})
        self.assertEqual(self.db.execute("select count(*) from community_events where kind='release'").fetchone()[0], 1)

    def test_immediate_promotion_reuses_existing_release_dedupe_key(self):
        config = self.immediate_config()
        event_id = PANEL.community.append_event(self.db, 'release', 'Существующее объявление',
                                               'Сохранённое сообщение', 'release:' + str(CODE))
        self.db.commit()
        self.remote['promote'](config, self.database, self.data, {})
        self.assertEqual(self.db.execute('select id,title,body from community_events').fetchall(),
                         [(event_id, 'Существующее объявление', 'Сохранённое сообщение')])

    def test_immediate_inbox_error_rolls_back_version_and_all_signals(self):
        config = self.immediate_config()
        self.db.execute("create trigger deny_release_event before insert on community_events begin select raise(abort,'fixture failure'); end")
        self.db.commit()
        original = self.state()
        with self.assertRaises(sqlite3.IntegrityError):
            self.remote['promote'](config, self.database, self.data, {})
        self.assertEqual(self.state(), original)
        self.assertEqual(self.db.execute('select count(*) from device_flags').fetchone()[0], 0)
        self.assertEqual(self.db.execute("select count(*) from events where kind='release_promoted'").fetchone()[0], 0)
        self.assertEqual(self.db.execute("select count(*) from community_events where kind='release'").fetchone()[0], 0)

    def test_immediate_banner_error_rolls_back_inbox_and_version(self):
        config = self.immediate_config()
        self.db.execute("create trigger deny_banner before insert on device_flags begin select raise(abort,'fixture failure'); end")
        self.db.commit()
        original = self.state()
        with self.assertRaises(sqlite3.IntegrityError):
            self.remote['promote'](config, self.database, self.data, {})
        self.assertEqual(self.state(), original)
        self.assertEqual(self.db.execute("select count(*) from events where kind='release_promoted'").fetchone()[0], 0)
        self.assertEqual(self.db.execute("select count(*) from community_events where kind='release'").fetchone()[0], 0)

    def test_conflicting_schedule_is_preserved(self):
        state = self.state()
        state["scheduled_app_version"] = "5.11.3"
        with self.assertRaisesRegex(ValueError, "Another release"):
            self.remote["check_baseline"](self.config, state)

    def test_same_version_code_rejected(self):
        config = {**self.config, "metadata": {**self.metadata, "version_code": OLD_CODE}}
        self.set_values({"release_schedule_enabled": "0"})
        with self.assertRaisesRegex(ValueError, "strictly increase"):
            self.remote["check_baseline"](config, self.state())

    def test_corrupt_public_artifact_never_overwritten(self):
        path = self.downloads / VERSION / self.metadata["artifacts"][0]["apk_file"]
        path.write_bytes(b"published artifact preserved")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.remote["public_copy"](self.stage, self.downloads, self.config)
        self.assertEqual(path.read_bytes(), b"published artifact preserved")

    def test_apk_identity_is_verified_not_only_json(self):
        artifact = self.metadata["artifacts"][0]
        apk = self.downloads / VERSION / artifact["apk_file"]
        runner = mock.Mock(side_effect=[
            f"package: name='{DEPLOY.PACKAGE}' versionCode='{CODE}' versionName='{VERSION}'",
            "Signer #1 certificate SHA-256 digest: " + SIGNER,
        ])
        DEPLOY.verify_apk(apk, artifact, self.metadata, Path("fixture-build-tools"), runner)
        self.assertEqual(runner.call_count, 2)
        runner = mock.Mock(return_value="package: name='wrong.package' versionCode='1' versionName='1.0.0'")
        with self.assertRaisesRegex(ValueError, "package/version"):
            DEPLOY.verify_apk(apk, artifact, self.metadata, Path("fixture-build-tools"), runner)


if __name__ == "__main__":
    unittest.main()
