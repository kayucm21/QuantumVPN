"""Delivery correlation and owned temporary-file cleanup regression tests."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import quantumvpn_maintenance as maintenance

class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / 'data'
        self.downloads = self.root / 'downloads'
        self.tmp = self.root / 'tmp'
        for folder in (self.data / 'backups', self.downloads / '5.10.12', self.tmp):
            folder.mkdir(parents=True)
        self.now = 1791287000

    def old(self, folder, name, content=b'data'):
        path = folder / name
        path.write_bytes(content)
        os.utime(path, (self.now - 3 * 86400, self.now - 3 * 86400))
        return path

    def cleanup(self, apply=False):
        return maintenance.cleanup_managed(str(self.data), str(self.downloads), now=self.now,
                                           temp_root=str(self.tmp), apply=apply)

    def test_preview_preserves_then_removes_only_verified_duplicate(self):
        path = self.old(self.tmp, 'QuantumVPN-5.10.12-debug-arm64-v8a.apk')
        permanent = self.old(self.downloads / '5.10.12', 'QuantumVPN-5.10.12-operator-debug-arm64-v8a.apk')
        self.assertEqual(self.cleanup()['eligible_bytes'], 4)
        self.assertTrue(path.exists())
        result = self.cleanup(True)
        self.assertEqual(result['reclaimed_bytes'], 4)
        self.assertFalse(path.exists())
        self.assertTrue(permanent.exists())

    def test_mismatching_or_current_apk_retained(self):
        stale = self.old(self.tmp, 'QuantumVPN-5.10.12-debug-arm64-v8a.apk', b'wrong')
        self.old(self.downloads / '5.10.12', 'QuantumVPN-5.10.12-operator-debug-arm64-v8a.apk', b'other')
        fresh = self.old(self.tmp, 'QuantumVPN-5.10.12-debug-armeabi-v7a.apk')
        os.utime(fresh, (self.now, self.now))
        self.cleanup(True)
        self.assertTrue(stale.exists())
        self.assertTrue(fresh.exists())

    def test_backup_archives_unrelated_files_and_symlinks_retained(self):
        backup = self.old(self.data / 'backups', 'quantum-control-20261005-120000.zip.enc')
        unfinished = self.old(self.data / 'backups', 'quantum-control-20261005-130000.zip')
        unrelated = self.old(self.tmp, 'user-file.txt')
        orphan = self.old(self.data / 'backups', '.operator-20261005-120000-000001.db')
        self.cleanup(True)
        self.assertFalse(orphan.exists())
        for path in (backup, unfinished, unrelated):
            self.assertTrue(path.exists())
        # Replaced path during inspection cannot be removed on an old inode.
        with mock.patch.object(maintenance, '_regular', return_value=None):
            self.assertEqual(self.cleanup(True)['reclaimed_bytes'], 0)

    def test_plaintext_backup_retained_with_corrupt_encrypted_counterpart(self):
        plaintext = self.old(self.data / 'backups', 'quantum-control-20261005-140000.zip')
        encrypted = self.old(self.data / 'backups', plaintext.name + '.enc', b'incomplete ciphertext')
        self.assertEqual(self.cleanup(True)['reclaimed_bytes'], 0)
        self.assertTrue(plaintext.exists())
        self.assertTrue(encrypted.exists())


class ReportIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        with mock.patch.dict(os.environ, {'QV_DATA_DIR': self.temp.name, 'QV_DOWNLOAD_ROOT': self.temp.name,
                                         'QV_ADMIN_USER': 'test', 'QV_ADMIN_PASSWORD': 'test',
                                         'QV_SUBSCRIPTION_UPSTREAM': 'https://example.invalid/sub'}):
            spec = importlib.util.spec_from_file_location('operations_fixture', Path(__file__).with_name('quantumvpn_operator_panel.py'))
            self.panel = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.panel)
        self.db = self.panel.conn()
        self.addCleanup(self.db.close)
        self.s = self.panel.settings(self.db)

    def test_autopilot_labels_do_not_expose_internal_codes(self):
        self.assertEqual(self.panel.autopilot_display({'ai_autopilot_last_status': 'stable', 'ai_autopilot_last_action': 'current_node_healthy'}), ('стабильно', 'текущая нода исправна'))
        self.assertEqual(self.panel.autopilot_display({'ai_autopilot_last_status': '<script>', 'ai_autopilot_last_action': 'bad'}), ('ожидание', 'собираются замеры'))

    def test_cleanup_starts_after_cold_http_reads(self):
        with mock.patch.object(self.panel.time, 'sleep', side_effect=RuntimeError('test stop')) as sleep, \
                mock.patch.object(self.panel.maintenance, 'cleanup_managed') as cleanup:
            with self.assertRaises(RuntimeError):
                self.panel.maintenance_worker()
        sleep.assert_called_once_with(60)
        cleanup.assert_not_called()

    def test_full_report_replies_to_archive_after_recording_delivery(self):
        archive = str(Path(self.temp.name) / 'report.zip.enc')
        with mock.patch.object(self.panel, 'operations_status_snapshot', return_value={'generated_at': 1791287000}) as snapshot, \
                mock.patch.object(self.panel, 'telegram_send_document', return_value=1234) as document, \
                mock.patch.object(self.panel, 'telegram_send', return_value=True) as message:
            result = self.panel.send_backup_report(self.db, self.s, archive)
        self.assertEqual(result, {'archive_sent': True, 'report_sent': True})
        self.assertEqual(message.call_args.kwargs['reply_to_message_id'], 1234)
        self.assertTrue(document.call_args.kwargs['receipt'])
        event = self.db.execute("select detail from audit where action='hourly_backup'").fetchone()
        self.assertTrue(json.loads(event[0])['ok'])
        self.assertEqual(snapshot.call_count, 2)

    def test_failed_document_does_not_claim_report_sent(self):
        with mock.patch.object(self.panel, 'operations_status_snapshot', return_value={}), \
                mock.patch.object(self.panel, 'telegram_send_document', return_value=False), \
                mock.patch.object(self.panel, 'telegram_send') as message:
            result = self.panel.send_backup_report(self.db, self.s, 'missing.zip.enc')
        self.assertFalse(result['archive_sent'])
        self.assertFalse(result['report_sent'])
        message.assert_not_called()

    def test_ai_paraphrases_do_not_spam_telegram(self):
        self.s.update(ai_engine='llama.cpp', ai_telegram_enabled='1', telegram_alerts_enabled='1')
        self.s['ai_last_notification_hash'] = self.panel.bot_status.notification_fingerprint({})
        analysis = {'ok': True, 'status': 'готов', 'advice': '**свежий текст**', 'analysis': {'recommendations': []}}
        with mock.patch.object(self.panel, 'ai_operations_snapshot', return_value={}), \
                mock.patch.object(self.panel, 'network_guard_snapshot', return_value={}), \
                mock.patch.object(self.panel.llama, 'analyze', return_value=analysis), \
                mock.patch.object(self.panel, 'operations_status_snapshot', return_value={}), \
                mock.patch.object(self.panel, 'telegram_send') as send:
            self.panel.run_ai_analysis(self.db, self.s)
            self.panel.run_ai_analysis(self.db, self.s)
        send.assert_not_called()

if __name__ == '__main__':
    unittest.main()
