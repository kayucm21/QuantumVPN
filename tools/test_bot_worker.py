"""Offline owner-command, privacy, cursor and single-poller regression tests."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock
from urllib.error import HTTPError


class BotWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        with mock.patch.dict(os.environ, {
            'QV_DATA_DIR': self.temp.name, 'QV_DOWNLOAD_ROOT': self.temp.name,
            'QV_ADMIN_USER': 'test', 'QV_ADMIN_PASSWORD': 'test',
            'QV_SUBSCRIPTION_UPSTREAM': 'https://example.invalid/sub',
            'QV_PUBLIC_BASE': 'https://panel.example:8443',
            'QV_DOWNLOAD_BASE': 'https://panel.example:8443',
        }):
            spec = importlib.util.spec_from_file_location('bot_worker_fixture', Path(__file__).with_name('quantumvpn_operator_panel.py'))
            self.panel = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.panel)
        self.db = self.panel.conn()
        self.settings = self.panel.settings(self.db)
        self.settings.update(telegram_chat_id='123456789', telegram_bot_token='123456789:' + 'a' * 35)
        self.now = 1791210000

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def update(self, ident=10, text='/status', sender=123456789, chat=None, **fields):
        return {'update_id': ident, 'message': {
            'date': self.now, 'text': text, 'from': {'id': sender, 'is_bot': False},
            'chat': {'id': sender if chat is None else chat, 'type': 'private'}, **fields}}

    def test_command_cursor_persists_and_replay_does_not_reply(self):
        original = dict(self.db.execute('select key,value from settings'))
        with mock.patch.object(self.panel, 'telegram_send', return_value=True) as send, \
                mock.patch.object(self.panel, 'bot_command_reply', return_value='safe status'):
            first = self.panel.telegram_receive_batch(self.db, self.settings, [self.update()], 'scope', now=self.now)
            second = self.panel.telegram_receive_batch(self.db, self.settings, [self.update()], 'scope', now=self.now + 10)
        self.assertEqual(first, {'next_update': 11, 'replies': 1})
        self.assertEqual(second, {'next_update': 11, 'replies': 0})
        self.assertEqual(send.call_count, 1)
        self.assertEqual(dict(self.db.execute('select key,value from settings')), original)

    def test_unauthorized_forward_bot_group_and_old_commands_silently_consumed(self):
        group = self.update(13)
        group['message']['chat']['type'] = 'group'
        robot = self.update(14)
        robot['message']['from']['is_bot'] = True
        old = self.update(15)
        old['message']['date'] = self.now - 301
        updates = [self.update(10, sender=99), self.update(11, chat=99),
                   self.update(12, forward_origin={'type': 'user'}), group, robot, old,
                   {'update_id': 16, 'edited_message': self.update()['message']}]
        with mock.patch.object(self.panel, 'telegram_send') as send:
            result = self.panel.telegram_receive_batch(self.db, self.settings, updates, 'scope', now=self.now)
        send.assert_not_called()
        self.assertEqual(result, {'next_update': 17, 'replies': 0})

    def test_rate_limited_owner_commands_never_mutate_settings(self):
        rate = {'last': self.now - 10, 'window': self.now, 'count': 29}
        with mock.patch.object(self.panel, 'telegram_send', return_value=True) as send, \
                mock.patch.object(self.panel, 'bot_command_reply', return_value='safe'):
            self.panel.telegram_receive_batch(self.db, self.settings, [self.update(1), self.update(2)], 'scope', rate=rate, now=self.now)
            self.panel.telegram_receive_batch(self.db, self.settings, [self.update(3)], 'scope', rate=rate, now=self.now + 10)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(rate['count'], 30)

    def test_batch_size_and_invalid_ids_are_bounded(self):
        with self.assertRaises(self.panel.TelegramRequestError):
            self.panel.telegram_receive_batch(self.db, self.settings, [self.update()] * 21, 'scope', now=self.now)
        with mock.patch.object(self.panel, 'telegram_send') as send:
            result = self.panel.telegram_receive_batch(self.db, self.settings,
                [{'update_id': True}, {'update_id': -1}, {'update_id': 2**63}, None], 'scope', now=self.now)
        self.assertEqual(result['next_update'], 0)
        send.assert_not_called()

    def test_failed_reply_is_not_replayed_after_restart(self):
        with mock.patch.object(self.panel, 'telegram_send', return_value=False), \
                mock.patch.object(self.panel, 'bot_command_reply', return_value='safe'):
            self.panel.telegram_receive_batch(self.db, self.settings, [self.update()], 'scope', now=self.now)
        with mock.patch.object(self.panel, 'telegram_send') as send:
            self.panel.telegram_receive_batch(self.db, self.settings, [self.update()], 'scope', now=self.now + 10)
        send.assert_not_called()

    def test_get_stable_never_leaks_scheduled_downloads(self):
        self.settings.update(app_version='5.11.2', scheduled_app_version='5.11.3',
                             release_schedule_enabled='1', release_publish_at=str(self.now + 3600))
        for abi in self.panel.REQUIRED_RELEASE_ABIS:
            folder = Path(self.temp.name) / '5.11.2'
            folder.mkdir(exist_ok=True)
            (folder / f'QuantumVPN-5.11.2-operator-debug-{abi}.apk').write_bytes(b'test')
        text = self.panel.bot_command_reply(self.db, self.settings, '/get_stable')
        self.assertIn('/downloads/5.11.2/', text)
        self.assertNotIn('/downloads/5.11.3/', text)
        self.assertNotIn('github.com', text)

    def test_get_stable_respects_maintenance_and_disabled_public_download(self):
        self.settings.update(maintenance='1')
        self.assertNotIn('https://', self.panel.bot_command_reply(self.db, self.settings, '/get_stable'))
        self.settings.update(maintenance='0', public_download_enabled='0')
        self.assertNotIn('https://', self.panel.bot_command_reply(self.db, self.settings, '/get_stable'))

    def test_dev_does_not_leak_embargo_url(self):
        text = self.panel.bot_command_reply(self.db, self.settings, '/get_dev')
        self.assertIn('до срока', text)
        self.assertNotIn('https://', text)

    def test_bot_api_rejects_unsupported_method_and_injected_token(self):
        with mock.patch.object(self.panel, 'build_opener') as opener:
            with self.assertRaises(self.panel.TelegramRequestError):
                self.panel.telegram_bot_api(self.settings, 'deleteWebhook')
            with mock.patch.object(self.panel, 'telegram_bot_token', return_value='bad/token'):
                with self.assertRaises(self.panel.TelegramRequestError):
                    self.panel.telegram_bot_api(self.settings, 'getUpdates')
        opener.assert_not_called()

    def test_bot_api_uses_fixed_host_and_bounded_body(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps({'ok': True, 'result': []}).encode()
        with mock.patch.object(self.panel, 'build_opener') as opener:
            opener.return_value.open.return_value = response
            result = self.panel.telegram_bot_api(self.settings, 'getUpdates', {'limit': 20})
        request = opener.return_value.open.call_args.args[0]
        self.assertTrue(request.full_url.startswith('https://api.telegram.org/bot'))
        self.assertIsInstance(opener.call_args.args[0], self.panel._BotNoRedirect)
        self.assertEqual(response.read.call_args.args[0], 256 * 1024 + 1)
        self.assertEqual(result, [])

    def test_bot_api_suppresses_token_bearing_http_error(self):
        with mock.patch.object(self.panel, 'build_opener') as opener:
            opener.return_value.open.side_effect = HTTPError('https://api.telegram.org/botSECRET/getUpdates', 409, 'SECRET', {}, None)
            with self.assertRaises(self.panel.TelegramRequestError) as caught:
                self.panel.telegram_bot_api(self.settings, 'getUpdates')
        self.assertEqual(caught.exception.code, 409)
        self.assertNotIn('SECRET', str(caught.exception))

    def worker_patches(self, side_effect):
        return (mock.patch.dict(sys.modules, {'fcntl': types.SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=lambda *args: None)}),
                mock.patch.object(self.panel.os, 'O_NOFOLLOW', 0, create=True),
                mock.patch.object(self.panel, 'settings', return_value=self.settings),
                mock.patch.object(self.panel, 'telegram_bot_api', side_effect=side_effect))

    def test_existing_webhook_is_never_removed_or_displaced(self):
        first, second, third, fourth = self.worker_patches([{'url': 'https://example.invalid/hook'}])
        with first, second, third, fourth as api:
            self.panel.telegram_command_worker()
        self.assertEqual(api.call_count, 1)
        self.assertEqual(api.call_args.args[1], 'getWebhookInfo')
        self.assertTrue(self.panel._BOT_RUNTIME['webhook'])
        self.assertFalse(self.panel._BOT_RUNTIME['polling'])

    def test_another_polling_receiver_conflict_stops_without_retry(self):
        first, second, third, fourth = self.worker_patches([{'url': ''}, {'username': 'FixtureBot'}, True, self.panel.TelegramRequestError(409)])
        with first, second, third, fourth as api:
            self.panel.telegram_command_worker()
        self.assertEqual(api.call_count, 4)
        self.assertEqual(self.panel._BOT_RUNTIME['state'], 'conflict')
        scope = api.call_args_list[2].args[2]['scope']
        self.assertEqual(scope, {'type': 'chat', 'chat_id': 123456789})

    def test_empty_successful_poll_is_heartbeat_and_not_notification(self):
        with mock.patch.object(self.panel, 'telegram_send') as send:
            result = self.panel.telegram_receive_batch(self.db, self.settings, [], 'scope', now=self.now)
        self.assertEqual(result, {'next_update': 0, 'replies': 0})
        self.assertEqual(tuple(self.db.execute('select next_update,updated_at from bot_receiver_state').fetchone()), (0, self.now))
        send.assert_not_called()

    def test_qualified_command_requires_the_verified_bot_username(self):
        self.panel._BOT_RUNTIME['username'] = 'FixtureBot'
        with mock.patch.object(self.panel, 'telegram_send', return_value=True) as send, \
                mock.patch.object(self.panel, 'bot_command_reply', return_value='safe'):
            self.panel.telegram_receive_batch(self.db, self.settings, [self.update(text='/status@FixtureBot')], 'scope', now=self.now)
            self.panel.telegram_receive_batch(self.db, self.settings, [self.update(11, text='/status@AnotherBot')], 'scope', now=self.now + 10)
        self.assertEqual(send.call_count, 1)

    def test_xray_process_states_are_normalized_for_status(self):
        with mock.patch.object(self.panel, 'latest_backup_info', return_value={}), \
                mock.patch.object(self.panel, 'cached_service_status', return_value={'operator': 'active', 'rospanel': 'active', 'xray': 'running'}), \
                mock.patch.object(self.panel.subprocess, 'run', return_value=types.SimpleNamespace(stdout='active')):
            snapshot = self.panel.bot_runtime_snapshot()
        self.assertEqual(snapshot['services']['xray'], 'active')

    def test_unavailable_model_catalogue_is_unknown_not_uninstalled(self):
        with mock.patch.object(self.panel, 'qwen_local_status', return_value={'ok': False, 'ready': False}), \
                mock.patch.object(self.panel, 'build_opener') as opener:
            opener.return_value.open.side_effect = OSError('fixture')
            snapshot = self.panel.bot_local_model_snapshot(self.settings)
        self.assertIsNone(snapshot['ready'])
        self.assertIsNone(snapshot['loaded'])
        self.assertIsNone(snapshot['memory_bytes'])

    def test_successful_empty_model_catalogue_can_report_uninstalled(self):
        with mock.patch.object(self.panel, 'qwen_local_status', return_value={'ok': True, 'ready': False}), \
                mock.patch.object(self.panel, 'build_opener') as opener:
            opener.return_value.open.side_effect = OSError('fixture')
            snapshot = self.panel.bot_local_model_snapshot(self.settings)
        self.assertIs(snapshot['ready'], False)

    def test_ai_busy_is_not_another_model_request(self):
        self.panel._AI_RUN_LOCK.acquire()
        try:
            with mock.patch.object(self.panel, '_run_ai_analysis') as inference:
                result = self.panel.run_ai_analysis(self.db, self.settings)
            inference.assert_not_called()
            self.assertEqual(result['status'], 'занят')
        finally:
            self.panel._AI_RUN_LOCK.release()

    def test_ai_lock_released_even_when_analysis_raises(self):
        with mock.patch.object(self.panel, '_run_ai_analysis', side_effect=RuntimeError('fixture')):
            with self.assertRaises(RuntimeError):
                self.panel.run_ai_analysis(self.db, self.settings)
        self.assertFalse(self.panel._AI_RUN_LOCK.locked())


if __name__ == '__main__':
    unittest.main()
