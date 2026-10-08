import io
import json
import sqlite3
import unittest
from unittest.mock import patch

try:
    import quantumvpn_autopilot as autopilot
    import quantumvpn_ai_journal as ai_journal
    import quantumvpn_llama as llama
except ImportError:
    from tools import quantumvpn_autopilot as autopilot, quantumvpn_llama as llama, quantumvpn_ai_journal as ai_journal


NOW = 1791300000
PRIMARY, RESERVE = '198.51.100.1:443', '198.51.100.2:443'


def stage(target, *, healthy=True, when=NOW, checks=3):
    return {'target': target, 'stage': 'tcp', 'status': 'healthy' if healthy else 'degraded',
            'checked_at': when, 'latency_ms': 20 if healthy else 1000,
            'recovery_checks': checks if healthy else 0,
            'failure_checks': 0 if healthy else checks, 'regression_checks': 0}


def report(*rows, now=NOW):
    return {'generated_at': now, 'stages': list(rows)}


def settings(**changes):
    return {'ai_autopilot_enabled': '1', 'load_balancer_last_target': PRIMARY,
            'nodes_recommended': PRIMARY, 'node_quarantine': '{}', **changes}


class LlamaAdapterTests(unittest.TestCase):
    def valid(self, recommendations=None):
        return {'status': 'ok', 'summary': 'Доступность стабильна.', 'risk': 'Новых сбоев нет.',
                'next_step': 'Продолжаю наблюдение.', 'recommendations': recommendations or []}

    def snapshot(self):
        return {'services': {'cpu_load_pct': 20, 'memory_used_pct': 25},
                'nodes': [{'target': PRIMARY, 'ok': True, 'checked_at': NOW, 'reserve_candidate': True}],
                'token': 'secret-token', 'log': 'run unsafe shell', 'account': 'private-user'}

    def response(self, value=None, **choice_changes):
        choice = {'finish_reason': 'stop', 'message': {'content': json.dumps(value or self.valid(), ensure_ascii=False)}, **choice_changes}
        return io.BytesIO(json.dumps({'choices': [choice], 'usage': {'completion_tokens': 100}}).encode())

    def test_official_local_request_schema_no_proxy_secret_or_thinking(self):
        class Client:
            def open(inner, request, timeout):
                self.assertEqual(request.full_url, 'http://127.0.0.1:11435/v1/chat/completions')
                self.assertEqual(timeout, 90)
                self.body = json.loads(request.data)
                return self.response()
        with patch.object(llama, '_opener', return_value=Client()):
            value = llama.analyze(self.snapshot())
        self.assertEqual(self.body['chat_template_kwargs'], {'enable_thinking': False})
        self.assertEqual(self.body['max_tokens'], 400)
        self.assertEqual(self.body['response_format']['type'], 'json_object')
        self.assertEqual(self.body['response_format']['schema']['additionalProperties'], False)
        schema = self.body['response_format']['schema']['properties']
        self.assertEqual(schema['recommendations']['maxItems'], 0)
        for key in ('summary', 'risk', 'next_step'):
            self.assertEqual(schema[key]['minLength'], 1)
            self.assertEqual(schema[key]['maxLength'], 400)
        self.assertNotIn('secret-token', json.dumps(self.body))
        self.assertNotIn('unsafe shell', json.dumps(self.body))
        self.assertNotIn('private-user', json.dumps(self.body))
        self.assertNotIn(PRIMARY, json.dumps(self.body))
        self.assertEqual(value['model'], llama.MODEL)
        self.assertEqual(value['usage'], {'completion_tokens': 100})

    def test_generation_schema_contains_exact_allowed_pairs_not_cross_product(self):
        allowed = [{'node_id': autopilot.node_id(PRIMARY), 'action': 'observe'},
                   {'node_id': autopilot.node_id(RESERVE), 'action': 'select_reserve'}]
        value = {**self.snapshot(), 'nodes': [{'target': PRIMARY}, {'target': RESERVE}]}
        with patch.object(llama, '_opener') as opener:
            opener.return_value.open.return_value = self.response(self.valid(allowed))
            result = llama.analyze(value, allowed_actions=allowed + [{'node_id': 'invented', 'action': 'observe'}])
        request = json.loads(opener.return_value.open.call_args.args[0].data)
        schema = request['response_format']['schema']['properties']['recommendations']
        self.assertEqual(schema['maxItems'], 4)
        self.assertEqual(schema['items']['enum'], allowed)
        self.assertEqual(result['analysis']['recommendations'], allowed)
        with self.assertRaises(llama.LlamaError) as error:
            llama.validate_analysis(self.valid([{'node_id': allowed[0]['node_id'], 'action': allowed[1]['action']}]), allowed)
        self.assertEqual(error.exception.reason, 'recommendation_not_allowed')

    def test_disables_proxy_and_redirect_handlers(self):
        with patch.object(llama, 'build_opener') as build:
            llama._opener()
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsNone(handlers[1].redirect_request(None, None, None, None))

    def test_refuses_unlisted_node_action_or_commands(self):
        allowed = [{'node_id': autopilot.node_id(PRIMARY), 'action': 'observe'}]
        for proposal in ({'node_id': 'invented', 'action': 'select_reserve'},
                         {'node_id': autopilot.node_id(PRIMARY), 'action': 'exec_shell'},
                         {'node_id': autopilot.node_id(PRIMARY), 'action': 'select_reserve'}):
            with self.assertRaises(llama.LlamaError):
                llama.validate_analysis(self.valid([proposal]), allowed)
        with self.assertRaises(llama.LlamaError):
            llama.validate_analysis({**self.valid(), 'shell': 'reboot'}, allowed)

    def test_ipv6_and_domaincase_action_ids_match_guard(self):
        for raw, canonical in (('2001:db8::1:443', '[2001:db8::1]:443'), ('NODE.EXAMPLE.COM:443', 'node.example.com:443')):
            allowed = [{'node_id': autopilot.node_id(canonical), 'action': 'observe'}]
            snapshot = {'nodes': [{'target': raw, 'ok': True}]}
            with patch.object(llama, '_opener') as opener:
                opener.return_value.open.return_value = self.response(self.valid(allowed))
                value = llama.analyze(snapshot, allowed_actions=allowed)
            self.assertEqual(value['analysis']['recommendations'], allowed)
            self.assertEqual(value['snapshot']['nodes'][0]['node_id'], autopilot.node_id(canonical))

    def test_toolcalls_and_truncation_rejected(self):
        for choice, reason in (({'finish_reason': 'length'}, 'output_truncated'),
                               ({'message': {'content': '{}', 'tool_calls': [{'name': 'shell'}]}}, 'tool_calls')):
            with patch.object(llama, '_opener') as opener:
                opener.return_value.open.return_value = self.response(**choice)
                with self.assertRaises(llama.LlamaError) as error:
                    llama.analyze(self.snapshot())
                self.assertEqual(error.exception.code, 'invalid_response')
                self.assertEqual(error.exception.reason, reason)

    def test_typed_response_reasons_never_contain_raw_output(self):
        cases = (({'choices': []}, 'response_shape'),
                 ({'choices': [{'finish_reason': 'error', 'message': {'content': '{}'}}]}, 'finish_reason'),
                 ({'choices': [{'finish_reason': 'stop', 'message': {'content': {}}}]}, 'content_type'),
                 ({'choices': [{'finish_reason': 'stop', 'message': {'content': 'x' * 8193}}]}, 'content_size'))
        for response, reason in cases:
            with patch.object(llama, '_opener') as opener:
                opener.return_value.open.return_value = io.BytesIO(json.dumps(response).encode())
                with self.assertRaises(llama.LlamaError) as error:
                    llama.analyze(self.snapshot())
            self.assertEqual(error.exception.code, 'invalid_response')
            self.assertEqual(error.exception.reason, reason)
        for raw, reason in ((b'private-secret invalid JSON', 'response_json'),
                            (json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'content': 'private-secret invalid JSON'}}]}).encode(), 'content_json')):
            with patch.object(llama, '_opener') as opener:
                opener.return_value.open.return_value = io.BytesIO(raw)
                with self.assertRaises(llama.LlamaError) as error:
                    llama.analyze(self.snapshot())
            self.assertEqual(error.exception.code, 'unavailable')
            self.assertEqual(error.exception.reason, reason)
            self.assertNotIn('private-secret', str(error.exception))
        for untrusted in ('private-secret', {'private': 'secret'}):
            self.assertEqual(llama.LlamaError('invalid_response', reason=untrusted).reason, 'unknown')

    def test_typed_validation_reasons_preserve_strict_boundaries(self):
        for changed, reason in (({'extra': True}, 'analysis_shape'), ({'status': []}, 'status_value'),
                                ({'summary': {}}, 'text_type'), ({'summary': ''}, 'text_length'),
                                ({'summary': 'я' * 401}, 'text_length'), ({'summary': 'a\nline'}, 'text_controls'),
                                ({'summary': '\ud800'}, 'text_encoding'), ({'recommendations': {}}, 'recommendations_shape'),
                                ({'recommendations': [{'node_id': 'invented', 'action': 'observe'}]}, 'recommendation_not_allowed')):
            with self.assertRaises(llama.LlamaError) as error:
                llama.validate_analysis({**self.valid(), **changed}, [])
            self.assertEqual(error.exception.code, 'invalid_response')
            self.assertEqual(error.exception.reason, reason)
        self.assertEqual(llama.validate_analysis({**self.valid(), 'summary': 'я' * 400}, [])['summary'], 'я' * 400)

    def test_resources_skip_without_request(self):
        value = self.snapshot()
        value['services']['cpu_load_pct'] = 90
        with patch.object(llama, '_opener') as opener:
            with self.assertRaisesRegex(llama.LlamaError, 'resources'):
                llama.analyze(value)
            opener.assert_not_called()

    def test_error_sanitized_and_single_inference_lock(self):
        with patch.object(llama, '_opener', side_effect=RuntimeError('private-token in endpoint')):
            with self.assertRaises(llama.LlamaError) as error:
                llama.analyze(self.snapshot())
        self.assertNotIn('private-token', str(error.exception))
        self.assertEqual(error.exception.reason, 'transport')
        llama._INFERENCE_LOCK.acquire()
        try:
            with self.assertRaisesRegex(llama.LlamaError, 'busy'):
                llama.analyze(self.snapshot())
        finally:
            llama._INFERENCE_LOCK.release()

    def test_sleep_status_does_not_generate(self):
        with patch.object(llama, '_local_json', side_effect=[{'status': 'ok'}, {'is_sleeping': True}]) as read:
            value = llama.local_status()
        self.assertTrue(value['installed'])
        self.assertTrue(value['ready'])
        self.assertFalse(value['resident'])
        self.assertEqual([call.args[0] for call in read.call_args_list], ['/health', '/props'])

    def test_oversized_response_and_malformed_fields_rejected(self):
        with patch.object(llama, '_opener') as opener:
            opener.return_value.open.return_value = io.BytesIO(b'x' * (llama.MAX_RESPONSE + 1))
            with self.assertRaisesRegex(llama.LlamaError, 'too_large') as error:
                llama.analyze(self.snapshot())
            self.assertEqual(error.exception.reason, 'response_size')
        for changed in ({'summary': {'object': True}}, {'status': []}, {'summary': '\ud800'}, {'summary': 'a\nline'}):
            with self.assertRaises(llama.LlamaError):
                llama.validate_analysis({**self.valid(), **changed}, [])


class AutopilotTests(unittest.TestCase):
    def plan(self, evidence, stored=None, now=NOW, proposals=None, nodes=None):
        return autopilot.plan_actions(evidence, nodes or [PRIMARY, RESERVE], stored or settings(), now=now, proposals=proposals)

    def test_repeated_degradation_chooses_registered_reserve_and_quarantines(self):
        value = self.plan(report(stage(PRIMARY, healthy=False), stage(RESERVE)))
        self.assertEqual([action['kind'] for action in value['actions']], ['quarantine_node', 'select_reserve'])
        self.assertEqual(value['changes']['nodes_recommended'], RESERVE)
        self.assertTrue(value['state']['pending'])
        self.assertEqual(json.loads(value['changes']['node_quarantine'])[PRIMARY]['source'], 'quantum_autopilot')

    def test_real_network_guard_report_drives_actions(self):
        from quantumvpn_network_guard import analyze_network_health
        rows = []
        for index in range(9):
            for target in (PRIMARY, RESERVE):
                rows.append({'ts': NOW - (8 - index) * 30, 'target': 'latency:' + target,
                             'ok': target == RESERVE or index < 6, 'latency_ms': 25})
        observed = analyze_network_health(rows, [PRIMARY, RESERVE], now=NOW, current_target=PRIMARY)
        value = self.plan(observed)
        self.assertEqual(value['changes']['nodes_recommended'], RESERVE)
        self.assertEqual([row['kind'] for row in value['actions']], ['quarantine_node', 'select_reserve'])

    def test_same_good_primary_does_not_flip_for_one_low_rtt(self):
        rows = report(stage(PRIMARY), {**stage(RESERVE), 'latency_ms': 1})
        value = self.plan(rows, proposals=[{'node_id': autopilot.node_id(RESERVE), 'action': 'select_reserve'}])
        self.assertEqual(value['changes'], {})
        self.assertEqual(value['status'], 'stable')

    def test_one_failure_cannot_select_healthy_reserve(self):
        value = self.plan(report(stage(PRIMARY, healthy=False, checks=1), stage(RESERVE)),
                          proposals=[{'node_id': autopilot.node_id(RESERVE), 'action': 'select_reserve'}])
        self.assertEqual(value['changes'], {})
        self.assertEqual(value['reason'], 'no_proven_regression')
        self.assertNotIn({'node_id': autopilot.node_id(RESERVE), 'action': 'select_reserve'}, value['allowed_actions'])

    def test_stored_policy_has_floors_and_form_policy_is_strict(self):
        self.assertEqual(autopilot.control_policy({}),
                         {'monitor_interval_seconds': 60, 'action_cooldown_seconds': 900, 'required_checks': 3})
        value = autopilot.control_policy({'ai_monitor_interval_seconds': '0', 'ai_action_cooldown_seconds': 1,
                                          'ai_required_checks': '1'})
        self.assertEqual(value, {'monitor_interval_seconds': 60, 'action_cooldown_seconds': 300, 'required_checks': 3})
        maximum = autopilot.control_policy(dict.fromkeys(autopilot.POLICY_FIELDS, 9999999999))
        self.assertEqual(maximum, {'monitor_interval_seconds': 3600, 'action_cooldown_seconds': 86400, 'required_checks': 10})
        for malformed in (True, False, 0.001, '0.001', '1e3', '-1', 'exec reboot', [], {}):
            self.assertEqual(autopilot.control_policy({'ai_action_cooldown_seconds': malformed})['action_cooldown_seconds'], 900)
            with self.assertRaises(ValueError):
                autopilot.validate_control_policy({'ai_action_cooldown_seconds': malformed})
        for unsafe in ('1', '299', '86401'):
            with self.assertRaises(ValueError):
                autopilot.validate_control_policy({'ai_action_cooldown_seconds': unsafe})
        self.assertEqual(autopilot.validate_control_policy({'ai_monitor_interval_seconds': '120'}),
                         {'ai_monitor_interval_seconds': '120', 'ai_action_cooldown_seconds': '900', 'ai_required_checks': '3'})

    def test_monitor_interval_preserves_pending_verification_and_manual_override_is_immediate(self):
        stored, initial = self.applied()
        now = NOW + 1
        value = self.plan(report(stage(PRIMARY, when=now), stage(RESERVE, when=now), now=now), stored, now)
        self.assertEqual(value['reason'], 'monitor_interval')
        self.assertEqual(value['state']['pending'], initial['state']['pending'])
        self.assertEqual(value['state']['last_decision_at'], NOW)
        stored['nodes_recommended'] = 'manual-choice'
        value = self.plan(report(stage(PRIMARY, when=now), stage(RESERVE, when=now), now=now), stored, now)
        self.assertEqual(value['reason'], 'manual_override')
        self.assertIsNone(value['state']['pending'])
        self.assertEqual(value['changes'], {})

    def test_configured_cooldown_and_check_series_are_enforced(self):
        evidence = report(stage(PRIMARY, healthy=False), stage(RESERVE))
        stored = settings(ai_action_cooldown_seconds='300',
                          ai_autopilot_state=json.dumps({'schema': 1, 'last_action_at': NOW - 299}))
        self.assertEqual(self.plan(evidence, stored)['reason'], 'cooldown')
        stored['ai_autopilot_state'] = json.dumps({'schema': 1, 'last_action_at': NOW - 300})
        self.assertTrue(self.plan(evidence, stored)['changes'])
        stored = settings(ai_required_checks='5')
        self.assertEqual(self.plan(evidence, stored)['changes'], {})
        value = self.plan(report(stage(PRIMARY, healthy=False, checks=5), stage(RESERVE, checks=5)), stored)
        self.assertTrue(value['changes'])
        stored = {**stored, **value['changes'], 'ai_autopilot_state': json.dumps(value['state'])}
        for offset in (60, 120, 180, 240, 300):
            now = NOW + offset
            value = self.plan(report(stage(PRIMARY, healthy=False, when=now, checks=5),
                                     stage(RESERVE, when=now, checks=5), now=now), stored, now)
            self.assertEqual(value['status'], 'verified' if offset == 300 else 'verifying')
            stored['ai_autopilot_state'] = json.dumps(value['state'])

    def test_maximum_monitor_interval_can_complete_post_change_checks(self):
        stored = settings(ai_monitor_interval_seconds='3600')
        value = self.plan(report(stage(PRIMARY, healthy=False), stage(RESERVE)), stored)
        stored = {**stored, **value['changes'], 'ai_autopilot_state': json.dumps(value['state'])}
        for offset in (3600, 7200, 10800):
            now = NOW + offset
            value = self.plan(report(stage(PRIMARY, healthy=False, when=now), stage(RESERVE, when=now), now=now), stored, now)
            self.assertEqual(value['status'], 'verified' if offset == 10800 else 'verifying')
            stored['ai_autopilot_state'] = json.dumps(value['state'])

    def test_no_single_node_lockout_or_unregistered_fabrication(self):
        evidence = report(stage(PRIMARY, healthy=False), stage(RESERVE))
        value = self.plan(evidence, nodes=[PRIMARY])
        self.assertEqual(value['changes'], {})
        self.assertEqual(value['reason'], 'no_proven_healthy_reserve')
        value = self.plan(evidence, proposals=[{'node_id': 'invented', 'action': 'select_reserve'}])
        self.assertEqual(value['changes']['nodes_recommended'], RESERVE)

    def test_stale_future_and_one_failure_cannot_change_nodes(self):
        for evidence in (report(stage(PRIMARY, healthy=False, checks=1)),
                         report(stage(PRIMARY, healthy=False, when=NOW - 301), stage(RESERVE, when=NOW - 301)),
                         report(stage(PRIMARY, healthy=False, when=NOW + 1), stage(RESERVE, when=NOW + 1)),
                         report(stage(PRIMARY, healthy=False), stage(RESERVE), now=NOW - 301)):
            self.assertEqual(self.plan(evidence)['changes'], {})

    def test_manual_exclusions_respected_and_unowned_quarantine_preserved(self):
        evidence = report(stage(PRIMARY, healthy=False), stage(RESERVE))
        for stored in (settings(node_drains=json.dumps({RESERVE: {'note': 'maintenance'}})),
                       settings(nodes_forbidden=RESERVE), settings(nodes_forbidden='198.51.100.2')):
            self.assertEqual(self.plan(evidence, stored)['changes'], {})
        old = {'203.0.113.9:443': {'until': NOW + 500, 'source': 'another_controller'}}
        value = self.plan(evidence, settings(node_quarantine=json.dumps(old)))
        self.assertEqual(json.loads(value['changes']['node_quarantine'])['203.0.113.9:443'], old['203.0.113.9:443'])

    def test_recovers_only_own_automatic_exclusion(self):
        old = {PRIMARY: {'until': NOW + 900, 'source': 'quantum_autopilot'}, RESERVE: {'until': NOW + 900, 'source': 'operator'}}
        value = self.plan(report(stage(PRIMARY), stage(RESERVE)), settings(node_quarantine=json.dumps(old)))
        self.assertEqual(value['actions'], [{'kind': 'recover_node', 'target': PRIMARY}])
        self.assertEqual(json.loads(value['changes']['node_quarantine']), {RESERVE: old[RESERVE]})

    def test_quarantined_foreign_reserve_does_not_allow_sole_node_lockout(self):
        old = {RESERVE: {'until': NOW + 900, 'source': 'other_controller'}}
        value = self.plan(report(stage(PRIMARY, healthy=False), stage(RESERVE)), settings(node_quarantine=json.dumps(old)))
        self.assertEqual(value['changes'], {})
        self.assertNotIn({'node_id': autopilot.node_id(RESERVE), 'action': 'select_reserve'}, value['allowed_actions'])

    def applied(self):
        old = settings()
        value = self.plan(report(stage(PRIMARY, healthy=False), stage(RESERVE)), old)
        return {**old, **value['changes'], 'ai_autopilot_state': json.dumps(value['state'])}, value

    def test_rolls_back_regressed_reserve_after_primary_recovery(self):
        stored, initial = self.applied()
        now = NOW + 120
        value = self.plan(report(stage(PRIMARY, when=now), stage(RESERVE, healthy=False, when=now), now=now), stored, now)
        self.assertEqual(value['actions'], [{'kind': 'rollback', 'target': PRIMARY}])
        self.assertEqual(value['changes'], initial['expected'])
        self.assertIsNone(value['state']['pending'])

    def test_manual_changes_cancel_old_rollback(self):
        stored, _ = self.applied()
        stored['nodes_recommended'] = 'manual-choice'
        now = NOW + 120
        value = self.plan(report(stage(PRIMARY, when=now), stage(RESERVE, healthy=False, when=now), now=now), stored, now)
        self.assertEqual(value['changes'], {})
        self.assertEqual(value['reason'], 'manual_override')

    def test_three_distinct_post_change_checks_required_not_replayed_report(self):
        stored, _ = self.applied()
        for offset in (60, 60, 120):
            now = NOW + offset
            value = self.plan(report(stage(PRIMARY, healthy=False, when=now), stage(RESERVE, when=now), now=now), stored, now)
            self.assertEqual(value['status'], 'verifying')
            stored['ai_autopilot_state'] = json.dumps(value['state'])
        now = NOW + 180
        value = self.plan(report(stage(PRIMARY, healthy=False, when=now), stage(RESERVE, when=now), now=now), stored, now)
        self.assertEqual(value['status'], 'verified')
        self.assertEqual(value['changes'], {})

    def test_cooldown_blocks_churn_but_not_validated_rollback(self):
        stored = settings(ai_autopilot_state=json.dumps({'schema': 1, 'last_action_at': NOW - 60}))
        value = self.plan(report(stage(PRIMARY, healthy=False), stage(RESERVE)), stored)
        self.assertEqual(value['changes'], {})
        self.assertEqual(value['reason'], 'cooldown')

    def test_disabled_no_actions(self):
        value = self.plan(report(stage(PRIMARY, healthy=False), stage(RESERVE)), settings(ai_autopilot_enabled='0'))
        self.assertEqual(value['status'], 'disabled')
        self.assertEqual(value['changes'], {})

    def db(self):
        db = sqlite3.connect(':memory:')
        db.execute('create table settings(key text primary key,value text not null)')
        db.execute('create table events(ts integer,kind text,device text,ip text,detail text)')
        db.executemany('insert into settings values (?,?)', list(settings().items()))
        db.execute('insert into settings values (?,?)', ('root_password', 'protected'))
        db.commit()
        self.addCleanup(db.close)
        return db

    def test_executor_atomic_settings_audit_and_outer_transaction(self):
        db = self.db()
        db.execute('insert into settings values (?,?)', ('outer_write', 'keep'))
        value = autopilot.execute(db, report(stage(PRIMARY, healthy=False), stage(RESERVE)), [PRIMARY, RESERVE], now=NOW)
        self.assertTrue(db.in_transaction)
        self.assertEqual(db.execute('select value from settings where key=?', ('nodes_recommended',)).fetchone()[0], RESERVE)
        events = db.execute('select kind,detail from events order by rowid').fetchall()
        self.assertEqual([row[0] for row in events], ['ai_autopilot_plan', 'ai_autopilot_quarantine_node',
                                                   'ai_autopilot_select_reserve', 'ai_autopilot_decision'])
        self.assertEqual(json.loads(events[0][1])['phase'], 'planned')
        self.assertEqual(json.loads(events[-1][1])['phase'], 'applied')
        self.assertEqual(ai_journal.read_entries(db), [value['journal']])
        self.assertNotIn(PRIMARY, json.dumps(events))
        self.assertNotIn(RESERVE, json.dumps(events))
        self.assertEqual(db.execute('select value from settings where key=?', ('root_password',)).fetchone()[0], 'protected')
        db.rollback()
        self.assertEqual(db.execute('select value from settings where key=?', ('nodes_recommended',)).fetchone()[0], PRIMARY)
        self.assertIsNone(db.execute('select value from settings where key=?', ('outer_write',)).fetchone())

    def test_event_failure_rolls_back_all_autopilot_writes(self):
        db = self.db()
        db.execute("create trigger block_audit before insert on events begin select raise(abort,'audit unavailable'); end")
        with self.assertRaises(sqlite3.IntegrityError):
            autopilot.execute(db, report(stage(PRIMARY, healthy=False), stage(RESERVE)), [PRIMARY, RESERVE], now=NOW)
        self.assertEqual(db.execute('select value from settings where key=?', ('nodes_recommended',)).fetchone()[0], PRIMARY)
        self.assertIsNone(db.execute('select value from settings where key=?', ('ai_autopilot_state',)).fetchone())

    def test_executor_refuses_a_change_whose_before_state_cannot_be_rolled_back(self):
        db = self.db()
        db.execute("update settings set value=? where key='nodes_recommended'", ('x' * 8193,))
        with self.assertRaisesRegex(ValueError, 'rollback limits'):
            autopilot.execute(db, report(stage(PRIMARY, healthy=False), stage(RESERVE)), [PRIMARY, RESERVE], now=NOW)
        self.assertEqual(db.execute("select value from settings where key='nodes_recommended'").fetchone()[0], 'x' * 8193)
        self.assertEqual(db.execute('select count(*) from events').fetchone()[0], 0)

    def test_executor_rechecks_freeze_manual_limits_and_policy_before_action(self):
        original = autopilot.plan_actions
        for key, changed in (('ai_autopilot_enabled', '0'), ('nodes_forbidden', RESERVE),
                             ('node_drains', json.dumps({RESERVE: {}})), ('ai_monitor_interval_seconds', '120'),
                             ('ai_action_cooldown_seconds', '1800'), ('ai_autopilot_state', '{}')):
            with self.subTest(key=key):
                db = self.db()
                def changed_during_plan(*args, **kwargs):
                    result = original(*args, **kwargs)
                    db.execute('insert into settings values (?,?) on conflict(key) do update set value=excluded.value', (key, changed))
                    return result
                with patch.object(autopilot, 'plan_actions', side_effect=changed_during_plan):
                    with self.assertRaisesRegex(RuntimeError, 'changed during decision'):
                        autopilot.execute(db, report(stage(PRIMARY, healthy=False), stage(RESERVE)), [PRIMARY, RESERVE], now=NOW)
                self.assertEqual(db.execute('select value from settings where key=?', ('nodes_recommended',)).fetchone()[0], PRIMARY)
                self.assertEqual(db.execute('select count(*) from events').fetchone()[0], 0)

    def test_audited_plan_freeze_cancels_action_and_disabled_executor_preserves_state(self):
        db = self.db()
        db.execute("create trigger operator_freeze after insert on events when new.kind='ai_autopilot_plan' begin update settings set value='0' where key='ai_autopilot_enabled'; end")
        with self.assertRaisesRegex(RuntimeError, 'changed during decision'):
            autopilot.execute(db, report(stage(PRIMARY, healthy=False), stage(RESERVE)), [PRIMARY, RESERVE], now=NOW)
        self.assertEqual(db.execute('select value from settings where key=?', ('nodes_recommended',)).fetchone()[0], PRIMARY)
        db.execute('drop trigger operator_freeze')
        stored, initial = self.applied()
        db.executemany('insert into settings values (?,?) on conflict(key) do update set value=excluded.value', list(stored.items()))
        db.execute("update settings set value='0' where key='ai_autopilot_enabled'")
        value = autopilot.execute(db, report(stage(PRIMARY), stage(RESERVE)), [PRIMARY, RESERVE], now=NOW + 60)
        self.assertEqual(value['status'], 'disabled')
        self.assertEqual(json.loads(db.execute("select value from settings where key='ai_autopilot_state'").fetchone()[0]), initial['state'])
        self.assertEqual(db.execute('select count(*) from events').fetchone()[0], 0)

    def test_repeated_executor_call_does_not_write_state_or_journal_within_interval(self):
        db = self.db()
        value = autopilot.execute(db, report(stage(PRIMARY), stage(RESERVE)), [PRIMARY, RESERVE], now=NOW)
        self.assertEqual(value['status'], 'stable')
        state = db.execute("select value from settings where key='ai_autopilot_state'").fetchone()[0]
        value = autopilot.execute(db, report(stage(PRIMARY), stage(RESERVE)), [PRIMARY, RESERVE], now=NOW + 1)
        self.assertEqual(value['reason'], 'monitor_interval')
        self.assertEqual(db.execute("select value from settings where key='ai_autopilot_state'").fetchone()[0], state)
        self.assertEqual(db.execute('select count(*) from events').fetchone()[0], 1)


class DecisionJournalTests(unittest.TestCase):
    def test_readable_journal_is_deterministic_redacted_and_bounded(self):
        evidence = report({**stage(PRIMARY, healthy=False), 'detail': 'token secret-user unsafe-shell'},
                          {**stage(RESERVE), 'subscription': 'private-vless://secret'})
        stored = settings(root_password='private-password', node_drains='{"secret-account":{}}')
        value = autopilot.plan_actions(evidence, [PRIMARY, RESERVE], stored, now=NOW,
                                       proposals=[{'node_id': autopilot.node_id(RESERVE), 'action': 'select_reserve', 'text': 'opaque model'}])
        entry = value['journal']
        text = ai_journal.render_entry(entry)
        self.assertEqual(text, ai_journal.render_entry(entry))
        self.assertIn('Действие:', text)
        self.assertIn('Доказательства:', text)
        self.assertIn('До:', text)
        self.assertIn('После:', text)
        self.assertIn('Откат: доступен', text)
        self.assertIn('активные VPN-сеансы не переключаются', text)
        encoded = json.dumps(entry, ensure_ascii=False) + text
        for secret in (PRIMARY, RESERVE, 'secret-user', 'unsafe-shell', 'private-vless', 'private-password', 'secret-account', 'opaque model'):
            self.assertNotIn(secret, encoded)
        self.assertLess(len(json.dumps(entry)), ai_journal.MAX_ENTRY_BYTES)

    def test_persisted_unknown_text_and_malformed_types_are_not_rendered(self):
        value = {'reason': [], 'status': {'secret': True}, 'phase': 'secret-phase', 'why': 'secret-prose',
                 'action': 'exec secret-command', 'actions': [{'kind': [], 'node_id': 'secret-target'}],
                 'evidence': [{'node_id': autopilot.node_id(PRIMARY), 'stage': 'tcp', 'status': 'healthy',
                               'latency_ms': 2**10000, 'detail': 'secret-detail'}],
                 'before': {'recommendations': ['private-vless://secret'], 'selected_node': PRIMARY},
                 'after': {'token': 'secret-token'}, 'rollback_available': 'yes'}
        clean = ai_journal.sanitize_entry(value)
        self.assertFalse(clean['rollback_available'])
        self.assertIsNone(clean['evidence'][0]['latency_ms'])
        rendered = ai_journal.render_entry(value)
        self.assertNotIn('secret', rendered)
        self.assertNotIn(PRIMARY, rendered)

    def test_journal_uses_latest_stage_measurement_like_planner(self):
        old = stage(PRIMARY, healthy=False, when=NOW - 60)
        fresh = stage(PRIMARY)
        value = autopilot.plan_actions(report(old, fresh, stage(RESERVE)), [PRIMARY, RESERVE], settings(), now=NOW)
        facts = [row for row in value['journal']['evidence'] if row['node_id'] == autopilot.node_id(PRIMARY)]
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]['status'], 'healthy')
        self.assertEqual(value['journal']['phase'], 'observed')

    def test_reader_ignores_invalid_or_oversized_entries_and_enforces_limit(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.execute('create table events(ts integer,kind text,device text,ip text,detail text)')
        clean = ai_journal.sanitize_entry({'at': NOW, 'reason': 'current_node_healthy'})
        for detail in (json.dumps(clean), '{bad json', 'x' * (ai_journal.MAX_ENTRY_BYTES + 1), json.dumps({'schema': 2})):
            db.execute('insert into events values (?,?,?,?,?)', (NOW, 'ai_autopilot_decision', '', '', detail))
        self.assertEqual(ai_journal.read_entries(db), [clean])
        self.assertEqual(ai_journal.read_entries(db, limit=1), [])


if __name__ == '__main__':
    unittest.main()
