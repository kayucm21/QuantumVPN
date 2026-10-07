"""Measured registered-node automation, no shell or topology fabrication.

The executor changes only panel recommendation and automatic-quarantine
settings. Existing sessions, server ports, keys and subscription contents are
not restarted or rewritten. Each change stores compare-and-swap rollback data;
manual drains/forbidden targets always take precedence over model proposals.
"""
import hashlib
import json
import re
from itertools import islice

try:
    from quantumvpn_network_guard import configured_node_targets
    import quantumvpn_ai_journal as ai_journal
except ImportError:
    from tools.quantumvpn_network_guard import configured_node_targets
    from tools import quantumvpn_ai_journal as ai_journal

MAX_NODES = 24
MAX_STATE_BYTES = 32768
FRESHNESS = 300
COOLDOWN = 900
QUARANTINE_TTL = 1800
POLICY_FIELDS = {
    'ai_monitor_interval_seconds': (60, 60, 3600),
    'ai_action_cooldown_seconds': (COOLDOWN, 300, 86400),
    'ai_required_checks': (3, 3, 10),
}
SETTINGS_KEYS = ('ai_autopilot_enabled', 'ai_autopilot_state', 'node_quarantine', 'node_drains',
                 'nodes_forbidden', 'nodes_recommended', 'load_balancer_last_target', 'load_balancer_last_decision',
                 'node_map_config', *POLICY_FIELDS)
MUTABLE_KEYS = {'node_quarantine', 'nodes_recommended', 'load_balancer_last_target', 'load_balancer_last_decision'}


def _stamp(value):
    return value if type(value) is int and 0 <= value <= 2**40 else 0


def _policy_integer(value):
    if type(value) is int:
        return value
    if isinstance(value, str) and re.fullmatch(r'[0-9]{1,10}', value):
        return int(value)
    return None


def control_policy(settings):
    """Safe stored policy: milliseconds and malformed values cannot lower floors."""
    settings = settings if isinstance(settings, dict) else {}
    result = {}
    for key, (default, minimum, maximum) in POLICY_FIELDS.items():
        value = _policy_integer(settings.get(key))
        result[key.removeprefix('ai_')] = default if value is None else max(minimum, min(maximum, value))
    return result


def validate_control_policy(settings):
    """Validate form values before saving; never accept fractions, booleans or code."""
    if not isinstance(settings, dict):
        raise ValueError('Control policy must be a mapping')
    result = {}
    for key, (default, minimum, maximum) in POLICY_FIELDS.items():
        value = _policy_integer(settings.get(key, default))
        if value is None or not minimum <= value <= maximum:
            raise ValueError(key + ' must be an integer in ' + str(minimum) + '..' + str(maximum))
        result[key] = str(value)
    return result


def _mapping(value):
    if isinstance(value, str):
        if len(value) > MAX_STATE_BYTES:
            return {}
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return {}
    return value if isinstance(value, dict) else {}


def node_id(target):
    return 'node_' + hashlib.sha256(target.encode('utf-8')).hexdigest()[:16]


def _manual_exclusions(settings, registered):
    drained = set(_mapping(settings.get('node_drains'))) & set(registered)
    forbidden = settings.get('nodes_forbidden', '')
    parts = {part.strip() for part in forbidden.split(',')} if isinstance(forbidden, str) else set()
    return drained | {target for target in registered if target in parts or target.rpartition(':')[0] in parts}


def _evidence(report, registered, now, required_checks=3):
    reports = report.get('stages') if isinstance(report.get('stages'), list) else []
    stages = {}
    for raw in islice(reports, MAX_NODES * 3):
        if not isinstance(raw, dict) or raw.get('target') not in registered or raw.get('stage') not in ('dns', 'tcp', 'tls'):
            continue
        stamp = _stamp(raw.get('checked_at'))
        if not stamp or stamp > now or now - stamp > FRESHNESS:
            continue
        stage = raw['stage']
        key = (raw['target'], stage)
        if key not in stages or stamp > _stamp(stages[key].get('checked_at')):
            stages[key] = raw
    healthy, degraded = {}, {}
    for target in registered:
        tcp = stages.get((target, 'tcp'), {})
        tests = [stages[(target, stage)] for stage in ('dns', 'tcp', 'tls') if (target, stage) in stages]
        delay = tcp.get('latency_ms')
        if (tcp.get('status') == 'healthy' and _stamp(tcp.get('recovery_checks')) >= required_checks
                and type(delay) in (int, float) and 0 <= delay <= 600000
                and all(item.get('status') == 'healthy' for item in tests)):
            healthy[target] = tcp
        if (tcp.get('status') == 'degraded'
                and max(_stamp(tcp.get('failure_checks')), _stamp(tcp.get('regression_checks'))) >= required_checks):
            degraded[target] = tcp
    return healthy, degraded


def _state(settings, now):
    raw = _mapping(settings.get('ai_autopilot_state'))
    if raw.get('schema') != 1:
        raw = {}
    # Persist only our bounded typed state, never model prose or unknown keys.
    state = {'schema': 1, 'last_action_at': min(now, _stamp(raw.get('last_action_at'))),
             'last_decision_at': min(now, _stamp(raw.get('last_decision_at'))), 'pending': None, 'history': []}
    pending = raw.get('pending')
    if isinstance(pending, dict):
        before, after = pending.get('before'), pending.get('after')
        if (isinstance(before, dict) and isinstance(after, dict) and set(before) == set(after)
                and set(before) <= MUTABLE_KEYS and len(before) <= 4
                and all(isinstance(v, str) and len(v) <= 8192 for v in [*before.values(), *after.values()])
                and isinstance(pending.get('target'), str) and len(pending['target']) <= 253):
            state['pending'] = {'since': _stamp(pending.get('since')), 'target': pending['target'],
                                'previous_target': pending.get('previous_target') if isinstance(pending.get('previous_target'), str) else '',
                                'verify_cursor': min(now, _stamp(pending.get('verify_cursor'))),
                                'verify_checks': min(10, _stamp(pending.get('verify_checks'))),
                                'before': before, 'after': after}
    history = raw.get('history')
    for entry in history[-12:] if isinstance(history, list) else []:
        if not isinstance(entry, dict) or entry.get('kind') not in ('select_reserve', 'quarantine_node', 'recover_node', 'rollback', 'verified', 'manual_override'):
            continue
        if isinstance(entry.get('target'), str) and len(entry['target']) <= 253:
            state['history'].append({'at': _stamp(entry.get('at')), 'kind': entry['kind'], 'target': entry['target']})
    return state


def _dump(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def plan_actions(report, configured_nodes, settings, *, now, proposals=None):
    """Return a typed plan plus a deterministic explanation of its evidence."""
    settings = settings if isinstance(settings, dict) else {}
    registered = configured_node_targets(configured_nodes)
    report = report if isinstance(report, dict) else {}
    result = _plan_actions(report, registered, settings, now=now, proposals=proposals)
    result['journal'] = ai_journal.build_entry(result, report, registered, settings,
                                              phase='planned' if result['changes'] else 'observed')
    return result


def _plan_actions(report, registered, settings, *, now, proposals=None):
    """Return checked automatic settings changes and durable rollback state.

    An unavailable model is not an unavailable monitor: the same evidence-based
    planner runs without proposals. A model may choose only an already healthy
    reserve; it cannot bypass repeated measurements, cooldown or manual limits.
    """
    now = _stamp(now)
    if not now:
        raise ValueError('Positive observation time required')
    policy = control_policy(settings)
    state = _state(settings, now)
    empty = {'schema': 1, 'generated_at': now, 'actions': [], 'changes': {}, 'expected': {},
             'state': state, 'policy': policy, 'status': 'observing', 'reason': 'insufficient_data', 'allowed_actions': []}
    if settings.get('ai_autopilot_enabled') not in ('1', True, 1):
        return {**empty, 'status': 'disabled', 'reason': 'operator_disabled'}
    if not registered:
        return {**empty, 'reason': 'no_registered_nodes'}
    pending = state['pending']
    # Manual changes and an operator freeze are honoured even between checks.
    if pending and any(settings.get(key, '') != value for key, value in pending['after'].items()):
        state['pending'] = None
        state['history'] = (state['history'] + [{'at': now, 'kind': 'manual_override', 'target': pending['target']}])[-12:]
        state['last_decision_at'] = now
        return {**empty, 'reason': 'manual_override'}
    if state['last_decision_at'] and now - state['last_decision_at'] < policy['monitor_interval_seconds']:
        return {**empty, 'status': 'verifying' if pending else 'observing', 'reason': 'monitor_interval'}
    state['last_decision_at'] = now
    generated = _stamp(report.get('generated_at'))
    if not generated or generated > now or now - generated > FRESHNESS:
        return {**empty, 'reason': 'stale_report'}
    blocked = _manual_exclusions(settings, registered)
    healthy, degraded = _evidence(report, registered, now, policy['required_checks'])
    healthy = {target: value for target, value in healthy.items() if target not in blocked}
    degraded = {target: value for target, value in degraded.items() if target not in blocked}
    # Preserve quarantine records owned by other controllers and retired
    # registrations. Only explicitly owned registered entries may be removed.
    quarantine = dict(_mapping(settings.get('node_quarantine')))
    current = settings.get('load_balancer_last_target', '')
    if current not in registered:
        recommended = settings.get('nodes_recommended', '')
        current = next((target.strip() for target in recommended.split(',') if target.strip() in registered), '') if isinstance(recommended, str) else ''
    own_quarantine = {target for target, value in quarantine.items()
                      if target in registered and isinstance(value, dict) and value.get('source') == 'quantum_autopilot'}
    available_healthy = {target: value for target, value in healthy.items()
                         if target in own_quarantine or not isinstance(quarantine.get(target), dict)
                         or _stamp(quarantine[target].get('until')) <= now}
    current_entry = quarantine.get(current)
    current_excluded = isinstance(current_entry, dict) and _stamp(current_entry.get('until')) > now
    may_reselect = not current or current in blocked or current in degraded or current_excluded
    allowed = [{'node_id': node_id(target), 'action': 'observe'} for target in registered]
    allowed += [{'node_id': node_id(target), 'action': 'recover_node'} for target in sorted(healthy.keys() & own_quarantine)]
    allowed += [{'node_id': node_id(target), 'action': 'select_reserve'} for target in sorted(available_healthy) if target != current and may_reselect]
    allowed += [{'node_id': node_id(target), 'action': 'quarantine_node'} for target in sorted(degraded)
                if any(other != target for other in available_healthy) and target not in quarantine]
    empty['allowed_actions'] = allowed
    if pending:
        target, previous = pending['target'], pending['previous_target']
        previous_entry = quarantine.get(previous)
        previous_blocked = (isinstance(previous_entry, dict) and _stamp(previous_entry.get('until')) > now
                            and previous_entry.get('source') != 'quantum_autopilot')
        rollback_quarantine = _mapping(pending['before'].get('node_quarantine', settings.get('node_quarantine')))
        rollback_entry = rollback_quarantine.get(previous)
        rollback_blocked = isinstance(rollback_entry, dict) and _stamp(rollback_entry.get('until')) > now
        if (target in degraded and previous in healthy and not previous_blocked and not rollback_blocked
                and _stamp(degraded[target].get('checked_at')) > pending['since']):
            # Revert only the keys that are still exactly ours. Previous target
            # must itself be freshly healthy before it is selected again.
            changes = dict(pending['before'])
            state['pending'] = None
            state['last_action_at'] = now
            state['history'] = (state['history'] + [{'at': now, 'kind': 'rollback', 'target': previous}])[-12:]
            return {**empty, 'status': 'applied', 'reason': 'reserve_regressed', 'state': state,
                    'actions': [{'kind': 'rollback', 'target': previous}], 'changes': changes,
                    'expected': dict(pending['after'])}
        verification_at = _stamp(healthy.get(target, {}).get('checked_at'))
        if verification_at > max(pending['since'], pending['verify_cursor']):
            pending['verify_checks'] = (0 if pending['verify_cursor'] and verification_at - pending['verify_cursor'] > max(FRESHNESS, policy['monitor_interval_seconds'] * 2)
                                         else pending['verify_checks']) + 1
            pending['verify_cursor'] = verification_at
        if pending['verify_checks'] >= policy['required_checks']:
            state['pending'] = None
            state['history'] = (state['history'] + [{'at': now, 'kind': 'verified', 'target': target}])[-12:]
            return {**empty, 'status': 'verified', 'reason': 'post_change_checks_passed', 'state': state,
                    'actions': [{'kind': 'verified', 'target': target}]}
        if now - pending['since'] <= max(1800, policy['monitor_interval_seconds'] * (policy['required_checks'] + 1)):
            return {**empty, 'status': 'verifying', 'reason': 'waiting_post_change_checks'}
        state['pending'] = None
    if state['last_action_at'] and now - state['last_action_at'] < policy['action_cooldown_seconds']:
        return {**empty, 'reason': 'cooldown'}
    actions, changes = [], {}
    updated_quarantine = dict(quarantine)
    for target in sorted(healthy.keys() & own_quarantine):
        updated_quarantine.pop(target, None)
        actions.append({'kind': 'recover_node', 'target': target})
        if len(actions) == 2:
            break
    # Exclude only when another freshly proven healthy node is available.
    for target in sorted(degraded):
        if len(actions) >= 2:
            break
        if target not in quarantine and any(other != target for other in available_healthy):
            updated_quarantine[target] = {'until': now + QUARANTINE_TTL, 'since': now,
                                          'source': 'quantum_autopilot', 'failures': max(_stamp(degraded[target].get('failure_checks')), _stamp(degraded[target].get('regression_checks')))}
            actions.append({'kind': 'quarantine_node', 'target': target})
    eligible = {target: evidence for target, evidence in healthy.items()
                if not isinstance(updated_quarantine.get(target), dict) or _stamp(updated_quarantine[target].get('until')) <= now}
    ordered = sorted(eligible, key=lambda target: (eligible[target].get('latency_ms', 600000), target))
    choice = current if current in eligible else (ordered[0] if ordered and may_reselect else '')
    # Models may choose among proven candidates, but do not move a stable path
    # merely because another measurement differs by a few milliseconds.
    if current not in eligible and may_reselect and isinstance(proposals, list):
        ids = {node_id(target): target for target in eligible}
        for proposal in proposals[:4]:
            if isinstance(proposal, dict) and proposal.get('action') == 'select_reserve' and isinstance(proposal.get('node_id'), str) and proposal['node_id'] in ids:
                choice = ids[proposal['node_id']]
                break
    if choice and choice != current:
        changes.update(load_balancer_last_target=choice, load_balancer_last_decision=str(now), nodes_recommended=choice)
        actions.append({'kind': 'select_reserve', 'target': choice})
    if updated_quarantine != quarantine:
        changes['node_quarantine'] = _dump(updated_quarantine)
    if not actions:
        return {**empty, 'status': 'stable' if current in healthy else 'observing',
                'reason': 'current_node_healthy' if current in healthy else 'no_proven_regression' if ordered and not may_reselect else 'no_proven_healthy_reserve'}
    expected = {key: settings.get(key, '') for key in changes}
    state['last_action_at'] = now
    state['history'] = (state['history'] + [{'at': now, 'kind': action['kind'], 'target': action['target']} for action in actions])[-12:]
    if choice and choice != current:
        state['pending'] = {'since': now, 'target': choice, 'previous_target': current,
                            'verify_cursor': now, 'verify_checks': 0,
                            'before': expected, 'after': dict(changes)}
    return {**empty, 'status': 'applied', 'reason': 'measured_registered_node_control', 'state': state,
            'actions': actions, 'changes': changes, 'expected': expected}


def execute(db, report, configured_nodes, *, now, proposals=None):
    """Atomic allowlisted SQLite action/audit; caller owns final commit.

    A savepoint preserves an outer panel transaction. No commands, file paths,
    endpoint connections, live engine configs or administrator fields are used.
    """
    db.execute('savepoint quantum_autopilot')
    try:
        placeholders = ','.join('?' for _ in SETTINGS_KEYS)
        settings = {row[0]: row[1] for row in db.execute('select key,value from settings where key in (' + placeholders + ')', SETTINGS_KEYS)}
        result = plan_actions(report, configured_nodes, settings, now=now, proposals=proposals)
        # A freeze, drain, forbid or policy change invalidates the entire plan,
        # including state writes, not just the keys it intends to change.
        def assert_unchanged():
            for key in SETTINGS_KEYS:
                row = db.execute('select value from settings where key=?', (key,)).fetchone()
                if (row[0] if row else '') != settings.get(key, ''):
                    raise RuntimeError('Autopilot setting changed during decision')
        assert_unchanged()
        changes = result['changes']
        if set(changes) - MUTABLE_KEYS:
            raise ValueError('Unsupported automatic setting')
        if any(not isinstance(value, str) or len(value) > 8192 for value in [*changes.values(), *result['expected'].values()]):
            raise ValueError('Automatic setting exceeds rollback limits')
        encoded_state = _dump(result['state'])
        if len(encoded_state) > MAX_STATE_BYTES:
            raise ValueError('Automatic state exceeds persistence limits')
        if result['status'] != 'disabled' and result['reason'] != 'monitor_interval':
            if changes:
                # A failed audit cancels the action before any settings change.
                db.execute('insert into events values (?,?,?,?,?)',
                           (now, 'ai_autopilot_plan', 'autopilot', '', _dump(result['journal'])))
                assert_unchanged()
            values = {**changes, 'ai_autopilot_state': encoded_state}
            for key, value in values.items():
                db.execute('insert into settings(key,value) values (?,?) on conflict(key) do update set value=excluded.value', (key, value))
            for action in result['actions']:
                detail = {'action': action['kind'], 'node_id': node_id(action['target']), 'reason': result['reason'],
                          'measured_at': result['generated_at'], 'rollback_available': bool(result['state']['pending']),
                          'cause': 'unconfirmed', 'throughput': 'not_measured'}
                db.execute('insert into events values (?,?,?,?,?)', (now, 'ai_autopilot_' + action['kind'], 'autopilot', '', _dump(detail)))
            result['journal'] = ai_journal.sanitize_entry({**result['journal'], 'phase': 'applied' if changes else 'observed'})
            db.execute('insert into events values (?,?,?,?,?)',
                       (now, 'ai_autopilot_decision', 'autopilot', '', _dump(result['journal'])))
        db.execute('release savepoint quantum_autopilot')
        return result
    except Exception:
        db.execute('rollback to savepoint quantum_autopilot')
        db.execute('release savepoint quantum_autopilot')
        raise
