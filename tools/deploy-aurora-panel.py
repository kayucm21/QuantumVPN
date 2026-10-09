"""Deploy only Aurora panel source, with pinned SSH trust and source-only rollback.

Without --apply, every remote check is read-only (including SQLite): no upload,
backup, restart or HTTP request is made. HTTP probes on --apply exercise the live
application's normal GET handlers; this utility never opens live SQLite writable.
Credentials come exclusively from QVPN_VDS_PASSWORD and are never logged.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid

import paramiko

ROOT = Path(__file__).resolve().parents[1]
REMOTE_ROOT = "/opt/quantumvpn-operator"
COMPANIONS = ("quantumvpn_control_quality.py", "quantumvpn_resources.py")
COMMUNITY_MODULES = ("quantumvpn_durak.py", "quantumvpn_community.py", "quantumvpn_control_next.py")
BOT_STATUS_MODULE = "quantumvpn_bot_status.py"
NETWORK_AI_MODULES = ("quantumvpn_gemini.py", "quantumvpn_network_guard.py", "quantumvpn_target_scan.py")
LOCAL_AI_MODULES = ("quantumvpn_llama.py", "quantumvpn_autopilot.py", "quantumvpn_maintenance.py")
PULSE_MODULES = ("quantumvpn_network_center.py", "quantumvpn_ai_journal.py", "quantumvpn_mtproto.py", "quantumvpn_proxy_links.py", "quantumvpn_webproxy.py")
CATALOG_SOURCES = ("quantumvpn_target_catalog.py", "assets/routing-catalog-seed.json", "assets/routing-catalog-seed.LICENSE.txt")

# Keep the remote operation self-contained; importing app would run writable
# initialization through helpers and is deliberately unnecessary for deployment.
REMOTE_SOURCE = r'''
import base64, hashlib, http.client, importlib, json, os, py_compile
from contextlib import closing
from pathlib import Path
import shutil, sqlite3, ssl, stat, subprocess, sys, time

sys.dont_write_bytecode = True
ROOT = Path('/opt/quantumvpn-operator')
SERVICE = 'quantumvpn-operator'
BASE_SOURCES = {'app.py', 'quantumvpn_aurora.py', 'assets/quantumvpn-world.svg'}
COMMUNITY_SOURCES = {'quantumvpn_durak.py', 'quantumvpn_community.py', 'quantumvpn_control_next.py'}
BOT_STATUS_SOURCES = {'quantumvpn_bot_status.py'}
NETWORK_AI_SOURCES = {'quantumvpn_gemini.py', 'quantumvpn_network_guard.py', 'quantumvpn_target_scan.py'}
LOCAL_AI_SOURCES = {'quantumvpn_llama.py', 'quantumvpn_autopilot.py', 'quantumvpn_maintenance.py'}
PULSE_SOURCES = {'quantumvpn_network_center.py', 'quantumvpn_ai_journal.py', 'quantumvpn_mtproto.py', 'quantumvpn_proxy_links.py', 'quantumvpn_webproxy.py'}
CATALOG_SOURCES = {'quantumvpn_target_catalog.py', 'assets/routing-catalog-seed.json', 'assets/routing-catalog-seed.LICENSE.txt'}
VOLATILE = {
    'node_quarantine', 'latency_state', 'latency_last_probe', 'latency_best_ms',
    'load_balancer_last_target', 'load_balancer_last_decision',
    'telegram_digest_last_attempt', 'telegram_digest_last_sent_date',
    'quality_subscription', 'ai_last_run', 'ai_last_status', 'ai_last_advice',
    'ai_last_error', 'ai_last_error_reason', 'ai_last_notification_hash', 'ai_last_notification_at',
    'ai_autopilot_state', 'ai_autopilot_last_run', 'ai_autopilot_last_status', 'ai_autopilot_last_action',
}

class CheckFailed(Exception):
    pass

def require(ok, label):
    if not ok:
        raise CheckFailed(label)

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':')).encode('utf-8')

def environment():
    # Systemd Environment= overrides can select a different loopback port/TLS
    # mode than an env file. Use only the authoritative running service values;
    # do not parse systemd values as shell syntax or inherit the SSH process env.
    values = {}
    pid = command(['systemctl', 'show', '--property=MainPID', '--value', SERVICE]).strip()
    require(pid.isdigit() and int(pid) > 0, 'service_pid')
    for entry in (Path('/proc') / pid.decode() / 'environ').read_bytes().split(b'\0'):
        if b'=' in entry:
            key, value = entry.split(b'=', 1)
            if key.startswith(b'QV_'):
                values[key.decode()] = value.decode('utf-8', 'surrogateescape')
    return values

def command(argv, timeout=15):
    result = subprocess.run(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    require(result.returncode == 0, 'command_failed_' + argv[0])
    return result.stdout

def safe_target(relative):
    path = ROOT / relative
    require(not path.is_symlink(), 'source_symlink')
    require(path.parent == ROOT or path.parent == ROOT / 'assets', 'source_path')
    require(not path.parent.is_symlink(), 'source_parent_symlink')
    require(not path.exists() or path.is_file(), 'source_not_regular')
    return path

def db_snapshot(data):
    database = data / 'operator.db'
    require(database.is_file() and not database.is_symlink(), 'database_missing')
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=15)) as db:
        require(db.execute('pragma quick_check').fetchone()[0] == 'ok', 'sqlite_integrity')
        settings = dict(db.execute('select key,value from settings'))
        stable = {key: value for key, value in settings.items() if key not in VOLATILE}
        resource = db.execute(
            'select sequence,production,staging,percent from resource_state where id=1'
        ).fetchall()
        require(len(resource) == 1, 'resource_state_missing')
        bundles = db.execute('select count(*) from resource_bundles').fetchone()[0]
        schedule = settings.get('release_schedule_enabled') == '1'
        if schedule:
            try:
                publish_at = int(settings.get('release_publish_at', '0'))
            except ValueError:
                raise CheckFailed('release_schedule_invalid')
            # A due or imminent scheduled release could legitimately change the
            # API baseline while restarting. Retry this deployment afterwards.
            require(publish_at > int(time.time()) + 300, 'release_schedule_due_soon')
        return {
            'settings_sha256': hashlib.sha256(canonical(stable)).hexdigest(),
            'resource_state': resource,
            'resource_bundle_count': bundles,
            'database_identity': (database.stat().st_dev, database.stat().st_ino),
        }

def key_snapshot(data):
    path = data / 'routing-ed25519.key'
    require(path.is_file() and not path.is_symlink(), 'signing_key_missing')
    require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'signing_key_mode')
    raw = path.read_bytes()
    require(len(raw) == 32, 'signing_key_invalid')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    public = Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    return digest(path), base64.urlsafe_b64encode(public).decode().rstrip('=')

def preflight(config):
    require(os.geteuid() == 0, 'root_required')
    require(ROOT.is_dir() and not ROOT.is_symlink(), 'source_root')
    env = environment()
    data = Path(env.get('QV_DATA_DIR', '/var/lib/quantumvpn-operator'))
    require(data.is_absolute() and data.is_dir(), 'data_root')
    require(command(['systemctl', 'is-active', SERVICE]).strip() == b'active', 'service_inactive')
    allowed = (BASE_SOURCES | (COMMUNITY_SOURCES if config.get('with_community') else set())
               | (BOT_STATUS_SOURCES if config.get('with_bot_status') else set())
               | (NETWORK_AI_SOURCES if config.get('with_network_ai') else set())
               | (LOCAL_AI_SOURCES if config.get('with_local_ai') else set())
               | (PULSE_SOURCES if config.get('with_pulse') else set())
               | (CATALOG_SOURCES if config.get('with_catalog') else set()))
    require(set(config['files']) <= allowed and {'app.py', 'quantumvpn_aurora.py'} <= set(config['files']), 'source_allowlist')
    require(not config.get('with_community') or COMMUNITY_SOURCES <= set(config['files']), 'community_sources_missing')
    require(not config.get('with_bot_status') or BOT_STATUS_SOURCES <= set(config['files']), 'bot_status_source_missing')
    require(not config.get('with_network_ai') or NETWORK_AI_SOURCES <= set(config['files']), 'network_ai_sources_missing')
    require(not config.get('with_local_ai') or LOCAL_AI_SOURCES <= set(config['files']), 'local_ai_sources_missing')
    require(not config.get('with_pulse') or PULSE_SOURCES <= set(config['files']), 'pulse_sources_missing')
    require(not config.get('with_catalog') or CATALOG_SOURCES <= set(config['files']), 'catalog_sources_missing')
    for name, expected in config['companions'].items():
        path = safe_target(name)
        require(path.is_file() and digest(path) == expected, 'companion_hash_' + name)
    states = {}
    for name, info in config['files'].items():
        path = safe_target(name)
        expected = info['old_sha256']
        require(path.exists() == (expected is not None), 'source_presence_' + name)
        if path.exists():
            require(digest(path) == expected, 'source_hash_' + name)
            metadata = path.stat()
            states[name] = {
                'exists': True, 'sha256': expected,
                'mode': stat.S_IMODE(metadata.st_mode),
                'uid': metadata.st_uid, 'gid': metadata.st_gid,
            }
        else:
            states[name] = {'exists': False}
    assets = ROOT / 'assets'
    if any(name.startswith('assets/') for name in config['files']):
        require(not assets.is_symlink(), 'assets_symlink')
        if assets.exists():
            require(assets.is_dir() and assets.stat().st_dev == ROOT.stat().st_dev,
                    'assets_filesystem')
    if config.get('with_community'):
        deps = ROOT / 'deps'
        require(deps.is_dir() and not deps.is_symlink(), 'community_dependencies_missing')
        require((deps / '.quantum-control-deps.json').is_file(), 'community_dependency_manifest_missing')
        manifest = json.loads((deps / '.quantum-control-deps.json').read_bytes())
        require(manifest.get('managed_by') == 'quantum-control-next', 'community_dependency_manifest_identity')
        wheels = [wheel for wheel in manifest.get('wheels', []) if wheel.get('name', '').lower() == 'webauthn']
        require(len(wheels) == 1 and wheels[0].get('version') == '3.0.1'
                and wheels[0].get('sha256') == '9927b2f530773bd1d7f8194cd643a2e634a20995ea31f2d8f7a3e70b11c93e31', 'community_webauthn_checksum_manifest')
        sys.path.insert(0, str(deps))
        from importlib import metadata as package_metadata
        require(package_metadata.version('webauthn') == '3.0.1', 'community_webauthn_version')
        dependency = importlib.import_module('webauthn')
        require(Path(dependency.__file__).resolve().is_relative_to(deps.resolve()), 'community_webauthn_origin')
        for function in ('generate_registration_options', 'verify_registration_response',
                         'generate_authentication_options', 'verify_authentication_response', 'options_to_json'):
            require(callable(getattr(dependency, function, None)), 'community_webauthn_api')
    # Select the verified isolated dependency chain before any external import.
    # Importing an older global cryptography package first caches its __path__;
    # prepending deps afterwards cannot expose newer modules needed by WebAuthn.
    # With no community flag, the existing global dependency checks are unchanged.
    # Bytecode remains disabled, and the application itself is never imported.
    for name in ('cryptography', 'PIL'):
        importlib.import_module(name)
    return env, data, states, db_snapshot(data), key_snapshot(data)

def request(env, path, timeout=8):
    bind = env.get('QV_BIND', '0.0.0.0')
    require(bind in ('0.0.0.0', '127.0.0.1', '::', '::1', 'localhost'),
            'loopback_not_bound')
    host = '::1' if bind in ('::', '::1') else '127.0.0.1'
    port = int(env.get('QV_PORT', '8765'))
    terminated = env.get('QV_TLS_TERMINATED', '').strip() in ('1', 'true', 'yes')
    tls = bool(env.get('QV_TLS_CERT') and env.get('QV_TLS_KEY') and not terminated)
    if tls:
        # This connection never leaves loopback; SSH authenticates the host.
        connection = http.client.HTTPSConnection(host, port, timeout=timeout,
                                                context=ssl._create_unverified_context())
    else:
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        try:
            connection.request('GET', path, headers={'User-Agent': 'QuantumVPN-Aurora-Deployment-Probe'})
            response = connection.getresponse()
            body = response.read(4 * 1024 * 1024 + 1)
        except TimeoutError:
            # Fixed probe paths contain no account/token material. Never expose
            # response bodies or runtime environment in deployment diagnostics.
            label = path.split('?', 1)[0].strip('/').replace('/', '_')
            if 'abi=arm64-v8a' in path: label += '_arm64'
            elif 'abi=armeabi-v7a' in path: label += '_armv7'
            raise CheckFailed('probe_timeout_' + label) from None
        require(len(body) <= 4 * 1024 * 1024, 'probe_size')
        return response.status, dict(response.getheaders()), body
    finally:
        connection.close()

def envelope(value, public):
    require(value.get('signature_algorithm') == 'ed25519', 'api_signature_algorithm')
    require(value.get('public_key') == public, 'api_signing_identity')
    payload = canonical(value['payload'])
    require(hashlib.sha256(payload).hexdigest() == value.get('sha256'), 'api_payload_hash')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(public + '=='))
    key.verify(base64.urlsafe_b64decode(value['signature'] + '=='), payload)
    return {key: item for key, item in value.items() if key not in ('signature', 'issued_at')}

def public_snapshot(env, public):
    result = {}
    for abi in ('arm64-v8a', 'armeabi-v7a'):
        # A restarted process has an empty APK checksum cache. Allow one
        # bounded cold read; contents and baseline checks stay identical.
        status, headers, body = request(env, '/api/client/update?abi=' + abi + '&current_version_code=0', timeout=30)
        require(status == 200, 'update_api_' + abi)
        result[abi] = json.loads(body)
        # The new opt-in guard adds this boolean. Legacy omission means false,
        # not a different release. True/non-boolean and every other field still
        # change the snapshot and fail deployment; no artifact/routing/signer
        # baseline is weakened by normalizing this one backward-compatible key.
        result[abi].setdefault('rollout_paused', False)
    status, headers, body = request(env, '/api/client/routing?bucket=0')
    require(status == 200, 'routing_api')
    result['routing'] = envelope(json.loads(body), public)
    status, headers, body = request(env, '/api/client/resources?version_code=2147483647')
    require(status in (200, 204), 'resources_api')
    result['resources'] = envelope(json.loads(body), public) if status == 200 else None
    return hashlib.sha256(canonical(result)).hexdigest()

def login_ready(env, config, seconds=35):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            status, headers, body = request(env, '/operator/login', timeout=2)
            server = next((value for key, value in headers.items() if key.lower() == 'server'), '')
            if (status == 200 and config['login_marker'].encode() in body
                    and ('QuantumControl/' + config['panel_build']) in server):
                command(['systemctl', 'is-active', SERVICE], timeout=3)
                return
        except (OSError, http.client.HTTPException, CheckFailed):
            pass
        time.sleep(0.5)
    raise CheckFailed('aurora_login_not_ready')

def restore(states, backup, replaced):
    for name in reversed(replaced):
        path = safe_target(name)
        info = states[name]
        require(path.is_file() and digest(path) == CONFIG['files'][name]['sha256'],
                'rollback_source_changed')
        if info['exists']:
            require(digest(backup / name) == info['sha256'], 'rollback_backup_hash')
            rollback = ROOT / ('.aurora-rollback-' + CONFIG['upload'] + '-' + Path(name).name)
            shutil.copy2(backup / name, rollback)
            os.chown(rollback, info['uid'], info['gid'])
            os.chmod(rollback, info['mode'])
            os.replace(rollback, path)
        else:
            # Remove only a source file introduced by this precise operation.
            path.unlink()

def deploy(config):
    env, data, states, baseline, signing = preflight(config)
    if not config['apply']:
        return {'mode': 'dry-run', 'verified': True, 'panel_build': config['panel_build'],
                'source_files': sorted(config['files']), 'companions': 'unchanged'}
    staged, compiled, replaced = [], [], []
    backup = None
    try:
        # Files are already uploaded under unique, root-only staging names.
        for name, info in config['files'].items():
            path = ROOT / info['stage']
            staged.append(path)
            require(path.is_file() and not path.is_symlink(), 'stage_missing')
            require(digest(path) == info['sha256'], 'stage_hash_' + name)
            if name.endswith('.py'):
                cache = path.with_name(path.name + '.pyc')
                compiled.append(cache)
                py_compile.compile(str(path), cfile=str(cache), doraise=True)
        backups = data / 'aurora-source-backups'
        require(not backups.is_symlink(), 'backup_root_symlink')
        backups.mkdir(mode=0o700, exist_ok=True)
        require(stat.S_IMODE(backups.stat().st_mode) & 0o077 == 0,
                'backup_root_permissions')
        backup = backups / ('aurora-' + config['upload'])
        backup.mkdir(mode=0o700)
        for name, info in states.items():
            if info['exists']:
                saved = backup / name
                saved.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copy2(safe_target(name), saved)
                os.chmod(saved, 0o600)
        database = data / 'operator.db'
        saved_db = backup / 'operator.db'
        fd = os.open(saved_db, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        backup_deadline = time.monotonic() + 45
        def backup_progress(status, remaining, total):
            require(time.monotonic() < backup_deadline, 'backup_timeout')
        with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=15)) as live:
            with closing(sqlite3.connect(str(saved_db))) as saved:
                live.backup(saved, pages=256, sleep=0.05, progress=backup_progress)
                require(saved.execute('pragma quick_check').fetchone()[0] == 'ok', 'backup_integrity')
        api_baseline = public_snapshot(env, signing[1])
        require(db_snapshot(data) == baseline, 'baseline_changed_during_preflight')
        require(key_snapshot(data) == signing, 'signing_changed_during_preflight')
        # Abort concurrent source or configuration changes immediately before commit.
        final_env, final_data, final_states, final_baseline, final_signing = preflight(config)
        require(final_env == env and final_data == data and final_states == states and final_baseline == baseline
                and final_signing == signing, 'baseline_changed_before_replace')
        app_metadata = states['app.py']
        if any(name.startswith('assets/') for name in config['files']):
            (ROOT / 'assets').mkdir(mode=0o755, exist_ok=True)
        # Replace app last: its imports can never refer to an unstaged new module.
        names = [name for name in config['files'] if name != 'app.py'] + ['app.py']
        metadata = {'panel_build': config['panel_build'], 'before': states,
                    'after_sha256': {name: info['sha256'] for name, info in config['files'].items()},
                    'database_restoration': 'never', 'created_at': int(time.time())}
        (backup / 'deployment.json').write_bytes(canonical(metadata))
        os.chmod(backup / 'deployment.json', 0o600)
        for name in names:
            info = states[name] if states[name]['exists'] else app_metadata
            staged_path = ROOT / config['files'][name]['stage']
            os.chown(staged_path, info['uid'], info['gid'])
            os.chmod(staged_path, info['mode'] if not name.startswith('assets/') or states[name]['exists'] else 0o644)
            os.replace(staged_path, safe_target(name))
            replaced.append(name)
        command(['systemctl', 'restart', SERVICE], timeout=20)
        login_ready(env, config)
        require(public_snapshot(env, signing[1]) == api_baseline, 'public_api_changed')
        require(db_snapshot(data) == baseline, 'configuration_changed')
        require(key_snapshot(data) == signing, 'signing_changed')
        actual_env = environment()
        require({key: value for key, value in actual_env.items() if key.startswith('QV_')}
                == {key: value for key, value in env.items() if key.startswith('QV_')},
                'runtime_configuration_changed')
        for name, info in config['files'].items():
            require(digest(safe_target(name)) == info['sha256'], 'installed_source_hash')
        for name, expected in config['companions'].items():
            require(digest(safe_target(name)) == expected, 'installed_companion_hash')
        return {'mode': 'applied', 'verified': True, 'panel_build': config['panel_build'],
                'backup': str(backup), 'public_api': 'unchanged', 'configuration': 'unchanged',
                'signing_identity': 'unchanged', 'source_files': sorted(config['files'])}
    except BaseException as original:
        if replaced:
            try:
                restore(states, backup, replaced)
                command(['systemctl', 'restart', SERVICE], timeout=20)
                command(['systemctl', 'is-active', SERVICE], timeout=5)
            except BaseException:
                raise CheckFailed('deployment_failed_and_source_rollback_failed') from None
            label = str(original) if isinstance(original, CheckFailed) else type(original).__name__
            raise CheckFailed('deployment_failed_source_rolled_back_' + label) from None
        raise
    finally:
        for path in staged + compiled:
            try:
                if path.exists() and not path.is_symlink():
                    path.unlink()
            except OSError:
                # A leftover unique staging/cache file cannot be imported by
                # app. Do not mask a completed source rollback or verification.
                pass

def main():
    try:
        print(json.dumps({'ok': True, **deploy(CONFIG)}, sort_keys=True))
    except BaseException as error:
        # Never echo exception details from HTTP, SSH, environment or SQLite.
        label = str(error) if isinstance(error, CheckFailed) else type(error).__name__
        print(json.dumps({'ok': False, 'error': label}, sort_keys=True))
        sys.exit(1)

if __name__ == '__main__':
    main()
'''


def sha256(value: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise argparse.ArgumentTypeError("expected a SHA-256 hex digest")
    return value.lower()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--host", required=True)
    result.add_argument("--port", type=int, default=22)
    result.add_argument("--user", default="root")
    result.add_argument("--known-hosts", type=Path, default=Path.home() / ".ssh" / "known_hosts")
    result.add_argument("--expected-old-app-sha256", required=True, type=sha256)
    result.add_argument("--expected-old-aurora-sha256", type=sha256,
                        help="Required when quantumvpn_aurora.py already exists remotely; otherwise expect absence")
    result.add_argument("--expected-old-world-sha256", type=sha256,
                        help="Required when the optional world SVG already exists remotely; otherwise expect absence")
    result.add_argument("--login-marker", default="Aurora2")
    result.add_argument("--with-community", action="store_true",
                        help="Also deploy the exact Durak/community/control-next module allowlist; verify isolated WebAuthn dependency first")
    for name in ("durak", "community", "control-next"):
        result.add_argument("--expected-old-" + name + "-sha256", type=sha256,
                            help="Existing module SHA-256; omitted means the module must be absent")
    result.add_argument("--with-bot-status", action="store_true",
                        help="Also deploy only quantumvpn_bot_status.py; no dependency changes")
    result.add_argument("--expected-old-bot-status-sha256", type=sha256,
                        help="Existing bot status module SHA-256; omitted means the module must be absent")
    result.add_argument("--with-network-ai", action="store_true",
                        help="Also deploy only quantumvpn_gemini.py, quantumvpn_network_guard.py and quantumvpn_target_scan.py; no dependency or configuration changes")
    for name in ("gemini", "network-guard", "target-scan"):
        result.add_argument("--expected-old-" + name + "-sha256", type=sha256,
                            help="Existing module SHA-256; omitted means the module must be absent")
    result.add_argument("--with-local-ai", action="store_true",
                        help="Also deploy only quantumvpn_llama.py, quantumvpn_autopilot.py and quantumvpn_maintenance.py; no dependency, model or configuration changes")
    for name in ("llama", "autopilot", "maintenance"):
        result.add_argument("--expected-old-" + name + "-sha256", type=sha256,
                            help="Existing module SHA-256; omitted means the module must be absent")
    result.add_argument("--with-pulse", action="store_true",
                        help="Also deploy only network center, AI journal, Telegram proxy controls and link UI; no proxy installation, service or configuration changes")
    for name in ("network-center", "ai-journal", "mtproto", "proxy-links", "webproxy"):
        result.add_argument("--expected-old-" + name + "-sha256", type=sha256,
                            help="Existing Pulse module SHA-256; omitted means the module must be absent")
    result.add_argument("--apply", action="store_true", help="Upload, back up, replace and verify; default is read-only")
    result.add_argument("--with-catalog", action="store_true", help="Deploy the exact routing catalogue module, pinned seed and licence; no active route changes")
    for name in ("catalog", "catalog-seed", "catalog-license"):
        result.add_argument("--expected-old-" + name + "-sha256", type=sha256,
                            help="Existing catalogue source SHA-256; omitted means this file must be absent")
    return result


def build_config(args: argparse.Namespace) -> tuple[dict, dict[str, bytes]]:
    local = {"app.py": ROOT / "tools" / "quantumvpn_operator_panel.py",
             "quantumvpn_aurora.py": ROOT / "tools" / "quantumvpn_aurora.py"}
    world = ROOT / "tools" / "assets" / "quantumvpn-world.svg"
    if world.is_file():
        local["assets/quantumvpn-world.svg"] = world
    elif args.expected_old_world_sha256:
        raise ValueError("Expected old world hash was supplied, but the local SVG is missing")
    with_community = getattr(args, "with_community", False)
    if with_community:
        for name in COMMUNITY_MODULES:
            local[name] = ROOT / "tools" / name
    elif any(getattr(args, key, None) for key in ("expected_old_durak_sha256", "expected_old_community_sha256", "expected_old_control_next_sha256")):
        raise ValueError("Community old hashes require --with-community")
    with_bot_status = getattr(args, "with_bot_status", False)
    if with_bot_status:
        local[BOT_STATUS_MODULE] = ROOT / "tools" / BOT_STATUS_MODULE
    elif getattr(args, "expected_old_bot_status_sha256", None):
        raise ValueError("Bot status old hash requires --with-bot-status")
    with_network_ai = getattr(args, "with_network_ai", False)
    if with_network_ai:
        for name in NETWORK_AI_MODULES:
            local[name] = ROOT / "tools" / name
    elif any(getattr(args, key, None) for key in ("expected_old_gemini_sha256", "expected_old_network_guard_sha256", "expected_old_target_scan_sha256")):
        raise ValueError("Network AI old hashes require --with-network-ai")
    with_local_ai = getattr(args, "with_local_ai", False)
    if with_local_ai:
        for name in LOCAL_AI_MODULES:
            local[name] = ROOT / "tools" / name
    elif any(getattr(args, key, None) for key in ("expected_old_llama_sha256", "expected_old_autopilot_sha256", "expected_old_maintenance_sha256")):
        raise ValueError("Local AI old hashes require --with-local-ai")
    with_pulse = getattr(args, "with_pulse", False)
    if with_pulse:
        for name in PULSE_MODULES:
            local[name] = ROOT / "tools" / name
    elif any(getattr(args, key, None) for key in ("expected_old_network_center_sha256", "expected_old_ai_journal_sha256", "expected_old_mtproto_sha256", "expected_old_proxy_links_sha256", "expected_old_webproxy_sha256")):
        raise ValueError("Pulse old hashes require --with-pulse")
    with_catalog = getattr(args, "with_catalog", False)
    if with_catalog:
        for name in CATALOG_SOURCES:
            local[name] = ROOT / "tools" / name
    elif any(getattr(args, key, None) for key in ("expected_old_catalog_sha256", "expected_old_catalog_seed_sha256", "expected_old_catalog_license_sha256")):
        raise ValueError("Catalogue old hashes require --with-catalog")
    payloads = {name: path.read_bytes() for name, path in local.items()}
    tree = ast.parse(payloads["app.py"])
    builds = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "PANEL_BUILD" for target in node.targets)
              and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
    if len(builds) != 1:
        raise ValueError("Panel must have one literal PANEL_BUILD")
    if not args.login_marker:
        raise ValueError("Login marker must not be empty")
    for name, payload in payloads.items():
        if name.endswith(".py"):
            compile(payload, name, "exec")
    upload = uuid.uuid4().hex
    old = {"app.py": args.expected_old_app_sha256,
           "quantumvpn_aurora.py": args.expected_old_aurora_sha256,
           "assets/quantumvpn-world.svg": args.expected_old_world_sha256}
    if with_community:
        old.update({"quantumvpn_durak.py": getattr(args, "expected_old_durak_sha256", None),
                    "quantumvpn_community.py": getattr(args, "expected_old_community_sha256", None),
                    "quantumvpn_control_next.py": getattr(args, "expected_old_control_next_sha256", None)})
    if with_bot_status:
        old[BOT_STATUS_MODULE] = getattr(args, "expected_old_bot_status_sha256", None)
    if with_network_ai:
        old.update({"quantumvpn_gemini.py": getattr(args, "expected_old_gemini_sha256", None),
                    "quantumvpn_network_guard.py": getattr(args, "expected_old_network_guard_sha256", None),
                    "quantumvpn_target_scan.py": getattr(args, "expected_old_target_scan_sha256", None)})
    if with_local_ai:
        old.update({"quantumvpn_llama.py": getattr(args, "expected_old_llama_sha256", None),
                    "quantumvpn_autopilot.py": getattr(args, "expected_old_autopilot_sha256", None),
                    "quantumvpn_maintenance.py": getattr(args, "expected_old_maintenance_sha256", None)})
    if with_pulse:
        old.update({"quantumvpn_network_center.py": getattr(args, "expected_old_network_center_sha256", None),
                    "quantumvpn_ai_journal.py": getattr(args, "expected_old_ai_journal_sha256", None),
                    "quantumvpn_mtproto.py": getattr(args, "expected_old_mtproto_sha256", None),
                    "quantumvpn_proxy_links.py": getattr(args, "expected_old_proxy_links_sha256", None),
                    "quantumvpn_webproxy.py": getattr(args, "expected_old_webproxy_sha256", None)})
    if with_catalog:
        old.update({"quantumvpn_target_catalog.py": getattr(args, "expected_old_catalog_sha256", None),
                    "assets/routing-catalog-seed.json": getattr(args, "expected_old_catalog_seed_sha256", None),
                    "assets/routing-catalog-seed.LICENSE.txt": getattr(args, "expected_old_catalog_license_sha256", None)})
    files = {name: {"sha256": hashlib.sha256(payload).hexdigest(), "old_sha256": old[name],
                    "stage": ".aurora-upload-" + upload + "-" + Path(name).name}
             for name, payload in payloads.items()}
    companions = {name: hashlib.sha256((ROOT / "tools" / name).read_bytes()).hexdigest()
                  for name in COMPANIONS}
    return {"apply": args.apply, "upload": upload, "files": files,
            "companions": companions, "panel_build": builds[0],
            "with_community": with_community,
            "with_bot_status": with_bot_status,
            "with_network_ai": with_network_ai,
            "with_local_ai": with_local_ai,
            "with_pulse": with_pulse,
            "with_catalog": with_catalog,
            "login_marker": args.login_marker}, payloads


def remote(client: paramiko.SSHClient, config: dict) -> dict:
    script = "CONFIG = json.loads(" + repr(json.dumps(config)) + ")\n" + REMOTE_SOURCE
    script = "import json\n" + script
    stdin, stdout, stderr = client.exec_command("python3 -", timeout=180)
    stdin.write(script)
    stdin.channel.shutdown_write()
    output = stdout.read().decode("utf-8", "replace")
    # Drain diagnostic output without ever printing server data or exception text.
    stderr.read()
    status = stdout.channel.recv_exit_status()
    try:
        value = json.loads(output)
    except (ValueError, TypeError):
        raise RuntimeError("Remote operation returned no structured result") from None
    if status or not value.get("ok"):
        raise RuntimeError("Remote verification failed: " + str(value.get("error", "unknown")))
    return value


def main() -> int:
    args = parser().parse_args()
    password = os.environ.get("QVPN_VDS_PASSWORD")
    if not password:
        raise ValueError("QVPN_VDS_PASSWORD is required")
    if not args.known_hosts.is_file():
        raise ValueError("Pinned known_hosts file is missing")
    if not 1 <= args.port <= 65535:
        raise ValueError("SSH port must be between 1 and 65535")
    config, payloads = build_config(args)
    client = paramiko.SSHClient()
    client.load_host_keys(str(args.known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(args.host, port=args.port, username=args.user, password=password,
                       timeout=15, auth_timeout=20, banner_timeout=20,
                       allow_agent=False, look_for_keys=False)
        # Complete read-only preflight before any write, even on --apply.
        preview = remote(client, {**config, "apply": False})
        if not args.apply:
            print(json.dumps(preview, sort_keys=True))
            return 0
        staged = []
        try:
            with client.open_sftp() as sftp:
                for name, payload in payloads.items():
                    target = REMOTE_ROOT + "/" + config["files"][name]["stage"]
                    # Exclusive creation prevents accidental staging overwrite;
                    # permissions are set before source bytes are written.
                    stream = sftp.open(target, "wx")
                    staged.append(target)
                    try:
                        sftp.chmod(target, 0o600)
                        stream.write(payload)
                        stream.flush()
                    finally:
                        stream.close()
            print(json.dumps(remote(client, config), sort_keys=True))
            return 0
        finally:
            # Exact per-run staging paths only; no globbing or source deletion.
            try:
                with client.open_sftp() as sftp:
                    for target in staged:
                        try:
                            sftp.remove(target)
                        except FileNotFoundError:
                            pass
            except (OSError, paramiko.SSHException):
                # Preserve the deployment result if the SSH session disappeared.
                # Staging names are unique and are never imported by the service.
                print("Could not clean this run's staging files", file=sys.stderr)
    finally:
        client.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, RuntimeError, paramiko.SSHException) as error:
        # Our own validation errors contain no credentials; SSH/OS messages may.
        message = str(error) if type(error) in (ValueError, RuntimeError) else type(error).__name__
        print("Aurora deployment failed: " + message, file=sys.stderr)
        raise SystemExit(1)
