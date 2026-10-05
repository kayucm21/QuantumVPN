"""Pinned isolated WebAuthn dependencies; inspect-only unless --apply.

Never modifies global Python, service settings, database, app source, or running
connections. Wheels come only from official PyPI, then each wheel's exact name,
version and SHA-256 are verified against PyPI JSON metadata before installation.
Existing managed deps are swapped only with explicit tree-hash compare-and-swap.
The previous dependency directory is preserved as a private recoverable backup.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import uuid

REMOTE = r'''
import email, hashlib, importlib, importlib.metadata, importlib.util, json, os, platform, re
from pathlib import Path
import shutil, stat, subprocess, sys, time, urllib.parse, urllib.request, zipfile
sys.dont_write_bytecode = True
ROOT = Path('/opt/quantumvpn-operator')
TARGET = ROOT / 'deps'
MARKER = '.quantum-control-deps.json'
WEBAUTHN_SHA256 = '9927b2f530773bd1d7f8194cd643a2e634a20995ea31f2d8f7a3e70b11c93e31'
PIP_VERSION = '26.2.1'
PIP_SHA256 = '71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e'

class CheckFailed(Exception): pass
def require(ok, label):
    if not ok: raise CheckFailed(label)

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''): h.update(chunk)
    return h.hexdigest()

def tree(path):
    require(path.is_dir() and not path.is_symlink(), 'dependency_directory')
    rows = []
    for item in sorted(path.rglob('*')):
        require(not item.is_symlink(), 'dependency_symlink')
        if not item.is_file() or '__pycache__' in item.parts or item.suffix == '.pyc': continue
        require(item.stat().st_size <= 100 * 1024 * 1024, 'dependency_file_size')
        rows.append((item.relative_to(path).as_posix(), sha(item)))
        require(len(rows) <= 20_000, 'dependency_file_count')
    return hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()

def installed(path):
    marker = path / MARKER
    require(marker.is_file() and not marker.is_symlink(), 'unmanaged_dependency_directory')
    require(marker.stat().st_size < 100_000, 'dependency_manifest_size')
    manifest = json.loads(marker.read_text())
    require(manifest.get('managed_by') == 'quantum-control-next' and manifest.get('webauthn_version') == '3.0.1', 'dependency_manifest_identity')
    return {'present': True, 'tree_sha256': tree(path), 'webauthn_version': manifest['webauthn_version'], 'wheel_count': len(manifest.get('wheels', []))}

def command(argv, seconds=180):
    env = dict(os.environ)
    env.update({'PIP_CONFIG_FILE': '/dev/null', 'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PYTHONDONTWRITEBYTECODE': '1'})
    for key in list(env):
        if key.startswith('PIP_') and key not in ('PIP_CONFIG_FILE', 'PIP_DISABLE_PIP_VERSION_CHECK'): del env[key]
    result = subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=seconds)
    require(result.returncode == 0, 'dependency_command_failed')

def official_metadata(name, version):
    url = 'https://pypi.org/pypi/' + urllib.parse.quote(name, safe='') + '/' + urllib.parse.quote(version, safe='') + '/json'
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'Quantum-Control-Dependency-Verification'}), timeout=20) as response:
        require(urllib.parse.urlsplit(response.url).hostname == 'pypi.org', 'metadata_origin')
        raw = response.read(2 * 1024 * 1024 + 1)
        require(len(raw) <= 2 * 1024 * 1024, 'metadata_size')
        return json.loads(raw)

def verify_wheel(path):
    require(path.is_file() and not path.is_symlink() and path.suffix == '.whl', 'wheel_file')
    with zipfile.ZipFile(path) as wheel:
        metadata_paths = [name for name in wheel.namelist() if name.endswith('.dist-info/METADATA')]
        require(len(metadata_paths) == 1, 'wheel_metadata')
        require(wheel.getinfo(metadata_paths[0]).file_size < 2 * 1024 * 1024, 'wheel_metadata_size')
        values = email.message_from_bytes(wheel.read(metadata_paths[0]))
    name, version = values['Name'], values['Version']
    require(bool(re.fullmatch(r'[A-Za-z0-9_.-]+', name or '')) and bool(re.fullmatch(r'[A-Za-z0-9_.+-]+', version or '')), 'wheel_identity')
    metadata = official_metadata(name, version)
    candidates = [value for value in metadata.get('urls', []) if value.get('filename') == path.name and value.get('packagetype') == 'bdist_wheel' and not value.get('yanked')]
    require(len(candidates) == 1 and urllib.parse.urlsplit(candidates[0].get('url', '')).hostname == 'files.pythonhosted.org', 'wheel_official_origin')
    digest = sha(path)
    require(digest == candidates[0]['digests']['sha256'], 'wheel_checksum')
    if name.lower() == 'webauthn': require(version == '3.0.1' and digest == WEBAUTHN_SHA256, 'webauthn_pinned_checksum')
    return {'name': name, 'version': version, 'filename': path.name, 'sha256': digest}

def bootstrap_pip(stage):
    # The distribution's Python may omit pip/ensurepip. Use one exact official
    # wheel as a temporary executable module, never apt or global pip install.
    metadata = official_metadata('pip', PIP_VERSION)
    filename = 'pip-' + PIP_VERSION + '-py3-none-any.whl'
    matches = [entry for entry in metadata.get('urls', []) if entry.get('filename') == filename and entry.get('packagetype') == 'bdist_wheel' and not entry.get('yanked')]
    require(len(matches) == 1 and matches[0]['digests']['sha256'] == PIP_SHA256, 'pip_pinned_metadata')
    url = matches[0]['url']
    require(urllib.parse.urlsplit(url).scheme == 'https' and urllib.parse.urlsplit(url).hostname == 'files.pythonhosted.org', 'pip_official_origin')
    with urllib.request.urlopen(url, timeout=30) as response:
        require(urllib.parse.urlsplit(response.url).hostname == 'files.pythonhosted.org', 'pip_download_origin')
        raw = response.read(8 * 1024 * 1024 + 1)
        require(len(raw) <= 8 * 1024 * 1024 and hashlib.sha256(raw).hexdigest() == PIP_SHA256, 'pip_download_checksum')
    wheel_path = stage / filename
    wheel_path.write_bytes(raw)
    verified = verify_wheel(wheel_path)
    require(verified['name'].lower() == 'pip' and verified['version'] == PIP_VERSION, 'pip_wheel_identity')
    destination = stage / 'pip-bootstrap'
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(wheel_path) as wheel:
        for member in wheel.infolist():
            require((destination / member.filename).resolve().is_relative_to(destination.resolve()), 'pip_wheel_path')
            require(not stat.S_ISLNK(member.external_attr >> 16), 'pip_wheel_symlink')
        wheel.extractall(destination)
    loader = "import runpy,sys; sys.dont_write_bytecode=True; sys.path.insert(0,sys.argv.pop(1)); runpy.run_module('pip',run_name='__main__')"
    return [sys.executable, '-c', loader, str(destination)]

def verify_import(path):
    # Fresh process avoids loading another globally installed dependency.
    source = "import importlib.metadata,pathlib,sys; sys.dont_write_bytecode=True; sys.path.insert(0,sys.argv[1]); import webauthn; assert importlib.metadata.version('webauthn')=='3.0.1'; assert pathlib.Path(webauthn.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve()); from webauthn import generate_registration_options,verify_registration_response,generate_authentication_options,verify_authentication_response,options_to_json; from webauthn.helpers.structs import UserVerificationRequirement; options_to_json(generate_registration_options(rp_id='example.invalid',rp_name='Test',user_id=b'preflight',user_name='test'))"
    command([sys.executable, '-c', source, str(path)], seconds=30)

def run(config):
    require(os.geteuid() == 0 and ROOT.is_dir() and not ROOT.is_symlink(), 'root_or_workspace')
    require(sys.version_info >= (3, 10) and platform.machine() in ('x86_64', 'aarch64'), 'python_or_platform')
    require(not TARGET.is_symlink(), 'dependency_target_symlink')
    baseline = installed(TARGET) if TARGET.exists() else {'present': False, 'tree_sha256': None}
    expected = config.get('expected_existing_sha256')
    pip_available = importlib.util.find_spec('pip') is not None
    if not config['apply']: return {'mode': 'inspect', **baseline, 'pip_available': pip_available}
    require(baseline['tree_sha256'] == expected, 'dependency_baseline_changed')
    require(shutil.disk_usage(ROOT).free >= 300 * 1024 * 1024, 'dependency_disk_space')
    transaction = config['transaction']
    require(bool(re.fullmatch('[0-9a-f]{32}', transaction)), 'transaction_id')
    stage = ROOT / ('.control-deps-stage-' + transaction)
    backup = ROOT / ('.control-deps-backup-' + transaction)
    require(not stage.exists() and not backup.exists(), 'transaction_paths_exist')
    stage.mkdir(mode=0o700)
    prior_moved = target_installed = False
    prior_mode = stat.S_IMODE(TARGET.stat().st_mode) if TARGET.exists() else None
    committed_hash = None
    try:
        wheels, staged_target = stage / 'wheels', stage / 'deps'
        wheels.mkdir(mode=0o700)
        pip_command = bootstrap_pip(stage)
        command(pip_command + ['download', '--disable-pip-version-check', '--no-cache-dir', '--only-binary=:all:', '--index-url', 'https://pypi.org/simple', '--dest', str(wheels), 'webauthn==3.0.1'])
        files = sorted(wheels.iterdir())
        require(1 <= len(files) <= 20 and sum(path.stat().st_size for path in files) <= 150 * 1024 * 1024, 'wheel_budget')
        verified = [verify_wheel(path) for path in files]
        require(sum(value['name'].lower() == 'webauthn' for value in verified) == 1, 'webauthn_wheel_missing')
        command(pip_command + ['install', '--disable-pip-version-check', '--no-cache-dir', '--no-index', '--no-deps', '--no-compile', '--target', str(staged_target)] + [str(path) for path in files])
        verify_import(staged_target)
        manifest = {'managed_by': 'quantum-control-next', 'webauthn_version': '3.0.1', 'created_at': int(time.time()), 'wheels': verified, 'installer_pip_version': PIP_VERSION, 'installer_pip_sha256': PIP_SHA256}
        (staged_target / MARKER).write_text(json.dumps(manifest, sort_keys=True))
        os.chmod(staged_target / MARKER, 0o644)
        os.chmod(staged_target, 0o755)
        committed_hash = tree(staged_target)
        require((installed(TARGET) if TARGET.exists() else {'present': False, 'tree_sha256': None}) == baseline, 'dependency_changed_before_swap')
        require(not TARGET.is_symlink() and stage.resolve().parent == ROOT.resolve(), 'dependency_swap_path')
        if TARGET.exists():
            os.replace(TARGET, backup)
            prior_moved = True
            os.chmod(backup, 0o700)
        os.replace(staged_target, TARGET)
        target_installed = True
        verify_import(TARGET)
        result = {'mode': 'applied', **installed(TARGET), 'service_restarted': False, 'global_python_changed': False}
        if prior_moved: result['backup'] = str(backup)
        return result
    except BaseException:
        # Move the exact introduced dependency tree aside, never delete or
        # overwrite user data. Old tree is restored without touching service.
        if target_installed:
            require(not TARGET.is_symlink() and TARGET.is_dir(), 'rollback_target_changed')
            require(tree(TARGET) == committed_hash, 'rollback_target_changed')
            os.replace(TARGET, stage / 'failed-deps')
        if prior_moved:
            os.replace(backup, TARGET)
            os.chmod(TARGET, prior_mode)
        raise
    finally:
        require(stage.resolve().parent == ROOT.resolve() and stage.name == '.control-deps-stage-' + transaction and not stage.is_symlink(), 'cleanup_path')
        shutil.rmtree(stage)

try:
    print(json.dumps({'ok': True, **run(CONFIG)}, sort_keys=True))
except BaseException as error:
    print(json.dumps({'ok': False, 'error': str(error) if isinstance(error, CheckFailed) else type(error).__name__}))
    sys.exit(1)
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--known-hosts", type=Path, default=Path.home() / ".ssh" / "known_hosts")
    parser.add_argument("--expected-existing-sha256", help="Required tree digest when a managed isolated deps directory already exists")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if args.expected_existing_sha256 is not None and not re.fullmatch("[0-9a-f]{64}", args.expected_existing_sha256):
        raise ValueError("Invalid existing tree SHA-256")
    if not args.known_hosts.is_file():
        raise ValueError("Pinned known_hosts is required")
    password = os.environ.get("QVPN_VDS_PASSWORD")
    if not password:
        raise ValueError("QVPN_VDS_PASSWORD is required")
    import paramiko
    client = paramiko.SSHClient()
    client.load_host_keys(str(args.known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(args.host, username="root", password=password, allow_agent=False, look_for_keys=False, timeout=15, auth_timeout=20, banner_timeout=20)
        config = {"apply": args.apply, "expected_existing_sha256": args.expected_existing_sha256, "transaction": uuid.uuid4().hex}
        source = "import json\nCONFIG=json.loads(" + repr(json.dumps(config)) + ")\n" + REMOTE
        stdin, stdout, stderr = client.exec_command("python3 -", timeout=480)
        stdin.write(source)
        stdin.channel.shutdown_write()
        raw = stdout.read().decode()
        stderr.read()  # Do not expose pip/server/SSH environment diagnostic output.
        status = stdout.channel.recv_exit_status()
        result = json.loads(raw)
        print(json.dumps(result, sort_keys=True))
        return 0 if not status and result.get("ok") else 1
    finally:
        client.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"ok": False, "error": type(error).__name__}), file=sys.stderr)
        raise SystemExit(1)
