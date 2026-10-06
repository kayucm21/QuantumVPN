"""Delete only expired owned temporary files; retain backups and published APKs."""
import hashlib
import os
from pathlib import Path
import re
import stat
import time

MAX_FILES = 256
MAX_HASH_BYTES = 256 * 1024 * 1024
TEMP_APK = re.compile(r"QuantumVPN-(\d+\.\d+\.\d+)-(?:operator-)?debug-(arm64-v8a|armeabi-v7a)\.apk\Z")
TEMP_DB = re.compile(r"\.(?:operator|rospanel)-\d{8}-\d{6}(?:-\d{6})?\.db\Z")

def _regular(path):
    try:
        value = path.lstat()
        return value if stat.S_ISREG(value.st_mode) and not path.is_symlink() else None
    except OSError:
        return None

def _digest(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(part)
    return digest.digest()

def cleanup_managed(data_root, download_root, *, now=None, temp_root='/tmp', apply=False):
    """Aged backup intermediates and verified duplicate APKs, no recursion.

    At most 256 direct files are inspected. APKs are removed only when a byte-
    identical permanent download survives. Plaintext backup archives are kept
    for investigation: an existing encrypted counterpart may be corrupt.
    """
    now = int(time.time()) if now is None else int(now)
    data, downloads, temporary = (Path(value) for value in (data_root, download_root, temp_root))
    for directory in (data, downloads, temporary):
        if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
            raise ValueError('Expected an existing absolute regular directory')
    backups = data / 'backups'
    if backups.is_symlink():
        raise ValueError('Backup directory must not be a symlink')
    candidates = []
    for folder in (backups, temporary):
        if not folder.is_dir():
            continue
        for index, path in enumerate(sorted(folder.iterdir(), key=lambda item: item.name)):
            if index >= MAX_FILES:
                break
            info = _regular(path)
            if info is None or now - info.st_mtime < 86400:
                continue
            reason, retained = None, None
            if folder == backups and TEMP_DB.fullmatch(path.name):
                reason = 'expired_backup_intermediate'
            elif folder == temporary:
                match = TEMP_APK.fullmatch(path.name)
                if match and now - info.st_mtime >= 2 * 86400 and 0 < info.st_size <= MAX_HASH_BYTES:
                    version, abi = match.groups()
                    permanent = downloads / version / f'QuantumVPN-{version}-operator-debug-{abi}.apk'
                    if permanent.parent.is_symlink():
                        continue
                    other = _regular(permanent)
                    if other and other.st_size == info.st_size and _digest(path) == _digest(permanent):
                        retained = str(permanent)
                        reason = 'verified_duplicate_apk'
            if not reason:
                continue
            # Recheck inode/mtime/size immediately before unlink, so a new
            # producer file cannot be removed using an old inspection result.
            fresh = _regular(path)
            if fresh is None or (fresh.st_ino, fresh.st_size, fresh.st_mtime_ns) != (info.st_ino, info.st_size, info.st_mtime_ns):
                continue
            if path.resolve().parent != folder.resolve():
                continue
            if apply:
                path.unlink()
            candidates.append({'name': path.name, 'bytes': info.st_size, 'reason': reason,
                               'removed': bool(apply), 'retained_copy': retained})
    return {'schema': 1, 'generated_at': now, 'apply': bool(apply),
            'files': candidates, 'reclaimed_bytes': sum(item['bytes'] for item in candidates) if apply else 0,
            'eligible_bytes': sum(item['bytes'] for item in candidates)}
