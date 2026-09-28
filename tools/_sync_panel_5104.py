from __future__ import annotations

import os
import sys
from pathlib import Path

import paramiko


ROOT = Path(__file__).resolve().parents[1]
VERSION = "5.10.4"
HOST = "150.241.96.191"


def run(client: paramiko.SSHClient, command: str) -> None:
    _, stdout, stderr = client.exec_command(command, timeout=120)
    output = stdout.read().decode("utf-8", "replace")
    error = stderr.read().decode("utf-8", "replace")
    status = stdout.channel.recv_exit_status()
    if status != 0:
        raise RuntimeError(f"remote command failed ({status}): {command}\n{output}\n{error}")


def main() -> None:
    password = os.environ.get("QVPN_VDS_PASSWORD")
    if not password:
        raise SystemExit("QVPN_VDS_PASSWORD is required")
    panel = ROOT / "tools" / "quantumvpn_operator_panel.py"
    notes = ROOT / "artifacts" / VERSION / "RELEASE_NOTES.md"
    if not panel.is_file() or not notes.is_file():
        raise SystemExit("panel source or release notes are missing")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username="root", password=password, timeout=60, banner_timeout=90, auth_timeout=60, look_for_keys=False, allow_agent=False)
    try:
        with client.open_sftp() as sftp:
            sftp.put(str(panel), "/tmp/quantumvpn_operator_panel.py")
            sftp.put(str(notes), "/tmp/RELEASE_NOTES.md")
        run(client, "python3 -m py_compile /tmp/quantumvpn_operator_panel.py")
        run(client, "install -m 750 /tmp/quantumvpn_operator_panel.py /opt/quantumvpn-operator/app.py")
        run(client, f"install -m 644 /tmp/RELEASE_NOTES.md /var/www/quantumvpn/downloads/{VERSION}/RELEASE_NOTES.md")
        run(client, "systemctl restart quantumvpn-operator && systemctl is-active --quiet quantumvpn-operator")
        print("panel_synced", flush=True)
    finally:
        client.close()


if __name__ == "__main__":
    main()
