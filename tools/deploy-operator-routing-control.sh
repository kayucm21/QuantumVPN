#!/usr/bin/env bash
# Deploy the operator routing control centre without touching APK artefacts,
# subscriptions, RosPanel, Xray, or nginx configuration.
set -euo pipefail

source_file=/tmp/quantumvpn_operator_panel.py
target_file=/opt/quantumvpn-operator/app.py
backup_file=/opt/quantumvpn-operator/app.py.before-5.10.7-control.2

python3 -m py_compile "$source_file"
test -f "$target_file"
test -f "$backup_file" || cp -p "$target_file" "$backup_file"
install -m 750 "$source_file" "$target_file"
python3 -m py_compile "$target_file"
systemctl restart quantumvpn-operator
systemctl is-active --quiet quantumvpn-operator

# The route policy is public configuration, so it is safe to use as a
# post-deploy smoke test. It must never include administrator credentials.
curl -fsSk https://127.0.0.1:8443/api/client/routing >/dev/null || \
  curl -fsS http://127.0.0.1:8765/api/client/routing >/dev/null

echo "Quantum Control routing centre deployed"
