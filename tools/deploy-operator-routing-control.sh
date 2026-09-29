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
# The application port is intentionally read from the environment file: it is
# not always the public nginx port and must not be hard-coded to an old value.
operator_port="$(sed -n 's/^QV_PORT=//p' /etc/quantumvpn-operator.env | head -n 1)"
case "$operator_port" in
  ''|*[!0-9]*) echo 'QV_PORT is missing or invalid' >&2; exit 1 ;;
esac
for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:${operator_port}/api/client/routing" >/dev/null 2>&1; then
    echo "Quantum Control routing centre deployed"
    exit 0
  fi
  sleep 0.5
done

echo "Operator did not become ready after restart" >&2
exit 1
