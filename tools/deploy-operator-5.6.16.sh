#!/usr/bin/env bash
set -euo pipefail

python3 -m py_compile /tmp/quantumvpn_operator_panel.py
printf '%s  %s\n' \
  '3f9370bcdfa98d33f272276f425098917f81d7e2b5fcbe60c8b948ae68ab9b7c' '/tmp/QuantumVPN-5.6.16-operator-debug-arm64-v8a.apk' \
  '2e1b631c4e125a44c90a8abe3ba28671301ea629ba3d34b71c34fa5cd65c6501' '/tmp/QuantumVPN-5.6.16-operator-debug-armeabi-v7a.apk' \
  | sha256sum -c -

release='/var/www/quantumvpn/downloads/5.6.16'
install -d -m 755 "$release"
install -m 644 /tmp/QuantumVPN-5.6.16-operator-debug-arm64-v8a.apk "$release/QuantumVPN-5.6.16-operator-debug-arm64-v8a.apk"
install -m 644 /tmp/QuantumVPN-5.6.16-operator-debug-armeabi-v7a.apk "$release/QuantumVPN-5.6.16-operator-debug-armeabi-v7a.apk"
install -m 644 /tmp/QuantumVPN-5.6.16-operator-debug-arm64-v8a.apk.sha256 "$release/QuantumVPN-5.6.16-operator-debug-arm64-v8a.apk.sha256"
install -m 644 /tmp/QuantumVPN-5.6.16-operator-debug-armeabi-v7a.apk.sha256 "$release/QuantumVPN-5.6.16-operator-debug-armeabi-v7a.apk.sha256"
install -m 644 /tmp/release-metadata.json "$release/release-metadata.json"
install -m 644 /tmp/build-info.txt "$release/build-info.txt"

backup="/opt/quantumvpn-operator/app.py.before-5.6.16"
test -f "$backup" || cp -p /opt/quantumvpn-operator/app.py "$backup"
install -m 750 /tmp/quantumvpn_operator_panel.py /opt/quantumvpn-operator/app.py
systemctl restart quantumvpn-operator
systemctl is-active --quiet quantumvpn-operator

rm -f \
  /tmp/QuantumVPN-5.6.16-operator-debug-arm64-v8a.apk \
  /tmp/QuantumVPN-5.6.16-operator-debug-armeabi-v7a.apk \
  /tmp/QuantumVPN-5.6.16-operator-debug-arm64-v8a.apk.sha256 \
  /tmp/QuantumVPN-5.6.16-operator-debug-armeabi-v7a.apk.sha256 \
  /tmp/release-metadata.json /tmp/build-info.txt \
  /tmp/quantumvpn_operator_panel.py /tmp/deploy-operator-5.6.16.sh

echo 'QuantumVPN 5.6.16 deployed'
