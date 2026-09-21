#!/usr/bin/env bash
set -euo pipefail

version='5.7.5'
version_code='103'
release="/var/www/quantumvpn/downloads/$version"

python3 -m py_compile /tmp/quantumvpn_operator_panel.py
printf '%s  %s\n' \
  '1b531e225412f0a9ff677cad6503623bb6b1f3ce25a9d1f1d1880bf4a5d70996' '/tmp/QuantumVPN-5.7.5-operator-debug-arm64-v8a.apk' \
  '3a942c7a4bb838bfbb3290acdb51d506b1226092f0325bf486400f86f86ca74a' '/tmp/QuantumVPN-5.7.5-operator-debug-armeabi-v7a.apk' \
  | sha256sum -c -

install -d -m 755 "$release"
for file in \
  QuantumVPN-5.7.5-operator-debug-arm64-v8a.apk \
  QuantumVPN-5.7.5-operator-debug-armeabi-v7a.apk \
  QuantumVPN-5.7.5-operator-debug-arm64-v8a.apk.sha256 \
  QuantumVPN-5.7.5-operator-debug-armeabi-v7a.apk.sha256 \
  release-metadata.json build-info.txt RELEASE_NOTES.md
do
  install -m 644 "/tmp/$file" "$release/$file"
done

backup="/opt/quantumvpn-operator/app.py.before-$version"
test -f "$backup" || cp -p /opt/quantumvpn-operator/app.py "$backup"
install -m 750 /tmp/quantumvpn_operator_panel.py /opt/quantumvpn-operator/app.py

python3 - "$version" "$version_code" <<'PY'
import sqlite3
import sys

version, version_code = sys.argv[1:3]
db = sqlite3.connect("/var/lib/quantumvpn-operator/operator.db")
values = {
    "app_version": version,
    "app_version_code": version_code,
    "rollout_percent": "100",
    "app_changelog": (
        "QuantumVPN 5.7.5: интерфейс открывается до проверки обновлений; "
        "исправлены темы Aurora и раздел конфиденциальности; "
        "возвращена полная VPN-архитектура."
    ),
}
for key, value in values.items():
    db.execute("insert or replace into settings(key,value) values (?,?)", (key, value))
db.commit()
db.close()
PY

systemctl restart quantumvpn-operator
systemctl is-active --quiet quantumvpn-operator

rm -f \
  /tmp/QuantumVPN-5.7.5-operator-debug-arm64-v8a.apk \
  /tmp/QuantumVPN-5.7.5-operator-debug-armeabi-v7a.apk \
  /tmp/QuantumVPN-5.7.5-operator-debug-arm64-v8a.apk.sha256 \
  /tmp/QuantumVPN-5.7.5-operator-debug-armeabi-v7a.apk.sha256 \
  /tmp/release-metadata.json /tmp/build-info.txt /tmp/RELEASE_NOTES.md \
  /tmp/quantumvpn_operator_panel.py /tmp/deploy-operator-5.7.5.sh

echo 'QuantumVPN 5.7.5 deployed'
