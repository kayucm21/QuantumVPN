#!/usr/bin/env bash
set -euo pipefail

version='5.8.0'
version_code='114'
release="/var/www/quantumvpn/downloads/$version"

python3 -m py_compile /tmp/quantumvpn_operator_panel.py
arm64_sum=$(sha256sum "/tmp/QuantumVPN-$version-operator-debug-arm64-v8a.apk" | awk '{print $1}')
armv7_sum=$(sha256sum "/tmp/QuantumVPN-$version-operator-debug-armeabi-v7a.apk" | awk '{print $1}')
printf '%s  %s\n' "$arm64_sum" "/tmp/QuantumVPN-$version-operator-debug-arm64-v8a.apk" | sha256sum -c -
printf '%s  %s\n' "$armv7_sum" "/tmp/QuantumVPN-$version-operator-debug-armeabi-v7a.apk" | sha256sum -c -

install -d -m 755 "$release"
for file in \
  "QuantumVPN-$version-operator-debug-arm64-v8a.apk" \
  "QuantumVPN-$version-operator-debug-armeabi-v7a.apk" \
  "QuantumVPN-$version-operator-debug-arm64-v8a.apk.sha256" \
  "QuantumVPN-$version-operator-debug-armeabi-v7a.apk.sha256" \
  release-metadata.json build-info.txt RELEASE_NOTES.md
do
  install -m 644 "/tmp/$file" "$release/$file"
done
if [[ -f /tmp/update.html ]]; then
  install -d -m 755 /var/www/quantumvpn/www
  install -m 644 /tmp/update.html /var/www/quantumvpn/www/update.html
  install -m 644 /tmp/update.html /var/www/quantumvpn/downloads/update.html
fi
chmod -R a+rX /var/www/quantumvpn/downloads

backup="/opt/quantumvpn-operator/app.py.before-$version"
test -f "$backup" || cp -p /opt/quantumvpn-operator/app.py "$backup"
install -m 750 /tmp/quantumvpn_operator_panel.py /opt/quantumvpn-operator/app.py

ENV=/etc/quantumvpn-operator.env
grep -q '^QV_DOWNLOAD_BASE=' "$ENV" && sed -i 's|^QV_DOWNLOAD_BASE=.*|QV_DOWNLOAD_BASE=https://pecaocek.ignorelist.com:8443|' "$ENV" || echo 'QV_DOWNLOAD_BASE=https://pecaocek.ignorelist.com:8443' >>"$ENV"
if [[ -f /tmp/setup-nginx-downloads.sh ]]; then
  bash /tmp/setup-nginx-downloads.sh || true
fi

python3 - "$version" "$version_code" <<'PY'
import sqlite3, sys, time
version, version_code = sys.argv[1:3]
db = sqlite3.connect("/var/lib/quantumvpn-operator/operator.db")
now = int(time.time())
rev = int((db.execute("select value from settings where key='config_revision'").fetchone() or ["1"])[0] or 1) + 1
values = {
    "app_version": version,
    "app_version_code": version_code,
    "rollout_percent": "100",
    "update_notifications_enabled": "1",
    "maintenance": "0",
    "feature_vpn_connect": "1",
    "feature_adblock": "1",
    "feature_auto_connect": "1",
    "feature_auto_failover": "1",
    "feature_selfsteal": "1",
    "config_revision": str(rev),
    "announce": "Доступен QuantumVPN 5.8.0: Smart Connect, авто-переход Wi‑Fi/LTE, центр уведомлений и Aurora Glass.",
    "announce_en": "QuantumVPN 5.8.0 is available: Smart Connect, Wi-Fi/LTE handoff, notification center and Aurora Glass.",
    "app_changelog": "Smart Connect; смена Wi‑Fi/LTE с контролируемым переподключением; центр уведомлений; Dynamic Color; обновлённый виджет; health-мониторинг панели.",
}
for key, value in values.items():
    db.execute("insert or replace into settings(key,value) values (?,?)", (key, value))
banner = "Доступно обновление QuantumVPN 5.8.0. Откройте приложение — после загрузки Android предложит установить или отменить."
devices = db.execute(
    "select distinct device from events where kind='policy' and ts > ? order by ts desc limit 5000",
    (now - 365 * 86400,),
).fetchall()
for (device,) in devices:
    if not device:
        continue
    db.execute(
        """
        insert into device_flags(device,force_banner,request_diagnostic,note,updated_at)
        values (?,?,?,?,?)
        on conflict(device) do update set force_banner=excluded.force_banner, updated_at=excluded.updated_at
        """,
        (device, banner, 0, "5.8.0-release", now),
    )
db.commit()
db.close()
print(f"notified_devices={len(devices)} config_revision={rev}")
PY

systemctl restart quantumvpn-operator
systemctl is-active --quiet quantumvpn-operator
echo 'QuantumVPN 5.8.0 deployed'
rm -f "/tmp/QuantumVPN-$version-operator-debug-*.apk" \
  "/tmp/QuantumVPN-$version-operator-debug-*.apk.sha256" \
  /tmp/release-metadata.json /tmp/build-info.txt /tmp/RELEASE_NOTES.md /tmp/update.html \
  /tmp/quantumvpn_operator_panel.py /tmp/deploy-operator-5.8.0.sh /tmp/setup-nginx-downloads.sh
