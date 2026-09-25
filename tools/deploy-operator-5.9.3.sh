#!/usr/bin/env bash
set -euo pipefail

version='5.9.3'
version_code='118'
release="/var/www/quantumvpn/downloads/$version"

python3 -m py_compile /tmp/quantumvpn_operator_panel.py
arm64_sum=$(sha256sum "/tmp/QuantumVPN-$version-operator-debug-arm64-v8a.apk" | awk '{print $1}')
armv7_sum=$(sha256sum "/tmp/QuantumVPN-$version-operator-debug-armeabi-v7a.apk" | awk '{print $1}')
echo "$arm64_sum  /tmp/QuantumVPN-$version-operator-debug-arm64-v8a.apk" | sha256sum -c -
echo "$armv7_sum  /tmp/QuantumVPN-$version-operator-debug-armeabi-v7a.apk" | sha256sum -c -

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
if [[ -f /tmp/setup-nginx-downloads.sh ]]; then bash /tmp/setup-nginx-downloads.sh || true; fi

# Upload now, but keep the current production release until the next 21:00 Moscow time.
python3 - "$version" "$version_code" <<'PY'
import datetime, sqlite3, sys, time
from zoneinfo import ZoneInfo
version, version_code = sys.argv[1:3]
tz = ZoneInfo("Europe/Moscow")
now = datetime.datetime.now(tz)
target = now.replace(hour=21, minute=0, second=0, microsecond=0)
if target <= now:
    target += datetime.timedelta(days=1)
publish_at = int(target.timestamp())
db = sqlite3.connect("/var/lib/quantumvpn-operator/operator.db")
values = {
    "release_schedule_enabled": "1",
    "release_publish_at": str(publish_at),
    "scheduled_app_version": version,
    "scheduled_app_version_code": version_code,
    "scheduled_rollout_percent": "100",
    "scheduled_min_version_code": "0",
    "scheduled_app_changelog": "Удалённое оформление без пересборки; живой мониторинг; DNS-фильтр и Kill Switch; безопасные обновления.",
    "update_notifications_enabled": "1",
    "announce": f"Сегодня в 21:00 по МСК доступно обновление QuantumVPN {version}: удалённое оформление и живой мониторинг.",
    "announce_en": f"QuantumVPN {version} with remote branding and live health monitoring will be available at 21:00 Moscow time.",
    "force_update_message": f"Сегодня в 21:00 по МСК будет доступно обновление QuantumVPN {version}.",
    "app_changelog": "Запланировано на 21:00 МСК: удалённое оформление, DNS-фильтр, Kill Switch и мониторинг нод.",
}
for key, value in values.items():
    db.execute("insert or replace into settings(key,value) values (?,?)", (key, value))
db.execute("insert into events values (?,?,?,?,?)", (int(time.time()), "release_scheduled", "operator", "", version + " at " + target.isoformat()))
db.commit()
db.close()
print("scheduled_publish_moscow=" + target.isoformat())
PY

systemctl restart quantumvpn-operator
systemctl is-active --quiet quantumvpn-operator
echo "QuantumVPN $version uploaded; scheduled for 21:00 Europe/Moscow"
rm -f "/tmp/QuantumVPN-$version-operator-debug-"*.apk \
  "/tmp/QuantumVPN-$version-operator-debug-"*.apk.sha256 \
  /tmp/release-metadata.json /tmp/build-info.txt /tmp/RELEASE_NOTES.md /tmp/update.html \
  /tmp/quantumvpn_operator_panel.py "/tmp/deploy-operator-$version.sh" /tmp/setup-nginx-downloads.sh
