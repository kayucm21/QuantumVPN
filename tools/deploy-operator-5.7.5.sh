#!/usr/bin/env bash
set -euo pipefail

version='5.7.5'
version_code='104'
release="/var/www/quantumvpn/downloads/$version"

python3 -m py_compile /tmp/quantumvpn_operator_panel.py

arm64_sum=$(sha256sum /tmp/QuantumVPN-5.7.5-operator-debug-arm64-v8a.apk | awk '{print $1}')
armv7_sum=$(sha256sum /tmp/QuantumVPN-5.7.5-operator-debug-armeabi-v7a.apk | awk '{print $1}')
printf '%s  %s\n' "$arm64_sum" /tmp/QuantumVPN-5.7.5-operator-debug-arm64-v8a.apk | sha256sum -c -
printf '%s  %s\n' "$armv7_sum" /tmp/QuantumVPN-5.7.5-operator-debug-armeabi-v7a.apk | sha256sum -c -

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

backup="/opt/quantumvpn-operator/app.py.before-$version-orbit"
test -f "$backup" || cp -p /opt/quantumvpn-operator/app.py "$backup"
install -m 750 /tmp/quantumvpn_operator_panel.py /opt/quantumvpn-operator/app.py

python3 - "$version" "$version_code" <<'PY'
import sqlite3
import sys
import time

version, version_code = sys.argv[1:3]
db = sqlite3.connect("/var/lib/quantumvpn-operator/operator.db")
values = {
    "app_version": version,
    "app_version_code": version_code,
    "rollout_percent": "100",
    "update_notifications_enabled": "1",
    "maintenance": "0",
    "feature_vpn_connect": "1",
    "announce": "Доступно обновление QuantumVPN 5.7.5 — Liquid Glass Orbit. Откройте приложение для загрузки.",
    "announce_en": "QuantumVPN 5.7.5 Liquid Glass Orbit is available. Open the app to download.",
    "app_changelog": (
        "QuantumVPN 5.7.5 Liquid Glass Orbit: проверка обновления на сплэше, "
        "новый интерфейс, быстрая вкладка устройств."
    ),
}
for key, value in values.items():
    db.execute("insert or replace into settings(key,value) values (?,?)", (key, value))

banner = "Доступно обновление QuantumVPN 5.7.5 (Liquid Glass Orbit). Откройте приложение — загрузка начнётся автоматически."
now = int(time.time())
devices = db.execute(
    """
    select distinct device from events
    where kind='policy' and ts > ?
    order by ts desc
    limit 5000
    """,
    (now - 90 * 86400,),
).fetchall()
for (device,) in devices:
    if not device:
        continue
    db.execute(
        """
        insert into device_flags(device,force_banner,request_diagnostic,note,updated_at)
        values (?,?,?,?,?)
        on conflict(device) do update set
          force_banner=excluded.force_banner,
          updated_at=excluded.updated_at
        """,
        (device, banner, 0, "orbit-notify", now),
    )
db.commit()
db.close()
print(f"notified_devices={len(devices)}")
PY

systemctl restart quantumvpn-operator
systemctl is-active --quiet quantumvpn-operator

python3 - <<'PY'
import os, sqlite3, urllib.parse, urllib.request
db = sqlite3.connect("/var/lib/quantumvpn-operator/operator.db")
s = dict(db.execute("select key,value from settings").fetchall())
db.close()
token = (s.get("telegram_bot_token") or "").strip()
chat = (s.get("telegram_chat_id") or "").strip()
if token and chat:
    text = (
        "[QuantumVPN] 5.7.5 Liquid Glass Orbit выложен. "
        "Оповещения об обновлении включены для всех устройств."
    )
    data = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=data,
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10).read()
        print("telegram_ok")
    except Exception as exc:
        print(f"telegram_fail:{exc}")
else:
    print("telegram_skipped")
PY

rm -f \
  /tmp/QuantumVPN-5.7.5-operator-debug-arm64-v8a.apk \
  /tmp/QuantumVPN-5.7.5-operator-debug-armeabi-v7a.apk \
  /tmp/QuantumVPN-5.7.5-operator-debug-arm64-v8a.apk.sha256 \
  /tmp/QuantumVPN-5.7.5-operator-debug-armeabi-v7a.apk.sha256 \
  /tmp/release-metadata.json /tmp/build-info.txt /tmp/RELEASE_NOTES.md \
  /tmp/quantumvpn_operator_panel.py /tmp/deploy-operator-5.7.5.sh

echo 'QuantumVPN 5.7.5 Liquid Glass Orbit deployed'
