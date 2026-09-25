#!/usr/bin/env bash
# Install nginx as TLS frontend for QuantumVPN operator:
# - nginx:8443 SSL + sendfile for /downloads/ (legacy API base)
# - nginx:127.0.0.1:18766 HTTP for RosPanel/xray TLS fallback on :443
# - python operator on 127.0.0.1:18765 (plain HTTP)
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx

CERT=/var/lib/rospanel/certs/cert.pem
KEY=/var/lib/rospanel/certs/key.pem
test -f "$CERT"
test -f "$KEY"

ENV=/etc/quantumvpn-operator.env
sed -i 's|/key\.pemQV_BIND=|/key.pem\nQV_BIND=|g' "$ENV" || true
grep -q '^QV_PORT=' "$ENV" && sed -i 's/^QV_PORT=.*/QV_PORT=18765/' "$ENV" || echo 'QV_PORT=18765' >>"$ENV"
grep -q '^QV_BIND=' "$ENV" && sed -i 's/^QV_BIND=.*/QV_BIND=127.0.0.1/' "$ENV" || echo 'QV_BIND=127.0.0.1' >>"$ENV"
grep -q '^QV_TLS_TERMINATED=' "$ENV" && sed -i 's/^QV_TLS_TERMINATED=.*/QV_TLS_TERMINATED=1/' "$ENV" || echo 'QV_TLS_TERMINATED=1' >>"$ENV"
grep -q '^QV_BACKLOG=' "$ENV" && sed -i 's/^QV_BACKLOG=.*/QV_BACKLOG=512/' "$ENV" || echo 'QV_BACKLOG=512' >>"$ENV"
# APK URLs on :443 (mobile carriers often reset :8443 around ~30MB).
grep -q '^QV_DOWNLOAD_BASE=' "$ENV" && sed -i 's|^QV_DOWNLOAD_BASE=.*|QV_DOWNLOAD_BASE=https://pecaocek.ignorelist.com:8443|' "$ENV" || echo 'QV_DOWNLOAD_BASE=https://pecaocek.ignorelist.com:8443' >>"$ENV"
grep -q '^QV_PUBLIC_BASE=' "$ENV" && sed -i 's|^QV_PUBLIC_BASE=.*|QV_PUBLIC_BASE=https://pecaocek.ignorelist.com:8443|' "$ENV" || echo 'QV_PUBLIC_BASE=https://pecaocek.ignorelist.com:8443' >>"$ENV"

cat >/etc/sysctl.d/99-quantumvpn-downloads.conf <<'SYSCTL'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_slow_start_after_idle = 0
SYSCTL
sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-quantumvpn-downloads.conf || true

cat >/etc/nginx/sites-available/quantumvpn-operator <<'NGINX'
# Public APK path via RosPanel/xray HTTPS :443 fallback (dest 127.0.0.1:18766).
server {
    listen 127.0.0.1:18766;
    server_name pecaocek.ignorelist.com _;

    client_max_body_size 200m;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 120;
    send_timeout 600s;
    lingering_close on;
    lingering_time 30s;
    aio threads;
    directio 16m;
    output_buffers 2 1m;

    location /downloads/ {
        alias /var/www/quantumvpn/downloads/;
        types { application/vnd.android.package-archive apk; }
        default_type application/vnd.android.package-archive;
        add_header Accept-Ranges bytes always;
        add_header Cache-Control "public, max-age=60" always;
        max_ranges 16;
        gzip off;
    }

    # Preserve RosPanel decoy / admin on the original fallback target.
    location / {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_pass http://127.0.0.1:8080;
    }
}

# Legacy operator API + downloads on :8443.
server {
    listen 8443 ssl reuseport;
    listen [::]:8443 ssl reuseport;
    server_name pecaocek.ignorelist.com _;

    ssl_certificate     /var/lib/rospanel/certs/cert.pem;
    ssl_certificate_key /var/lib/rospanel/certs/key.pem;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_protocols       TLSv1.2 TLSv1.3;

    client_max_body_size 200m;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 120;
    keepalive_requests 1000;
    send_timeout 600s;
    lingering_close on;
    lingering_time 30s;
    aio threads;
    directio 16m;
    output_buffers 2 1m;

    location /downloads/ {
        alias /var/www/quantumvpn/downloads/;
        types { application/vnd.android.package-archive apk; }
        default_type application/vnd.android.package-archive;
        add_header Accept-Ranges bytes always;
        add_header Cache-Control "public, max-age=60" always;
        max_ranges 16;
        gzip off;
    }

    location / {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_pass http://127.0.0.1:18765;
    }
}
NGINX

ln -sfn /etc/nginx/sites-available/quantumvpn-operator /etc/nginx/sites-enabled/quantumvpn-operator
rm -f /etc/nginx/sites-enabled/default

install -d -m 755 /var/www/quantumvpn/downloads
chmod -R a+rX /var/www/quantumvpn/downloads || true

# Point xray VLESS TLS fallback at nginx ONLY when explicitly enabled.
# Broken fallback (18766 without nginx) takes down https://pecaocek.ignorelist.com/:443.
if [[ "${QV_ENABLE_443_FALLBACK:-0}" == "1" && -f /var/lib/rospanel/xray/config.json ]]; then
  python3 - <<'PY'
import json
from pathlib import Path
path = Path("/var/lib/rospanel/xray/config.json")
data = json.loads(path.read_text(encoding="utf-8"))
changed = False
for inbound in data.get("inbounds", []):
    if inbound.get("tag") != "vless-in":
        continue
    fallbacks = inbound.setdefault("settings", {}).setdefault("fallbacks", [])
    if not fallbacks:
        fallbacks.append({"dest": "127.0.0.1:18766", "xver": 1})
        changed = True
    else:
        for item in fallbacks:
            if item.get("dest") in ("127.0.0.1:8080", "8080", "localhost:8080"):
                item["dest"] = "127.0.0.1:18766"
                item["xver"] = int(item.get("xver") or 1)
                changed = True
        if not any(item.get("dest") == "127.0.0.1:18766" for item in fallbacks):
            fallbacks.insert(0, {"dest": "127.0.0.1:18766", "xver": 1})
            changed = True
if changed:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("xray_fallback=127.0.0.1:18766")
else:
    print("xray_fallback_unchanged")
PY
  systemctl restart xray 2>/dev/null || systemctl restart rospanel || true
fi

systemctl restart quantumvpn-operator
sleep 1
systemctl is-active --quiet quantumvpn-operator
nginx -t
systemctl enable nginx
systemctl restart nginx
systemctl is-active --quiet nginx

ss -lntp | grep -E ':8443|:18765|:18766|:443' || true
echo 'nginx TLS frontend for /downloads ready (8443 + :443 fallback)'
