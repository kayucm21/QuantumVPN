#!/usr/bin/env bash
# Install an active ModSecurity/OWASP CRS WAF in front of Quantum Control.
#
# Scope is deliberately limited to /operator and /operator/* on nginx:8443.
# APK downloads, public client APIs and the RosPanel route keep their existing
# fast paths.  /operator/upload is authenticated by the application and is
# excluded from body inspection because APK files may be hundreds of MB.
set -euo pipefail

SITE=/etc/nginx/sites-available/quantumvpn-operator
WAF_RULES=/etc/nginx/modsecurity-quantum-operator.conf
WAF_LIMITS=/etc/nginx/conf.d/quantumvpn-operator-waf-limits.conf
WAF_LOGROTATE=/etc/logrotate.d/quantumvpn-operator-waf
BACKUP_DIR=/root/quantumvpn-backups
STAMP=$(date +%Y%m%d-%H%M%S)

test -f "$SITE"
install -d -m 700 "$BACKUP_DIR"
cp -a "$SITE" "$BACKUP_DIR/quantumvpn-operator.before-waf-$STAMP.conf"
[[ -f "$WAF_RULES" ]] && cp -a "$WAF_RULES" "$BACKUP_DIR/modsecurity-quantum-operator.before-waf-$STAMP.conf" || true
[[ -f "$WAF_LIMITS" ]] && cp -a "$WAF_LIMITS" "$BACKUP_DIR/quantumvpn-operator-waf-limits.before-waf-$STAMP.conf" || true
[[ -f "$WAF_LOGROTATE" ]] && cp -a "$WAF_LOGROTATE" "$BACKUP_DIR/quantumvpn-operator-waf-logrotate.before-waf-$STAMP.conf" || true

restore() {
  cp -af "$BACKUP_DIR/quantumvpn-operator.before-waf-$STAMP.conf" "$SITE"
  if [[ -f "$BACKUP_DIR/modsecurity-quantum-operator.before-waf-$STAMP.conf" ]]; then
    cp -af "$BACKUP_DIR/modsecurity-quantum-operator.before-waf-$STAMP.conf" "$WAF_RULES"
  else
    rm -f "$WAF_RULES"
  fi
  if [[ -f "$BACKUP_DIR/quantumvpn-operator-waf-limits.before-waf-$STAMP.conf" ]]; then
    cp -af "$BACKUP_DIR/quantumvpn-operator-waf-limits.before-waf-$STAMP.conf" "$WAF_LIMITS"
  else
    rm -f "$WAF_LIMITS"
  fi
  if [[ -f "$BACKUP_DIR/quantumvpn-operator-waf-logrotate.before-waf-$STAMP.conf" ]]; then
    cp -af "$BACKUP_DIR/quantumvpn-operator-waf-logrotate.before-waf-$STAMP.conf" "$WAF_LOGROTATE"
  else
    rm -f "$WAF_LOGROTATE"
  fi
  nginx -t && systemctl reload nginx || true
}
trap restore ERR

export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends libnginx-mod-http-modsecurity modsecurity-crs

# Nginx's worker user needs only the ModSecurity runtime state directories.
install -d -o www-data -g www-data -m 700 /var/cache/modsecurity/tmp /var/cache/modsecurity/data

cat >"$WAF_RULES" <<'RULES'
# Quantum Control WAF: active OWASP CRS on the operator route only.
Include /etc/nginx/modsecurity.conf

SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 33554432
SecRequestBodyNoFilesLimit 1048576
SecRequestBodyLimitAction Reject
SecResponseBodyAccess Off
SecTmpDir /var/cache/modsecurity/tmp
SecDataDir /var/cache/modsecurity/data
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/nginx/modsec_quantum_operator_audit.log

# OWASP CRS paranoia level 1 is the stable baseline for an operator panel.
# Ubuntu's helper file uses Apache's IncludeOptional directive, which the
# ModSecurity-nginx connector does not parse.  These four files are installed
# by the package and keep the same load order without that incompatibility.
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
Include /usr/share/modsecurity-crs/rules/*.conf
Include /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf

# The panel only needs browser/API methods.  Reject unexpected verbs early.
SecRule REQUEST_METHOD "!@within GET HEAD POST OPTIONS" "id:1001001,phase:1,deny,status:405,log,auditlog,msg:'Quantum Control: method not allowed'"

# RosPanel operators legitimately save Russian UTF-8 maintenance notices,
# category labels and release notes. CRS 941310 mistakes certain UTF-8 byte
# sequences for malformed XSS and answers 403 before the authenticated panel
# can receive the form. Narrowly remove only that false positive on the policy
# endpoint; output is HTML-escaped by the application and the rest of CRS stays
# active. CRS 920220 similarly misreads the panel's URL-encoded Cyrillic flash
# messages after a successful redirect.
SecRule REQUEST_URI "@beginsWith /operator/policy" "id:1001002,phase:1,pass,nolog,ctl:ruleRemoveById=941310"
SecRule REQUEST_URI "@beginsWith /operator" "id:1001003,phase:1,pass,nolog,ctl:ruleRemoveById=920220"
RULES
chmod 640 "$WAF_RULES"

cat >"$WAF_LIMITS" <<'LIMITS'
# Per-IP protection for the management panel.  It is intentionally separate
# from /downloads and /api/client so Android updates cannot be rate-limited.
limit_req_zone $binary_remote_addr zone=quantum_operator:10m rate=20r/m;
limit_conn_zone $binary_remote_addr zone=quantum_operator_conn:10m;
LIMITS
chmod 644 "$WAF_LIMITS"

cat >"$WAF_LOGROTATE" <<'ROTATE'
/var/log/nginx/modsec_quantum_operator_audit.log {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
ROTATE
chmod 644 "$WAF_LOGROTATE"

export QV_WAF_SITE="$SITE"
python3 - <<'PY'
from pathlib import Path
import os

path = Path(os.environ["QV_WAF_SITE"])
text = path.read_text(encoding="utf-8")
begin = "    # BEGIN QUANTUM CONTROL WAF\n"
end = "    # END QUANTUM CONTROL WAF\n"
if begin in text:
    text = text[:text.index(begin)] + text[text.index(end, text.index(begin)) + len(end):]

# The extra panel is proxied to the local Python service.  Insert the WAF
# locations directly before that generic fallback, preserving RosPanel's
# separately configured locations in the same virtual host.
needle = "proxy_pass http://127.0.0.1:18765;"
proxy_at = text.rfind(needle)
if proxy_at < 0:
    raise SystemExit("Quantum Control upstream was not found in nginx site")
location_at = text.rfind("    location ", 0, proxy_at)
if location_at < 0:
    raise SystemExit("Quantum Control fallback location was not found")

proxy = """        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_pass http://127.0.0.1:18765;
"""
waf = """    # BEGIN QUANTUM CONTROL WAF
    # APK uploads are authenticated by Quantum Control but skip inspection so
    # ModSecurity never buffers a large APK in memory.
    location = /operator/upload {
        limit_req zone=quantum_operator burst=4 nodelay;
        limit_conn quantum_operator_conn 4;
        modsecurity off;
""" + proxy + """    }

    location = /operator {
        limit_req zone=quantum_operator burst=30 nodelay;
        limit_conn quantum_operator_conn 12;
        modsecurity on;
        modsecurity_rules_file /etc/nginx/modsecurity-quantum-operator.conf;
""" + proxy + """    }

    location ^~ /operator/ {
        limit_req zone=quantum_operator burst=30 nodelay;
        limit_conn quantum_operator_conn 12;
        modsecurity on;
        modsecurity_rules_file /etc/nginx/modsecurity-quantum-operator.conf;
""" + proxy + """    }
    # END QUANTUM CONTROL WAF

"""
path.write_text(text[:location_at] + waf + text[location_at:], encoding="utf-8")
PY

nginx -t
systemctl reload nginx
systemctl is-active --quiet nginx
trap - ERR
echo "Quantum Control WAF active; backup: $BACKUP_DIR/quantumvpn-operator.before-waf-$STAMP.conf"
