"""Pinned, fail-closed compatibility for Telegram iOS's broken SNI envelope.

Only the 517-byte legacy iOS GREASE-wrapped configured hostname is recognized.
The original HMAC, timestamp, replay and cipher checks remain byte-identical.
No network, process or file operations are performed by this module.
"""
from __future__ import annotations

import hashlib

COMMIT = 'f36d8af769ffaeac36978d38c2c0f6d1104c2137'
TREE = 'a6d7476f22881f8cd3396077e80286e0ac15502f'
NET_SOURCE_SHA256 = '44442dccdbd5e26716bd3d1d11ad4995f949585a514f0a923168bb59c9c5b856'
PATCH_ID = 'ios-grease-sni-compat-v1'
SOURCE_URL = 'https://github.com/TelegramMessenger/Telegram-iOS/blob/5145b9e/submodules/MtProtoKit/Sources/MTTcpConnection.m'

HELPER = r'''/* QuantumVPN: recognize only the authenticated legacy iOS SNI shape.
 * Do not rewrite ClientHello: the original HMAC/time/replay checks below still
 * authenticate its complete, unmodified bytes before any MTProto service. */
static unsigned int qvpn_ios_domain_count;
static const struct domain_info *qvpn_ios_domain_info (const unsigned char *r, int len) {
  static const unsigned char header[] = {0x16,3,1,2,0,1,0,1,0xfc,3,3};
  static const int ids[] = {-1,23,0xff01,10,11,16,5,13,18,51,45,43,27,-1,21};
  if (qvpn_ios_domain_count != 1 || !default_domain_info || len != 517 ||
      memcmp (r, header, sizeof(header)) || r[43] != 32) { return NULL; }
  int pos = 76;
  int n = 256 * r[pos] + r[pos + 1]; pos += 2;
  if (n < 2 || (n & 1) || n > len - pos - 4) { return NULL; }
  pos += n;
  if (r[pos++] != 1 || r[pos++] != 0) { return NULL; }
  n = 256 * r[pos] + r[pos + 1]; pos += 2;
  if (n != len - pos) { return NULL; }
  int index = 0;
  while (pos < len) {
    if (index >= (int)(sizeof(ids) / sizeof(ids[0])) || len - pos < 4) { return NULL; }
    int id = 256 * r[pos] + r[pos + 1]; pos += 2;
    int size = 256 * r[pos] + r[pos + 1]; pos += 2;
    if (size > len - pos || id == 0) { return NULL; }
    if (ids[index] == -1) {
      if ((id & 0x0f0f) != 0x0a0a || (id >> 8) != (id & 255)) { return NULL; }
    } else if (id != ids[index]) { return NULL; }
    if (index == 0) {
      size_t d = strlen (default_domain_info->domain);
      if (d < 3 || d > 253 || size != (int)d + 5 ||
          256 * r[pos] + r[pos + 1] != (int)d + 3 || r[pos + 2] != 0 ||
          256 * r[pos + 3] + r[pos + 4] != (int)d ||
          memcmp (r + pos + 5, default_domain_info->domain, d)) { return NULL; }
    }
    if (id == 21) {
      int i; for (i = 0; i < size; i++) { if (r[pos + i]) { return NULL; } }
    }
    pos += size; index++;
  }
  if (index != (int)(sizeof(ids) / sizeof(ids[0]))) { return NULL; }
  return default_domain_info;
}

'''
ANCHOR = 'static const struct domain_info *get_sni_domain_info (const unsigned char *request, int len) {'
DOMAIN_ANCHOR = 'void tcp_rpc_add_proxy_domain (const char *domain) {\n  assert (domain != NULL);'
SELECT_ANCHOR = '        const struct domain_info *info = get_sni_domain_info (client_hello, read_len);\n'


def patch_source(raw: bytes) -> bytes:
    if hashlib.sha256(raw).hexdigest() != NET_SOURCE_SHA256:
        raise RuntimeError('pinned_net_source_identity_required')
    source = raw.decode('utf-8')
    for anchor in (ANCHOR, DOMAIN_ANCHOR, SELECT_ANCHOR):
        if source.count(anchor) != 1:
            raise RuntimeError('ios_patch_anchor_mismatch')
    start = source.index('        unsigned char client_random[32];')
    end = source.index('        int pos = 76;', start)
    authentication = source[start:end]
    source = source.replace(ANCHOR, HELPER + ANCHOR)
    source = source.replace(DOMAIN_ANCHOR, DOMAIN_ANCHOR + '\n  qvpn_ios_domain_count++;')
    source = source.replace(SELECT_ANCHOR, SELECT_ANCHOR +
                            '        if (info == NULL) { info = qvpn_ios_domain_info (client_hello, read_len); }\n')
    if source[source.index('        unsigned char client_random[32];'):source.index('        int pos = 76;', source.index('        unsigned char client_random[32];'))] != authentication:
        raise RuntimeError('authentication_block_changed')
    return source.encode('utf-8')


def matches_legacy_envelope(wire: bytes, domain: str, *, configured_domains: int = 1) -> bool:
    """Independent Python oracle for offline C-helper boundary cases, no auth.

    True is only an envelope match, never permission to connect. The native
    binary must subsequently require its original secret/time/replay checks.
    """
    if configured_domains != 1 or len(wire) != 517 or wire[:11] != bytes.fromhex('1603010200010001fc0303') or wire[43] != 32:
        return False
    name = domain.encode('ascii')
    if not 3 <= len(name) <= 253:
        return False
    def word(pos): return int.from_bytes(wire[pos:pos + 2], 'big')
    pos = 78
    size = word(76)
    if size < 2 or size & 1 or size > len(wire) - pos - 4:
        return False
    pos += size
    if wire[pos:pos + 2] != b'\x01\0':
        return False
    pos += 2
    size = word(pos); pos += 2
    if size != len(wire) - pos:
        return False
    ids = (-1, 23, 0xff01, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, -1, 21)
    index = 0
    while pos < len(wire):
        if index >= len(ids) or len(wire) - pos < 4:
            return False
        kind, size = word(pos), word(pos + 2); pos += 4
        if size > len(wire) - pos or kind == 0:
            return False
        if ids[index] == -1:
            if kind & 0x0f0f != 0x0a0a or kind >> 8 != kind & 255:
                return False
        elif kind != ids[index]:
            return False
        value = wire[pos:pos + size]
        if index == 0 and value != (len(name) + 3).to_bytes(2, 'big') + b'\0' + len(name).to_bytes(2, 'big') + name:
            return False
        if kind == 21 and any(value):
            return False
        pos += size; index += 1
    return index == len(ids)
