# MTProto FakeTLS iOS compatibility, 10 October 2026

## Observed failure and scope

The owner reports Android working and iPhones stuck on Connecting/Checking on
Wi-Fi and mobile. Exact installed Telegram/iOS versions were not supplied.
No physical iPhone was available: all results below are protocol-level tests,
not a claim that every user's device/network has been verified.

Before deployment the native owned endpoint `pecaocek.ignorelist.com:5443`
authenticated ordinary and modern iOS-shaped clients, including Telegram's
`resPQ` nonce. A reproduced legacy iOS 517-byte ClientHello was rejected before
FakeTLS authentication (`invalid_tls_record`).

The legacy shape is independently constructed from the length-placeholder
behavior in [Telegram-iOS commit 5145b9e](https://github.com/TelegramMessenger/Telegram-iOS/blob/5145b9e/submodules/MtProtoKit/Sources/MTTcpConnection.m).
Its hostname appears inside a GREASE extension rather than extension zero
(SNI). [Upstream issue 1912](https://github.com/TelegramMessenger/Telegram-iOS/issues/1912)
reports related behavior, but does not prove which version the owner's friends
use. Modern Safari-style larger ClientHello is tested separately from pinned
[iOS source](https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/MtProtoKit/Sources/MTTcpConnection.m).

## Narrow server fix

Only `quantumvpn-mtproto-tls.service` was restarted. Domain, port 5443, existing
client secret, unit and credential-file security patch were preserved. No APK,
VPN, subscriptions, DNS, nginx, padded 3443 service or WEB443 relay changed.

The server falls back only for the exact bounded legacy 517-byte extension
sequence, with exactly one configured cover domain whose hostname matches.
It does not accept arbitrary absent, malformed or unknown SNI. It never
rewrites ClientHello. Original full-packet HMAC, timestamp, replay and cipher
authentication code remains byte-identical.

Build provenance:

- Official MTProxy commit: `f36d8af769ffaeac36978d38c2c0f6d1104c2137`.
- Official tree: `a6d7476f22881f8cd3396077e80286e0ac15502f`.
- Base network source SHA-256: `44442dccdbd5e26716bd3d1d11ad4995f949585a514f0a923168bb59c9c5b856`.
- Compatibility patch: `ios-grease-sni-compat-v1`.
- Source fetched using HTTPS; commit/tree, full Git fsck and source digests
  checked. This is not a claim of an upstream signed commit.
- Compiler runs as the existing unprivileged service account, with restricted
  writable output directories, CPU/RAM limits and a bounded transient unit.

The private transaction backup is
`/var/lib/quantumvpn-mtproto-tls-ios-backups/txn-5mxv4r69`. It contains the original
binary/config and audited source/provenance, not an extra plaintext secret
copy. Runtime modules and retained original source tree were intentionally not
overwritten; config's `ios_compat` records the additional binary build patch.

## Verified after deployment

All three complete FakeTLS + Telegram nonce proofs passed:

| Client wire profile | VDS loopback | Public PC to VDS |
| --- | --- | --- |
| Standard | 19 ms | 314 ms |
| Legacy iOS GREASE/SNI defect | 10 ms | 233 ms |
| Modern iOS Safari/hybrid key-share shape | 18 ms | 268 ms |

These are one-shot protocol response times, not user application latency,
throughput measurements, or a guarantee about ISP filtering.

Mandatory negative checks passed: bad HMAC, expired timestamp, unknown explicit
SNI, unknown legacy cover hostname, valid-HMAC malformed envelope and replayed
ClientHello are rejected. A fresh valid legacy hello is accepted. Stats are
exclusively loopback; service active, 19 ready upstreams, zero proxy errors at
the post-restart snapshot. Guarded fingerprints of protected inputs matched.
130 scoped offline protocol, installer and proxy-monitor/link tests passed.
Repeat inspection returned `AlreadyPatched`, with all three public proofs and
all authentication-negative gates still passing, without another restart.
The read-only Network-center regression check also passed: both panels active,
four public ABI/API variants and HTTPS APK HEAD requests healthy at unchanged
5.11.4, WARP IPv4/IPv6 diagnostic probes healthy, six Network-center pages 200.

## Reverification and recovery

`tools/patch-mtproto-ios-vds.py` defaults to inspection. Explicit `--apply`
performs a guarded, idempotent hotfix; `--verify-public` adds external proofs.
SSH uses the pinned known-hosts file and transient `QVPN_VDS_PASSWORD`; secrets
are not logged, passed in argv, or committed. Diagnostic modules run in memory
without overwriting the approved existing runtime modules.

Before replacement a durable root-only transaction is written. Binary/config
replacements verify old hashes and are atomic. Failed post-install gates restore
only this transaction's original binary/config and restart only TLS5443.
Interrupted pending transactions require explicit apply to recover, refusing
foreign/concurrently changed identities. Exact owned build staging is removed;
the recoverable backup remains on VDS.

Next device gate: on an affected iPhone, disable VPN and toggle the existing
5443 proxy off/on. If Checking persists, collect exact Telegram/iOS version and
test both networks. No account login codes or proxy credentials are required
in diagnostics.
