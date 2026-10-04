# YouTube slowdown: server UDP repair, 4 October 2026

## Confirmed and changed

During a bounded transfer through the production loopback Xray SOCKS endpoint,
Linux recorded **4,466 new UDP receive-buffer errors** (InErrors and RcvbufErrors),
with 42,071 received datagrams. Existing Xray UDP sockets had only **212,992 bytes**
of receive capacity; several sockets also had substantial cumulative drop counts.
This proves a server receive-queue problem, not that every observed Android video
stall had exactly this cause. Namespace counters include concurrent user traffic.

Applied only three sysctls:

| Setting | Previous | Applied |
| --- | ---: | ---: |
| net.core.rmem_default | 212992 | 1048576 |
| net.core.rmem_max | 212992 | 16777216 |
| net.core.wmem_max | 212992 | 16777216 |

Persistent file: `/etc/sysctl.d/99-z-quantumvpn-udp-buffers.conf`.
Private rollback state (0600) retained on the VDS:
`/var/lib/quantumvpn-operator/performance-backups/udp-buffer-20261004T142516Z-6d2027164ddb413da27a5eac366c14fa.json`.

RosPanel was restarted to recreate old UDP sockets. The independent reserve
Trojan service, operator service and nginx remain active. A canonical comparison
confirmed that the generated Xray configuration did not change. Client keys,
subscriptions, Android DNS/routing, WARP pool, MTU, TCP and APK 5.11.2 were unchanged.
The initial SSH mutation reply was interrupted; a separate read-only check
confirmed the exact backup, applied settings, unchanged configuration and active
SOCKS endpoint before proceeding. The helper now has transaction-bound read-only
reconciliation and never retries a mutation blindly. New transactions also require
an atomic `verified` completion marker, written only after restart and health
checks; new sysctl values alone cannot falsely confirm a completed socket restart.

## Post-change verification

- Live Xray UDP sockets now report `rb1048576`; send capacity stays `tb212992`.
- Three independent repetitions through the existing Xray path had **zero new
  UDP InErrors/RcvbufErrors/SndbufErrors**. Socket drop counters were also zero
  at the inspected post-restart point.
- In the last two repetitions all six 8 MiB bulk transfers per repetition were
  complete and valid: Cloudflare HTTP 200 and Google HTTP 206 with exactly
  8,388,608 bytes. Google measured **161–271 Mbit/s**, Cloudflare **120–223 Mbit/s**.
  These are short server-egress samples, not Android or GoogleVideo bitrate.
- Some earlier Google download responses were HTTP 404. They were excluded from
  speed results, not interpreted as slow transfers or successes.
- Before the change, IPv4 server egress and short YouTube 204 requests worked;
  direct IPv6 probes failed. No IPv6 address or DNS record was changed here.
- Ten offline collector/repair-policy tests and 75 existing server tests passed.
  A final read-only repair preflight confirmed the persistent values and valid
  active configuration without another restart. The collector is bounded,
  defaults to read-only and never outputs raw profiles, keys or client records.

## Open Android gate

`adb devices -l` returned no device. No phone playback, Android system logcat,
same-session app diagnostic, CPU trace or actual GoogleVideo flow was available.
Do not mark the physical video-performance gate closed.

The signed panel routing policy is enabled, revision 7, profile `balanced`.
The current APK maps it to RU-direct routing. A Russian CDN IP could therefore
take a direct path; this remains a candidate pending the actual playback report.
The server sends YouTube through its existing WARP leastPing balancer. The pool's
shared identity and missing throughput-based scoring were inspected but not
changed without a causal comparison.

Ask the user to reconnect VPN and test the same video/quality. If the slowdown
persists, collect the in-app diagnostic without restarting the process and ADB
system evidence using `.agents/skills/test-zapret-android/SKILL.md` before changing
Android VPN/TUN/DNS implementation.

## Reusable tools and primary references

- `tools/check_youtube_vds.py`: bounded server-only measurements, optional
  `--proxy` uses only the verified existing loopback no-auth SOCKS endpoint.
- `tools/apply_youtube_udp_buffers.py`: read-only preflight by default; explicit
  `--apply`, private backup and guarded `--rollback` mode. Applying or rolling
  back restarts RosPanel and interrupts current VPN connections briefly.
- [Hysteria UDP-buffer ceilings](https://v2.hysteria.network/docs/advanced/Performance/).
- [Exact Xray 26.7.28 WireGuard bind](https://github.com/XTLS/Xray-core/blob/v26.7.28/proxy/wireguard/bind.go)
  and [system dialer](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/system_dialer.go).
- [Linux socket defaults](https://kernel.org/doc/html/v5.19/admin-guide/sysctl/net.html).
- [Cloudflare bounded speed-test API](https://github.com/cloudflare/speedtest).
- [Official Google platform-tools resource](https://developer.android.com/tools/releases/platform-tools).

The 16 MiB maxima follow the Hysteria guidance. The 1 MiB receive default is the
conservative measured repair for Xray's default UDP socket, not a claim that the
Hysteria documentation prescribes that default.
