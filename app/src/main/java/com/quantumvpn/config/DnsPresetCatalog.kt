package com.quantumvpn.config

/**
 * Built-in DNS override presets for Settings / Home chips.
 */
data class DnsPreset(
    val title: String,
    val hostname: String,
    val ipv4: String,
)

object DnsPresetCatalog {
    val presets: List<DnsPreset> = listOf(
        DnsPreset("Cloudflare", "one.one.one.one", "1.1.1.1"),
        DnsPreset("Google", "dns.google", "8.8.8.8"),
        DnsPreset("Quad9", "dns.quad9.net", "9.9.9.9"),
        DnsPreset("AdGuard", "dns.adguard.com", "94.140.14.14"),
        DnsPreset("Mullvad", "dns.mullvad.net", "194.242.2.2"),
        DnsPreset("OpenDNS", "dns.opendns.com", "208.67.222.222"),
    )
}
