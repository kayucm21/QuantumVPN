package com.quantumvpn.routing

/**
 * Compiles a Happ routing profile into QuantumVPN managed route rules.
 *
 * Remote Happ geo `.dat` URLs are not downloaded (ADR: local packaged rule-sets only).
 * Common RU / private tags map onto built-in presets / `.srs`; plain domains/CIDRs become
 * inline managed rules; unknown `geosite:` / `geoip:` tags are skipped.
 */
object HappRoutingCompiler {
    private val PRIVATE_CIDRS = setOf(
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "255.255.255.255",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )

    private data class Bucket(
        val action: RoutingRuleAction,
        val domains: MutableList<String> = mutableListOf(),
        val cidrs: MutableList<String> = mutableListOf(),
        var russia: Boolean = false,
        var lan: Boolean = false,
    )

    fun applyToProfileJson(
        rawJson: String,
        catalog: HappRoutingCatalog,
        installed: InstalledRuleSets,
    ): String {
        if (!catalog.enabled || catalog.active == null) {
            return RoutingConfigEditor.apply(
                rawJson,
                RoutingPreset.AllThroughVpn,
                emptyList(),
                installed,
            ).json
        }
        val profile = catalog.active!!
        val direct = Bucket(RoutingRuleAction.Direct)
        val proxy = Bucket(RoutingRuleAction.Proxy)
        val block = Bucket(RoutingRuleAction.Block)
        absorbSites(profile.directSites, direct)
        absorbIps(profile.directIp, direct)
        absorbSites(profile.proxySites, proxy)
        absorbIps(profile.proxyIp, proxy)
        absorbSites(profile.blockSites, block)
        absorbIps(profile.blockIp, block)

        val manual = buildList {
            fun flush(bucket: Bucket) {
                if (bucket.domains.isNotEmpty()) {
                    add(
                        ManagedRoutingRule(
                            matchType = RoutingMatchType.DomainSuffix,
                            values = bucket.domains.distinct(),
                            action = bucket.action,
                        ),
                    )
                }
                if (bucket.cidrs.isNotEmpty()) {
                    add(
                        ManagedRoutingRule(
                            matchType = RoutingMatchType.IpCidr,
                            values = bucket.cidrs.distinct(),
                            action = bucket.action,
                        ),
                    )
                }
            }
            flush(block)
            flush(proxy)
            flush(direct)
        }

        val preset = when {
            direct.russia && profile.globalProxy && !proxy.russia -> RoutingPreset.RussiaDirect
            proxy.russia && !profile.globalProxy && !direct.russia -> RoutingPreset.RussiaVpn
            (direct.lan || proxy.lan || block.lan) &&
                profile.globalProxy &&
                !direct.russia &&
                !proxy.russia &&
                manual.isEmpty() -> RoutingPreset.BypassLan
            manual.isEmpty() && profile.globalProxy && !direct.russia && !proxy.russia ->
                RoutingPreset.AllThroughVpn
            manual.isEmpty() && !profile.globalProxy && !proxy.russia ->
                RoutingPreset.OnlySelectedSites
            // Happ rules + RU tags: keep RU via RussiaDirect/Vpn when possible, else Custom.
            direct.russia && profile.globalProxy -> RoutingPreset.RussiaDirect
            proxy.russia && !profile.globalProxy -> RoutingPreset.RussiaVpn
            !profile.globalProxy -> RoutingPreset.OnlySelectedSites
            else -> RoutingPreset.Custom
        }

        return RoutingConfigEditor.apply(rawJson, preset, manual, installed).json
    }

    private fun absorbSites(values: List<String>, bucket: Bucket) {
        for (raw in values) {
            val value = raw.trim()
            when {
                value.isEmpty() -> Unit
                isRuSite(value) -> bucket.russia = true
                isPrivateSite(value) -> bucket.lan = true
                value.startsWith("geosite:", ignoreCase = true) -> Unit
                else -> bucket.domains += value
                    .removePrefix("domain:")
                    .removePrefix("full:")
                    .removePrefix("*.")
            }
        }
    }

    private fun absorbIps(values: List<String>, bucket: Bucket) {
        for (raw in values) {
            val value = raw.trim()
            when {
                value.isEmpty() -> Unit
                isRuIp(value) -> bucket.russia = true
                isPrivateIp(value) -> bucket.lan = true
                value.startsWith("geoip:", ignoreCase = true) -> Unit
                else -> bucket.cidrs += value
            }
        }
    }

    private fun isRuSite(value: String): Boolean {
        val v = value.lowercase()
        return v == "geosite:category-ru" ||
            v == "geosite:geolocation-ru" ||
            v == "geosite:ru" ||
            v.endsWith(":category-ru") ||
            v.endsWith(":geolocation-ru")
    }

    private fun isRuIp(value: String): Boolean {
        val v = value.lowercase()
        return v == "geoip:ru" || (v.startsWith("geoip:") && v.endsWith(":ru"))
    }

    private fun isPrivateSite(value: String): Boolean {
        val v = value.lowercase()
        return v == "geosite:private" || v == "geosite:private-domain"
    }

    private fun isPrivateIp(value: String): Boolean {
        val v = value.lowercase()
        return v == "geoip:private" || value in PRIVATE_CIDRS
    }
}
