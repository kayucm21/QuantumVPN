package com.quantumvpn.vpn

import com.quantumvpn.ui.ServerMode

/**
 * Prefer alternate protocol family on failover (Hysteria ↔ VLESS/Trojan/Reality).
 */
object ProtocolSwitchHint {
    fun family(type: String?): String {
        val t = type.orEmpty().lowercase()
        return when {
            t.contains("hysteria") || t == "tuic" || t == "shadowquic" -> "udp"
            t.contains("vless") || t.contains("trojan") || t.contains("vmess") ||
                t.contains("shadowsocks") -> "tls"
            else -> "other"
        }
    }

    /**
     * Rank candidates: prefer opposite protocol family from [failedType], then QoE.
     *
     * [mode] biases the score: Gaming weights latency heavily, Movie de-emphasizes
     * latency in favor of reliability/throughput, Standard is balanced.
     */
    fun preferAlternate(
        candidates: List<ServerFailover.Candidate>,
        typeByTag: Map<String, String>,
        failedType: String?,
        reliabilityByTag: Map<String, Int> = emptyMap(),
        mode: ServerMode = ServerMode.Standard,
    ): ServerFailover.Candidate? {
        if (candidates.isEmpty()) return null
        val failedFamily = family(failedType)
        return candidates.minByOrNull { c ->
            val type = typeByTag[c.outboundTag]
            val fam = family(type)
            val altBonus = if (failedFamily != "other" && fam != failedFamily && fam != "other") 0 else 80
            val health = ServerHealthScore.score(c.pingMillis)
            val reliability = reliabilityByTag[c.outboundTag] ?: 50
            val latencyWeight = when (mode) {
                ServerMode.Gaming -> 3
                ServerMode.Movie -> 0
                ServerMode.Standard -> 1
            }
            val reliabilityWeight = when (mode) {
                ServerMode.Gaming -> 1
                ServerMode.Movie -> 3
                ServerMode.Standard -> 1
            }
            altBonus + (200 - health - reliability) * 10 * reliabilityWeight +
                c.pingMillis * latencyWeight
        }
    }
}
