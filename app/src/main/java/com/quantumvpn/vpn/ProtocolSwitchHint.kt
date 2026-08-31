package com.quantumvpn.vpn

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
     */
    fun preferAlternate(
        candidates: List<ServerFailover.Candidate>,
        typeByTag: Map<String, String>,
        failedType: String?,
        reliabilityByTag: Map<String, Int> = emptyMap(),
    ): ServerFailover.Candidate? {
        if (candidates.isEmpty()) return null
        val failedFamily = family(failedType)
        return candidates.minByOrNull { c ->
            val type = typeByTag[c.outboundTag]
            val fam = family(type)
            val altBonus = if (failedFamily != "other" && fam != failedFamily && fam != "other") 0 else 80
            val health = ServerHealthScore.score(c.pingMillis)
            val reliability = reliabilityByTag[c.outboundTag] ?: 50
            altBonus + (200 - health - reliability) * 10 + c.pingMillis
        }
    }
}
