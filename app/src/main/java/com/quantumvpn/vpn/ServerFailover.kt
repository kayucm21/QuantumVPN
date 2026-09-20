package com.quantumvpn.vpn

import com.quantumvpn.ui.ServerMode

/** Pick next-best outbound for auto-failover and «Лучший сервер» (ping + QoE score). */
object ServerFailover {
    data class Candidate(val groupTag: String, val outboundTag: String, val pingMillis: Int)

    fun nextBest(
        groups: List<RuntimeSelectorGroup>,
        pingByTag: Map<String, Int?>,
        excludeTag: String? = null,
        excludeTags: Set<String> = emptySet(),
        maxPingMillis: Int = 2_000,
        /** Optional reliability 0..100 — higher is better. */
        reliabilityByTag: Map<String, Int> = emptyMap(),
        mode: ServerMode = ServerMode.Standard,
    ): Candidate? {
        val primary = groups.forServerUi().primaryGroup() ?: return null
        val blocked = excludeTags + setOfNotNull(excludeTag)
        return primary.items
            .asSequence()
            .filter { it.tag !in blocked }
            .mapNotNull { item ->
                val ping = pingByTag[item.tag] ?: item.pingMillis ?: return@mapNotNull null
                if (ping < 0 || ping > maxPingMillis) return@mapNotNull null
                Candidate(primary.tag, item.tag, ping)
            }
            .toList()
            .let { list ->
                ProtocolSwitchHint.preferAlternate(
                    candidates = list,
                    typeByTag = primary.items.associate { it.tag to it.type },
                    failedType = null,
                    reliabilityByTag = reliabilityByTag,
                    mode = mode,
                ) ?: list.minByOrNull { candidate ->
                    val health = ServerHealthScore.score(candidate.pingMillis)
                    val reliability = reliabilityByTag[candidate.outboundTag] ?: 50
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
                    (200 - health - reliability) * 10 * reliabilityWeight +
                        candidate.pingMillis * latencyWeight
                }
            }
    }

    fun candidates(
        groups: List<RuntimeSelectorGroup>,
        pingByTag: Map<String, Int?>,
        excludeTag: String? = null,
        excludeTags: Set<String> = emptySet(),
        maxPingMillis: Int = 2_000,
    ): List<Candidate> {
        val primary = groups.forServerUi().primaryGroup() ?: return emptyList()
        val blocked = excludeTags + setOfNotNull(excludeTag)
        return primary.items
            .asSequence()
            .filter { it.tag !in blocked }
            .mapNotNull { item ->
                val ping = pingByTag[item.tag] ?: item.pingMillis ?: return@mapNotNull null
                if (ping < 0 || ping > maxPingMillis) return@mapNotNull null
                Candidate(primary.tag, item.tag, ping)
            }
            .toList()
    }

    /** Absolute best in primary group including current selection. */
    fun bestOverall(
        groups: List<RuntimeSelectorGroup>,
        pingByTag: Map<String, Int?>,
        maxPingMillis: Int = 2_000,
        reliabilityByTag: Map<String, Int> = emptyMap(),
        mode: ServerMode = ServerMode.Standard,
    ): Candidate? = nextBest(
        groups = groups,
        pingByTag = pingByTag,
        excludeTag = null,
        excludeTags = emptySet(),
        maxPingMillis = maxPingMillis,
        reliabilityByTag = reliabilityByTag,
        mode = mode,
    )
}
