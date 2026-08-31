package com.quantumvpn.profiles

/** Removes duplicate managed servers by stable identity (protocol+host+port+transport). */
object ServerDeduper {
    fun dedupe(servers: List<ManagedServer>): List<ManagedServer> {
        if (servers.size <= 1) return servers
        val seen = LinkedHashSet<String>()
        return servers.filter { server ->
            val key = server.identityKey.ifBlank { server.displayName }
            seen.add(key)
        }
    }
}
