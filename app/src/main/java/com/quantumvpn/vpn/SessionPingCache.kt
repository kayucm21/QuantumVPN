package com.quantumvpn.vpn

/**
 * In-memory ping cache for the current app process / VPN session.
 * Cleared when VPN stops or profile changes.
 */
object SessionPingCache {
    @Volatile
    private var profileId: String? = null
    private val lock = Any()
    private val values = linkedMapOf<String, Int?>()

    fun bind(profileId: String) {
        synchronized(lock) {
            if (this.profileId != profileId) {
                this.profileId = profileId
                values.clear()
            }
        }
    }

    fun putAll(profileId: String, pings: Map<String, Int?>) {
        synchronized(lock) {
            bind(profileId)
            values.putAll(pings)
            while (values.size > MAX) {
                values.remove(values.keys.first())
            }
        }
    }

    fun get(outboundTag: String): Int? = synchronized(lock) { values[outboundTag] }

    fun snapshot(): Map<String, Int?> = synchronized(lock) { values.toMap() }

    fun clear() {
        synchronized(lock) {
            profileId = null
            values.clear()
        }
    }

    private const val MAX = 256
}
