package com.quantumvpn.vpn

/** Rolling ad/tracker block counter for the active VPN session. */
internal class AdBlockStatsTracker(
    private val windowMillis: Long = 60_000L,
) {
    private val recentHits = ArrayDeque<Long>()
    private var sessionTotal: Long = 0L

    @Synchronized
    fun recordHit(now: Long = System.currentTimeMillis()) {
        trim(now)
        recentHits.addLast(now)
        sessionTotal++
    }

    @Synchronized
    fun perMinute(now: Long = System.currentTimeMillis()): Int {
        trim(now)
        return recentHits.size
    }

    @Synchronized
    fun total(): Long = sessionTotal

    @Synchronized
    fun reset() {
        recentHits.clear()
        sessionTotal = 0L
    }

    private fun trim(now: Long) {
        while (recentHits.isNotEmpty() && now - recentHits.first() > windowMillis) {
            recentHits.removeFirst()
        }
    }
}
