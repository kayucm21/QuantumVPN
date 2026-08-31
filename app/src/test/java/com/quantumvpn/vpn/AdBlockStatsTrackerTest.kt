package com.quantumvpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

class AdBlockStatsTrackerTest {
    @Test
    fun `tracks rolling per-minute hits`() {
        val tracker = AdBlockStatsTracker(windowMillis = 60_000L)
        val now = 1_000_000L
        tracker.recordHit(now)
        tracker.recordHit(now + 1_000L)
        assertEquals(2, tracker.perMinute(now + 2_000L))
        assertEquals(2L, tracker.total())
        assertEquals(0, tracker.perMinute(now + 61_000L))
        assertEquals(2L, tracker.total())
    }
}
