package com.quantumvpn.vpn

import org.junit.Assert.assertTrue
import org.junit.Test

class ServerHealthScoreTest {
    @Test
    fun `combined score rewards stable low latency server`() {
        val stable = ServerHealthScore.combined(pingMillis = 42, reliabilityScore = 95)
        val flaky = ServerHealthScore.combined(pingMillis = 42, reliabilityScore = 20)
        val slow = ServerHealthScore.combined(pingMillis = 380, reliabilityScore = 95)

        assertTrue(stable > flaky)
        assertTrue(stable > slow)
    }
}
