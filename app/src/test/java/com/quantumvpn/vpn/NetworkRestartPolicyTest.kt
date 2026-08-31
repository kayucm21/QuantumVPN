package com.quantumvpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

class NetworkRestartPolicyTest {
    @Test
    fun `transient change that returns to session baseline cancels restart`() {
        val baseline = "wifi-a"

        assertEquals(
            NetworkRestartDecision.DebounceRestart,
            NetworkRestartPolicy.decide(baseline, "no-network"),
        )
        assertEquals(
            NetworkRestartDecision.KeepSession,
            NetworkRestartPolicy.decide(baseline, baseline),
        )
    }

    @Test
    fun `stable different network still requests controlled restart`() {
        assertEquals(
            NetworkRestartDecision.DebounceRestart,
            NetworkRestartPolicy.decide("wifi-a", "mobile-b"),
        )
    }
}
