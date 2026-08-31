package com.quantumvpn.diagnostics

import com.quantumvpn.ui.UiSettings
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.VpnSessionStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityScoreCalculatorTest {
    @Test
    fun connectedWithHardeningScoresHigh() {
        val score = SecurityScoreCalculator.compute(
            vpnState = VpnConnectionState.Connected(
                profileId = "p",
                profileName = "t",
                connectedAtEpochMillis = 1L,
            ),
            settings = UiSettings(
                blockNonVpnTraffic = true,
                appLockEnabled = true,
                dnsOverride = com.quantumvpn.config.DnsOverride(enabled = true),
            ),
            stats = VpnSessionStats(externalIp = "1.2.3.4"),
        )
        assertTrue(score.score >= 80)
        assertTrue(score.grade == "A" || score.grade == "B")
    }

    @Test
    fun stoppedSuggestsConnect() {
        val score = SecurityScoreCalculator.compute(
            vpnState = VpnConnectionState.Stopped,
            settings = UiSettings(),
            stats = VpnSessionStats(),
        )
        assertTrue(score.tips.any { it.contains("VPN", ignoreCase = true) })
        assertTrue(score.score < 80)
    }
}
