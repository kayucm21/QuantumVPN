package com.quantumvpn.diagnostics

import com.quantumvpn.ui.UiSettings
import com.quantumvpn.vpn.VpnConnectionState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityChecklistTest {
    @Test
    fun summaryCountsOkItems() {
        val items = SecurityChecklist.items(
            vpnState = VpnConnectionState.Stopped,
            settings = UiSettings(blockNonVpnTraffic = true, appLockEnabled = true),
        )
        assertEquals(7, items.size)
        assertTrue(items.any { it.title.contains("Kill") && it.ok })
        assertFalse(items.first { it.title.contains("VPN") }.ok)
        assertTrue(SecurityChecklist.summary(items).contains("/7"))
    }
}
