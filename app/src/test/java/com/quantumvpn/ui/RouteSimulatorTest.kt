package com.quantumvpn.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class RouteSimulatorTest {
    @Test
    fun russiaDirectRoutesRuDirect() {
        val result = RouteSimulator.simulate("mail.ru", "Россия напрямую", null)
        assertEquals("Напрямую", result.action)
    }

    @Test
    fun allThroughVpn() {
        val result = RouteSimulator.simulate("example.com", "Всё через VPN", null)
        assertEquals("Через VPN", result.action)
    }

    @Test
    fun blankDomain() {
        val result = RouteSimulator.simulate("  ", null, null)
        assertEquals("—", result.action)
    }
}
