package com.quantumvpn.hardening

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdBlockConnectPreflightTest {
    @Test
    fun `detects strict private dns modes`() {
        assertTrue(AdBlockConnectPreflight.isStrictPrivateDns("hostname"))
        assertTrue(AdBlockConnectPreflight.isStrictPrivateDns("provider_hostname"))
        assertFalse(AdBlockConnectPreflight.isStrictPrivateDns("opportunistic"))
        assertFalse(AdBlockConnectPreflight.isStrictPrivateDns("off"))
        assertFalse(AdBlockConnectPreflight.isStrictPrivateDns(null))
    }
}
