package com.quantumvpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class UnderlyingServerPingTest {
    @Test fun parsesHostAndPort() {
        assertEquals("example.com" to 8443, UnderlyingServerPing.parseEndpoint("example.com:8443"))
    }

    @Test fun parsesBracketedIpv6() {
        assertEquals("2001:db8::1" to 443, UnderlyingServerPing.parseEndpoint("[2001:db8::1]:443"))
    }

    @Test fun defaultsMissingPort() {
        assertEquals("example.com" to 443, UnderlyingServerPing.parseEndpoint("example.com"))
        assertNull(UnderlyingServerPing.parseEndpoint(null))
    }
}
