package com.quantumvpn.updates

import org.junit.Assert.assertEquals
import org.junit.Test

class SimpleFtpClientPasvTest {
    @Test
    fun `rewrites private PASV host to control host`() {
        val client = SimpleFtpClient(
            host = "185.117.119.3",
            username = "u",
            password = "p",
        )
        assertEquals("185.117.119.3", client.rewritePasvHost("127.0.0.1", "185.117.119.3"))
        assertEquals("185.117.119.3", client.rewritePasvHost("10.0.0.5", "185.117.119.3"))
        assertEquals("185.117.119.3", client.rewritePasvHost("192.168.1.2", "185.117.119.3"))
        assertEquals("1.2.3.4", client.rewritePasvHost("1.2.3.4", "185.117.119.3"))
    }
}
