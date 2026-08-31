package com.quantumvpn.networkbootstrap

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BootstrapFailureTest {
    @Test
    fun `dns response codes map to stable support codes`() {
        assertNull(DnsResponseClassifier.classify(rcode = 0, answerCount = 1))
        assertEquals(
            BootstrapFailureCode.DnsEmptyAnswer,
            DnsResponseClassifier.classify(rcode = 0, answerCount = 0),
        )
        assertEquals(
            BootstrapFailureCode.DnsNameNotFound,
            DnsResponseClassifier.classify(rcode = 3, answerCount = 0),
        )
        assertEquals(
            BootstrapFailureCode.DnsRefused,
            DnsResponseClassifier.classify(rcode = 5, answerCount = 0),
        )
        assertEquals(
            BootstrapFailureCode.DnsResponse,
            DnsResponseClassifier.classify(rcode = 2, answerCount = 0),
        )
    }

    @Test
    fun `published support codes are unique`() {
        val codes = BootstrapFailureCode.entries.map(BootstrapFailureCode::value)
        assertEquals(codes.size, codes.distinct().size)
        assertTrue(codes.all { it.matches(Regex("(?:NET|DNS)-\\d{3}")) })
    }

    @Test
    fun `network transition retries once and then becomes explicit failure`() {
        assertEquals(
            NetworkTransitionDecision.Accept,
            NetworkTransitionPolicy.decide(
                startedKey = "100:wlan0:false:8.8.8.8",
                currentKey = "100:wlan0:false:8.8.8.8",
                attempt = 0,
                maxNetworkChanges = 1,
            ),
        )
        assertEquals(
            NetworkTransitionDecision.Retry,
            NetworkTransitionPolicy.decide(
                startedKey = "100:wlan0:false:8.8.8.8",
                currentKey = "100:wlan0:true:8.8.8.8",
                attempt = 0,
                maxNetworkChanges = 1,
            ),
        )
        assertEquals(
            NetworkTransitionDecision.Fail,
            NetworkTransitionPolicy.decide(
                startedKey = "100:wlan0:true:8.8.8.8",
                currentKey = "100:wlan0:true:1.1.1.1",
                attempt = 1,
                maxNetworkChanges = 1,
            ),
        )
    }
}
