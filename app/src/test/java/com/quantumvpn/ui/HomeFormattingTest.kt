package com.quantumvpn.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class HomeFormattingTest {
    @Test
    fun bytesStayCompact() {
        assertEquals("0 B", formatBytes(0))
        assertEquals("1.0 KB", formatBytes(1_024))
        assertEquals("1.5 MB", formatBytes(1_572_864))
    }

    @Test
    fun pingShowsMillisOrDash() {
        assertEquals("—", formatPing(null))
        assertEquals("999 ms", formatPing(999))
        assertEquals("1000 ms", formatPing(1_000))
    }
}
