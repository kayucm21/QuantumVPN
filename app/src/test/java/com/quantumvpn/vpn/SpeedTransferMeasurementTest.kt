package com.quantumvpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

class SpeedTransferMeasurementTest {
    @Test
    fun `fast body transfer retains submillisecond precision`() {
        // A 64 KiB body transferred in 0.5 ms is 1048.576 Mbps. Rounding the
        // duration up to one millisecond previously halved this result.
        assertEquals(1_048_576L, SpeedTransferMeasurement(65_536L, 500_000L).kbps)
    }

    @Test
    fun `rate uses decimal bits per second and handles bounded slow samples`() {
        assertEquals(32_000L, SpeedTransferMeasurement(32_000_000L, 8_000_000_000L).kbps)
        assertEquals(8_000L, SpeedTransferMeasurement(1_000_000L, 1_000_000_000L).kbps)
    }

    @Test
    fun `empty and invalid samples cannot become a successful speed`() {
        assertEquals(0L, SpeedTransferMeasurement(0L, 1_000_000L).kbps)
        assertEquals(0L, SpeedTransferMeasurement(1_000_000L, 0L).kbps)
        assertEquals(0L, SpeedTransferMeasurement(1_000_000L, -1L).kbps)
    }
}
