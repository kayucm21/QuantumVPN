package com.quantumvpn.ui

import org.junit.Assert.*
import org.junit.Test

class AuroraUiPolicyTest {
    @Test fun largeFontRespectsAndroidScale() {
        assertEquals(1.6f, auroraFontScale(1.6f, false), .001f)
        assertEquals(1.84f, auroraFontScale(1.6f, true), .001f)
    }
    @Test fun cameraPhotoIsBoundedBeforeDecode() {
        assertEquals(4, backgroundSampleSize(4080, 3072))
        assertEquals(1, backgroundSampleSize(720, 1280))
        assertTrue(Int.MAX_VALUE.toLong() / backgroundSampleSize(Int.MAX_VALUE, Int.MAX_VALUE) <= 1440)
    }
    @Test fun progressNeverInventsAnUnknownDownloadSize() {
        assertNull(startupDownloadProgress(12, -1))
        assertNull(startupDownloadProgress(12, 0))
        assertEquals(.5f, startupDownloadProgress(50, 100)!!, .001f)
        assertEquals(1f, startupDownloadProgress(Long.MAX_VALUE, 100)!!, .001f)
    }
    @Test fun pingDistinguishesWaitingFromUnreachable() {
        assertEquals("Проверка…", serverPingText(null, false))
        assertEquals("Нет ответа", serverPingText(null, true))
        assertEquals("52 мс", serverPingText(52, true))
    }
}
