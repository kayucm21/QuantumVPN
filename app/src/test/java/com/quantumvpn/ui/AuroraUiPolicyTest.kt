package com.quantumvpn.ui

import org.junit.Assert.*
import org.junit.Test

class AuroraUiPolicyTest {
    @Test fun quantum2CaptionReplacesOnlyTheLegacyDefault() {
        assertEquals("Больше свободы. Ближе к людям.", quantum2Tagline("HORIZON GLASS · 2026"))
        assertEquals("Больше свободы. Ближе к людям.", quantum2Tagline(""))
        assertEquals("Мой подзаголовок", quantum2Tagline("Мой подзаголовок"))
    }
    @Test fun largeFontRespectsAndroidScale() {
        assertEquals(1.6f, auroraFontScale(1.6f, false), .001f)
        assertEquals(1.84f, auroraFontScale(1.6f, true), .001f)
    }
    @Test fun visualRefreshDoesNotShrinkUserTextBelowNormalSize() {
        assertEquals(1f, auroraFontScale(.85f, false), .001f)
        assertEquals(1.15f, auroraFontScale(.85f, true), .001f)
        assertEquals(2f, auroraFontScale(2f, false), .001f)
    }
    @Test fun cameraPhotoIsBoundedBeforeDecode() {
        assertEquals(4, backgroundSampleSize(4080, 3072))
        assertEquals(1, backgroundSampleSize(720, 1280))
        assertTrue(Int.MAX_VALUE.toLong() / backgroundSampleSize(Int.MAX_VALUE, Int.MAX_VALUE) <= 1440)
    }
    @Test fun backgroundDecodeBoundsCoverPortraitLandscapeAndLimitBoundary() {
        assertEquals(1, backgroundSampleSize(1440, 1440))
        assertEquals(2, backgroundSampleSize(1441, 1000))
        assertEquals(4, backgroundSampleSize(3072, 4080))
        assertEquals(1, backgroundSampleSize(0, 0))
    }
    @Test fun progressNeverInventsAnUnknownDownloadSize() {
        assertNull(startupDownloadProgress(12, -1))
        assertNull(startupDownloadProgress(12, 0))
        assertEquals(.5f, startupDownloadProgress(50, 100)!!, .001f)
        assertEquals(1f, startupDownloadProgress(Long.MAX_VALUE, 100)!!, .001f)
    }
    @Test fun downloadProgressIsMeasuredAndClampedAtBothBounds() {
        assertEquals(0f, startupDownloadProgress(-20, 100)!!, .001f)
        assertEquals(0f, startupDownloadProgress(0, 100)!!, .001f)
        assertEquals(.5f, startupDownloadProgress(Long.MAX_VALUE / 2, Long.MAX_VALUE)!!, .001f)
        assertNull(startupDownloadProgress(Long.MAX_VALUE, Long.MIN_VALUE))
    }
    @Test fun pingDistinguishesWaitingFromUnreachable() {
        assertEquals("Проверка…", serverPingText(null, false))
        assertEquals("Нет ответа", serverPingText(null, true))
        assertEquals("52 мс", serverPingText(52, true))
    }
    @Test fun invalidPingNeverLooksLikeAWorkingZeroLatencyServer() {
        assertEquals("Проверка…", serverPingText(0, false))
        assertEquals("Нет ответа", serverPingText(0, true))
        assertEquals("Проверка…", serverPingText(-1, false))
        assertEquals("Нет ответа", serverPingText(-1, true))
        assertEquals("700 мс", serverPingText(700, true))
    }
}
