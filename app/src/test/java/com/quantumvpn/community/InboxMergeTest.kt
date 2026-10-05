package com.quantumvpn.community

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InboxMergeTest {
    private fun entry(key: String, time: Long, read: Boolean = false) = InboxEntry(key, "release", "Заголовок", "Текст", time, read = read)

    @Test fun stableIdentityDeduplicatesRefreshAndKeepsReadState() {
        val merged = InboxMerge.merge(listOf(entry("a", 1, true)), listOf(entry("a", 2), entry("b", 3)))
        assertEquals(listOf("b", "a"), merged.map { it.key })
        assertTrue(merged.last().read)
        assertFalse(merged.first().read)
    }

    @Test fun cacheIsBoundedAndNewestEventsSurvive() {
        val merged = InboxMerge.merge(emptyList(), (0..500).map { entry("$it", it.toLong()) })
        assertEquals(InboxMerge.MAX_ENTRIES, merged.size)
        assertEquals("500", merged.first().key)
    }

    @Test fun handoffIsDistinctFromInstalledAppLaunch() {
        assertEquals("install_handoff", DeliveryMilestone.InstallHandoff.wireValue)
        assertEquals("app_started", DeliveryMilestone.AppStarted.wireValue)
    }
}
