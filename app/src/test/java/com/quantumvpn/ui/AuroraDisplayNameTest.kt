package com.quantumvpn.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AuroraDisplayNameTest {
    @Test fun trimsAndCollapsesSpacesWithoutChangingUnicode() {
        assertEquals("Алексей Иванов", normalizeAuroraDisplayName("  Алексей   Иванов  "))
        assertEquals("СеверныйЛис", normalizeAuroraDisplayName("СеверныйЛис"))
    }
    @Test fun rejectsEmptyOversizedAndControlNames() {
        listOf("", "  ", "A", "!@", "x".repeat(25), "Иван\nПетр", "Иван\u202e").forEach {
            assertNull(it, normalizeAuroraDisplayName(it))
        }
    }
}
