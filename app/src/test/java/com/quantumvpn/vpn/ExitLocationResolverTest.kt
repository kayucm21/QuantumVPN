package com.quantumvpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ExitLocationResolverTest {
    @Test
    fun `guesses sweden from english server label`() {
        val location = ExitLocationResolver.fromServerLabel("Sweden-01 Premium")
        assertNotNull(location)
        assertEquals("SE", location!!.countryCode)
        assertEquals("🇸🇪", location.flagEmoji)
        assertTrue(location.displayLabel.contains("Швеция"))
    }

    @Test
    fun `reads flag emoji from server label`() {
        val location = ExitLocationResolver.fromServerLabel("🇩🇪 Frankfurt-1")
        assertNotNull(location)
        assertEquals("DE", location!!.countryCode)
        assertEquals("🇩🇪", location.flagEmoji)
        assertTrue(location.countryName.contains("Frankfurt"))
    }

    @Test
    fun `geo country code becomes flag`() {
        val location = ExitLocationResolver.fromGeo("Sweden", "se")
        assertEquals("Sweden", location!!.countryName)
        assertEquals("SE", location.countryCode)
        assertEquals("🇸🇪", location.flagEmoji)
    }

    @Test
    fun `blank label returns null`() {
        assertNull(ExitLocationResolver.fromServerLabel("   "))
    }
}
