package com.quantumvpn.vpn

import org.junit.Assert.assertTrue
import org.junit.Test

class AppScopePresetsTest {
    @Test
    fun streamingFindsYoutubeWhenInstalled() {
        val installed = listOf(
            InstalledApp("com.google.android.youtube", "YouTube", false, true, "YouTube"),
            InstalledApp("com.example.other", "Other", false, true, null),
        )
        val packages = AppScopePresets.packagesFor(AppScopePreset.Streaming, installed)
        assertTrue(packages.contains("com.google.android.youtube"))
        assertTrue("com.example.other" !in packages)
    }
}
