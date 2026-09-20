package com.quantumvpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class GameCatalogTest {
    private val androidPackage = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")

    private fun app(packageName: String) = InstalledApp(
        packageName = packageName,
        label = packageName,
        system = false,
        enabled = true,
        suggestion = null,
    )

    @Test
    fun `all catalog packages look like android packages`() {
        assertTrue(GameCatalog.allPackages.isNotEmpty())
        GameCatalog.allPackages.forEach { pkg ->
            assertTrue("bad package: $pkg", androidPackage.matches(pkg))
        }
    }

    @Test
    fun `detectInstalled finds installed games only`() {
        val detected = GameCatalog.detectInstalled(
            listOf(app("com.tencent.ig"), app("com.example.other")),
        )

        assertEquals(1, detected.size)
        assertEquals("pubg-mobile", detected[0].first.id)
        assertEquals(setOf("com.tencent.ig"), detected[0].second)
    }

    @Test
    fun `detectInstalled is empty without games`() {
        assertTrue(GameCatalog.detectInstalled(listOf(app("com.example.other"))).isEmpty())
    }
}
