package com.quantumvpn.routing

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import kotlin.io.path.createTempDirectory
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RuleSetAssetInstallerTest {
    @Test
    fun `installs verifies repairs and cleans interrupted temporary files`() {
        val root = createTempDirectory("rulesets-").toFile()
        try {
            val domain = byteArrayOf(1, 2, 3)
            val ip = byteArrayOf(4, 5, 6, 7)
            val source = assets(domain, ip)
            val installer = RuleSetAssetInstaller(root) { name ->
                ByteArrayInputStream(requireNotNull(source[name]))
            }
            root.resolve("orphan.tmp").writeText("partial")

            val installed = kotlinx.coroutines.runBlocking { installer.ensureInstalled() }
            assertArrayEquals(domain, root.resolve("zapret-ru-domains.srs").readBytes())
            assertFalse(root.resolve("orphan.tmp").exists())

            root.resolve("zapret-ru-ip.srs").writeText("corrupt")
            kotlinx.coroutines.runBlocking { installer.ensureInstalled() }
            assertArrayEquals(ip, root.resolve("zapret-ru-ip.srs").readBytes())
            assertTrue(installed.requirePath("zapret-ru-ip").endsWith("zapret-ru-ip.srs"))
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun `rejects corrupt bundled asset before publishing manifest`() {
        val root = createTempDirectory("rulesets-bad-").toFile()
        try {
            val source = assets(byteArrayOf(1), byteArrayOf(2)).toMutableMap()
            source["zapret-ru-domains.srs"] = byteArrayOf(9)
            val failure = runCatching {
                kotlinx.coroutines.runBlocking {
                    RuleSetAssetInstaller(root) { ByteArrayInputStream(requireNotNull(source[it])) }
                        .ensureInstalled()
                }
            }
            assertTrue(failure.isFailure)
            assertFalse(root.resolve("manifest.json").exists())
        } finally {
            root.deleteRecursively()
        }
    }

    private fun assets(domain: ByteArray, ip: ByteArray): Map<String, ByteArray> = mapOf(
        "manifest.json" to """
            {
              "version":1,
              "sets":[
                {"tag":"zapret-ru-domains","file":"zapret-ru-domains.srs","sha256":"${sha(domain)}"},
                {"tag":"zapret-ru-ip","file":"zapret-ru-ip.srs","sha256":"${sha(ip)}"}
              ]
            }
        """.trimIndent().toByteArray(),
        "zapret-ru-domains.srs" to domain,
        "zapret-ru-ip.srs" to ip,
    )

    private fun sha(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }
}
