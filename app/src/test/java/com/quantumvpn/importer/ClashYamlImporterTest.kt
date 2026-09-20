package com.quantumvpn.importer

import com.quantumvpn.config.JsonConfig
import com.quantumvpn.profiles.ProfileSource
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ClashYamlImporterTest {
    @Test
    fun `parses clash shadowsocks proxy`() {
        val yaml = """
            proxies:
              - name: Test SS
                type: ss
                server: example.com
                port: 8388
                cipher: aes-256-gcm
                password: secret
        """.trimIndent()
        val servers = ClashYamlImporter.parse(yaml)
        assertEquals(1, servers.size)
        assertEquals("shadowsocks", servers.single().outbound.string("type"))
        assertEquals("example.com", servers.single().outbound.string("server"))
    }

    @Test
    fun `full import via ImportParser`() {
        val result = ImportParser.parse(
            """
            proxies:
              - name: HY1
                type: hysteria
                server: hy.example
                port: 443
                auth_str: pass
                sni: hy.example
            """.trimIndent(),
            ProfileSource.File,
            "clash-import",
        ).candidate as ImportCandidate.Managed
        assertEquals(1, result.servers.size)
        assertEquals("hysteria", result.servers.single().outbound.string("type"))
    }
}

class HysteriaV1ImportTest {
    @Test
    fun `parses hysteria share link`() {
        val server = ShareLinkParser.parse(
            "hysteria://testpass@127.0.0.1:8443/?peer=sni.test&insecure=1&upmbps=50&downmbps=100",
        )
        assertEquals("hysteria", server.outbound.string("type"))
        assertEquals("testpass", server.outbound.string("auth_str"))
        assertEquals(50, (server.outbound["up_mbps"] as JsonPrimitive).content.toInt())
    }
}

private fun JsonObject.string(key: String): String? =
    (this[key] as? JsonPrimitive)?.content
