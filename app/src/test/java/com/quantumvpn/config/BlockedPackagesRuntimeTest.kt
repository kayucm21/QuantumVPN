package com.quantumvpn.config

import com.quantumvpn.config.JsonConfig
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BlockedPackagesRuntimeTest {
    @Test
    fun `block mode injects reject rules for selected packages`() {
        val raw = """
            {
              "dns":{"servers":[{"type":"local","tag":"local-dns"}],"final":"local-dns"},
              "inbounds":[{"type":"tun","tag":"tun-in","auto_route":true,
                "address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],
                "route_address":["0.0.0.0/0","::/0"]}],
              "outbounds":[{"type":"direct","tag":"direct"}],
              "route":{"auto_detect_interface":true,"final":"direct"}
            }
        """.trimIndent()
        val result = RuntimeConfigBuilder.build(
            raw,
            options = RuntimeConfigOptions(
                dnsMode = DnsMode.FromJson,
                blockedPackageNames = listOf("com.example.blocked"),
            ),
        ) as RuntimeConfigResult.Ready
        val root = JsonConfig.parse(result.json) as kotlinx.serialization.json.JsonObject
        val rules = ((root["route"] as kotlinx.serialization.json.JsonObject)["rules"] as JsonArray)
        val first = rules.first() as kotlinx.serialization.json.JsonObject
        assertEquals("reject", first.string("action"))
        assertTrue(first["package_name"].toString().contains("com.example.blocked"))
    }
}

private fun kotlinx.serialization.json.JsonObject.string(key: String): String? =
    (this[key] as? JsonPrimitive)?.content
