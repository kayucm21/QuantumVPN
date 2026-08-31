package com.quantumvpn.hardening

import com.quantumvpn.config.JsonConfig
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnRuntimeHardeningTest {
    @Test
    fun `default protection removes network control surfaces without mutating source`() {
        val source = root(
            experimental = """
                "experimental":{
                  "clash_api":{"external_controller":"127.0.0.1:9090","secret":"pw","mode":"rule"},
                  "v2ray_api":{"listen":"127.0.0.1:8080"},
                  "cache_file":{"enabled":true}
                }
            """.trimIndent(),
        )

        val result = VpnRuntimeHardening.apply(source, VpnHidingOptions())
            as RuntimeHardeningResult.Ready
        val experimental = result.root["experimental"] as JsonObject
        val clash = experimental["clash_api"] as JsonObject
        val tun = (result.root["inbounds"] as JsonArray).single() as JsonObject

        assertFalse("external_controller" in clash)
        assertFalse("secret" in clash)
        assertEquals("rule", (clash["mode"] as JsonPrimitive).content)
        assertFalse("v2ray_api" in experimental)
        assertTrue("cache_file" in experimental)
        assertEquals("1500", (tun["mtu"] as JsonPrimitive).content)
        assertTrue("source object must remain untouched", "v2ray_api" in source.toString())
    }

    @Test
    fun `strict protection blocks every non tun inbound`() {
        val source = JsonConfig.parse(
            """
                {"inbounds":[
                  {"type":"tun","address":["172.19.0.1/30","fd00::1/126"],"auto_route":true},
                  {"type":"mixed","listen":"127.0.0.1","listen_port":1080}
                ]}
            """.trimIndent(),
        ) as JsonObject

        val result = VpnRuntimeHardening.apply(source, VpnHidingOptions())

        assertTrue(result is RuntimeHardeningResult.Blocked)
        assertTrue((result as RuntimeHardeningResult.Blocked).message.contains("mixed"))
    }

    @Test
    fun `disabled localhost protection preserves advanced raw endpoints`() {
        val source = root(
            experimental = """
                "experimental":{"clash_api":{"external_controller":"127.0.0.1:9090"}}
            """.trimIndent(),
            extraInbound = ",{\"type\":\"socks\",\"listen\":\"127.0.0.1\",\"listen_port\":1080}",
        )

        val result = VpnRuntimeHardening.apply(
            source,
            VpnHidingOptions(blockLocalEndpoints = false),
        ) as RuntimeHardeningResult.Ready

        assertTrue("external_controller" in result.root.toString())
        assertEquals(2, (result.root["inbounds"] as JsonArray).size)
    }

    @Test
    fun `normalized mtu is runtime only and session name is neutral`() {
        val source = root()
        val options = VpnHidingOptions(
            neutralSessionName = true,
            tunMtuMode = TunMtuMode.Normalize1500,
        )

        val result = VpnRuntimeHardening.apply(source, options) as RuntimeHardeningResult.Ready
        val tun = (result.root["inbounds"] as JsonArray).single() as JsonObject

        assertEquals("1500", (tun["mtu"] as JsonPrimitive).content)
        assertFalse("mtu" in source.toString())
        assertEquals("Системная сеть", VpnRuntimeHardening.sessionName(options))
        assertEquals("QuantumVPN", VpnRuntimeHardening.sessionName(VpnHidingOptions()))
    }

    @Test
    fun `normalized mtu clamps tun to userspace wireguard endpoint`() {
        val source = root(
            rootExtra = """
                ,"endpoints":[{"type":"wireguard","tag":"wg","mtu":1280}]
            """.trimIndent(),
        )

        val result = VpnRuntimeHardening.apply(source, VpnHidingOptions())
            as RuntimeHardeningResult.Ready
        val tun = (result.root["inbounds"] as JsonArray).single() as JsonObject

        assertEquals("1280", (tun["mtu"] as JsonPrimitive).content)
        assertFalse("stored profile must remain untouched", "\"mtu\":1500" in source.toString())
    }

    @Test
    fun `normalized mtu uses smallest userspace wireguard endpoint`() {
        val source = root(
            rootExtra = """
                ,"endpoints":[
                  {"type":"wireguard","tag":"wg-a","mtu":1408},
                  {"type":"wireguard","tag":"wg-b","mtu":1280},
                  {"type":"wireguard","tag":"wg-system","system":true,"mtu":1200}
                ]
            """.trimIndent(),
        )

        val result = VpnRuntimeHardening.apply(source, VpnHidingOptions())
            as RuntimeHardeningResult.Ready
        val tun = (result.root["inbounds"] as JsonArray).single() as JsonObject

        assertEquals("1280", (tun["mtu"] as JsonPrimitive).content)
    }

    @Test
    fun `normalized mtu still applies to system wireguard`() {
        val source = root(
            rootExtra = """
                ,"endpoints":[{"type":"wireguard","tag":"wg-system","system":true}]
            """.trimIndent(),
        )

        val result = VpnRuntimeHardening.apply(source, VpnHidingOptions())
            as RuntimeHardeningResult.Ready
        val tun = (result.root["inbounds"] as JsonArray).single() as JsonObject

        assertEquals("1500", (tun["mtu"] as JsonPrimitive).content)
    }

    private fun root(
        experimental: String? = null,
        extraInbound: String = "",
        rootExtra: String = "",
    ): JsonObject {
        val suffix = experimental?.let { ",$it" }.orEmpty()
        return JsonConfig.parse(
            """
                {
                  "inbounds":[{"type":"tun","address":["172.19.0.1/30","fd00::1/126"],"auto_route":true}$extraInbound]
                  $suffix
                  $rootExtra
                }
            """.trimIndent(),
        ) as JsonObject
    }
}
