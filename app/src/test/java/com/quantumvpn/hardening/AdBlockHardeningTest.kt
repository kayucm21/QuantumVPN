package com.quantumvpn.hardening

import com.quantumvpn.config.JsonConfig
import com.quantumvpn.config.RuntimeConfigBuilder
import com.quantumvpn.config.RuntimeConfigOptions
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AdBlockHardeningTest {
    private val baseProfile = """
        {
          "dns":{"servers":[{"type":"local","tag":"local-dns"}],"final":"local-dns"},
          "inbounds":[{"type":"tun","tag":"tun-in","auto_route":true,
            "address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],
            "route_address":["0.0.0.0/0","::/0"]}],
          "outbounds":[
            {"type":"direct","tag":"direct"},
            {"type":"vless","tag":"proxy","server":"vpn.example","uuid":"00000000-0000-4000-8000-000000000001"}
          ],
          "route":{"auto_detect_interface":true,"final":"direct","rules":[]}
        }
    """.trimIndent()

    @Test
    fun `applies dns reject and route reject rules`() {
        val root = JsonConfig.parse(baseProfile) as JsonObject
        val result = AdBlockHardening.apply(
            root,
            AdBlockOptions(enabled = true, level = AdBlockLevel.Standard),
            proxyTag = "proxy",
        )
        val routeRules = ((result["route"] as JsonObject)["rules"] as JsonArray)
        assertTrue(routeRules.any { (it as JsonObject).string("action") == "reject" })
        assertTrue(
            routeRules.any { (it as JsonObject).string("action") == "hijack-dns" },
        )
        assertTrue(
            routeRules.count { (it as JsonObject).string("action") == "hijack-dns" } >= 2,
        )
        val dnsRules = ((result["dns"] as JsonObject)["rules"] as JsonArray)
        assertTrue(dnsRules.isNotEmpty())
        assertTrue(
            dnsRules.any { (it as JsonObject).string("action") == "reject" },
        )
        val servers = ((result["dns"] as JsonObject)["servers"] as JsonArray)
        assertTrue(
            servers.any { (it as JsonObject).string("tag") == AdBlockHardening.ONLINE_FILTER_DNS_TAG },
        )
        assertTrue(
            servers.any {
                val o = it as JsonObject
                o.string("tag")?.startsWith(AdBlockHardening.ONLINE_FILTER_DNS_TAG) == true &&
                    (o.string("server") == AdBlockHardening.ONLINE_FILTER_HOST ||
                        o.string("server") == AdBlockHardening.ONLINE_FILTER_IPV4)
            },
        )
        assertEquals(
            AdBlockHardening.ONLINE_FILTER_DNS_TAG,
            (result["dns"] as JsonObject).string("final"),
        )
    }

    @Test
    fun `creates dns and route when profile lacks them`() {
        val minimal = """
            {
              "inbounds":[{"type":"tun","tag":"tun-in","auto_route":true,
                "address":["172.19.0.1/30"],"route_address":["0.0.0.0/0"]}],
              "outbounds":[{"type":"direct","tag":"direct"}]
            }
        """.trimIndent()
        val root = JsonConfig.parse(minimal) as JsonObject
        val result = AdBlockHardening.apply(root, AdBlockOptions(enabled = true))
        assertTrue(result["dns"] is JsonObject)
        assertTrue(result["route"] is JsonObject)
    }

    @Test
    fun `runtime builder keeps ad dns reject with fromJson dns mode`() {
        val built = RuntimeConfigBuilder.build(
            baseProfile,
            options = RuntimeConfigOptions(
                adBlockEnabled = true,
                adBlockOptions = AdBlockOptions(enabled = true, level = AdBlockLevel.Standard),
            ),
        )
        assertTrue(built is com.quantumvpn.config.RuntimeConfigResult.Ready)
        val root = JsonConfig.parse((built as com.quantumvpn.config.RuntimeConfigResult.Ready).json) as JsonObject
        val dnsRules = ((root["dns"] as JsonObject)["rules"] as JsonArray)
        assertTrue(dnsRules.any { (it as JsonObject).string("action") == "reject" })
        val routeRules = ((root["route"] as JsonObject)["rules"] as JsonArray)
        assertTrue(routeRules.any { (it as JsonObject).string("action") == "hijack-dns" })
    }

    @Test
    fun `strip removes managed rules`() {
        val root = JsonConfig.parse(baseProfile) as JsonObject
        val blocked = AdBlockHardening.apply(root, AdBlockOptions(enabled = true))
        val stripped = AdBlockHardening.strip(blocked)
        val routeRules = ((stripped["route"] as JsonObject)["rules"] as JsonArray)
        assertTrue(routeRules.none { (it as JsonObject).string("action") == "reject" })
    }

    @Test
    fun `disabled returns unchanged aside from strip`() {
        val root = JsonConfig.parse(baseProfile) as JsonObject
        val result = AdBlockHardening.apply(root, AdBlockOptions(enabled = false))
        assertEquals(root.toString(), result.toString())
    }

    private fun JsonObject.string(key: String): String? =
        (this[key] as? JsonPrimitive)?.contentOrNull
}
