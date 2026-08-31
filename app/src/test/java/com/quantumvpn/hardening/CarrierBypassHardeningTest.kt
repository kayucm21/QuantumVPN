package com.quantumvpn.hardening

import com.quantumvpn.config.JsonConfig
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CarrierBypassHardeningTest {
    @Test
    fun `standard injects outbound fragment and route record only`() {
        val source = sampleRoot()
        val result = CarrierBypassHardening.apply(source, BypassPreset.Standard.toOptions(true))
        val tls = outboundTls(result.root)

        assertTrue((tls["record_fragment"] as JsonPrimitive).booleanOrNull == true)
        assertTrue((tls["fragment"] as JsonPrimitive).booleanOrNull == true)
        assertEquals("500ms", (tls["fragment_fallback_delay"] as JsonPrimitive).content)
        assertTrue(result.patchedTlsCount >= 1)
        assertTrue(result.routeOptionsInjected)

        val first = ((result.root["route"] as JsonObject)["rules"] as JsonArray).first() as JsonObject
        assertEquals("route-options", (first["action"] as JsonPrimitive).content)
        assertTrue((first["tls_record_fragment"] as JsonPrimitive).booleanOrNull == true)
        assertFalse((first["tls_fragment"] as? JsonPrimitive)?.booleanOrNull == true)
    }

    @Test
    fun `aggressive does not inject route tls_fragment`() {
        val result = CarrierBypassHardening.apply(sampleRoot(), BypassPreset.Aggressive.toOptions(true))
        val first = ((result.root["route"] as JsonObject)["rules"] as JsonArray).first() as JsonObject
        assertTrue((first["tls_record_fragment"] as JsonPrimitive).booleanOrNull == true)
        assertFalse((first["tls_fragment"] as? JsonPrimitive)?.booleanOrNull == true)
        val tls = outboundTls(result.root)
        assertTrue((tls["fragment"] as JsonPrimitive).booleanOrNull == true)
    }

    @Test
    fun `reality never gets clienthello fragment`() {
        val source = JsonConfig.parse(
            """
            {
              "outbounds":[{
                "type":"vless",
                "tag":"proxy",
                "server":"example.com",
                "server_port":443,
                "tls":{"enabled":true,"server_name":"example.com","reality":{"enabled":true}}
              }],
              "route":{"rules":[{"action":"route","outbound":"proxy"}]}
            }
            """.trimIndent(),
        ) as JsonObject
        val tls = outboundTls(
            CarrierBypassHardening.apply(source, BypassPreset.Aggressive.toOptions(true)).root,
        )
        assertTrue((tls["record_fragment"] as JsonPrimitive).booleanOrNull == true)
        assertFalse((tls["fragment"] as? JsonPrimitive)?.booleanOrNull == true)
    }

    @Test
    fun `soft preset uses record fragment only without route options`() {
        val result = CarrierBypassHardening.apply(
            sampleRoot(),
            BypassPreset.Soft.toOptions(enabled = true),
        )
        val tls = outboundTls(result.root)
        assertTrue((tls["record_fragment"] as JsonPrimitive).booleanOrNull == true)
        assertFalse((tls["fragment"] as? JsonPrimitive)?.booleanOrNull == true)
        assertFalse(result.routeOptionsInjected)
    }

    @Test
    fun `aggressive toggle upgrades soft to aggressive`() {
        val opts = resolveBypassOptions(
            enabled = true,
            preset = BypassPreset.Soft,
            alwaysAggressive = true,
        )
        assertEquals(BypassPreset.Aggressive, opts.preset)
        assertTrue(opts.aggressive)
    }

    @Test
    fun `idempotent route-options injection`() {
        val once = CarrierBypassHardening.apply(sampleRoot(), BypassPreset.Standard.toOptions(true))
        val twice = CarrierBypassHardening.apply(once.root, BypassPreset.Aggressive.toOptions(true))
        val rules = (twice.root["route"] as JsonObject)["rules"] as JsonArray
        val optionsCount = rules.count {
            val rule = it as? JsonObject ?: return@count false
            (rule["action"] as? JsonPrimitive)?.content == "route-options"
        }
        assertEquals(1, optionsCount)
    }

    @Test
    fun `hysteria gets udp_fragment`() {
        val source = JsonConfig.parse(
            """
            {
              "outbounds":[{
                "type":"hysteria2",
                "tag":"proxy",
                "server":"example.com",
                "server_port":443
              }],
              "route":{"rules":[{"action":"route","outbound":"proxy"}]}
            }
            """.trimIndent(),
        ) as JsonObject
        val result = CarrierBypassHardening.apply(source, BypassPreset.Aggressive.toOptions(true))
        val outbound = (result.root["outbounds"] as JsonArray).first() as JsonObject
        assertTrue((outbound["udp_fragment"] as JsonPrimitive).booleanOrNull == true)
        assertTrue(result.patchedTlsCount >= 1)
    }

    @Test
    fun `disabled leaves outbounds untouched`() {
        val source = sampleRoot()
        val patched = CarrierBypassHardening.apply(source, CarrierBypassOptions(enabled = false))
        assertEquals(source, patched.root)
    }

    private fun outboundTls(root: JsonObject): JsonObject {
        val outbound = (root["outbounds"] as JsonArray).first() as JsonObject
        return outbound["tls"] as JsonObject
    }

    private fun sampleRoot(): JsonObject = JsonConfig.parse(
        """
        {
          "outbounds":[{
            "type":"vless",
            "tag":"proxy",
            "server":"example.com",
            "server_port":443,
            "tls":{"enabled":true,"server_name":"example.com"}
          }],
          "route":{"auto_detect_interface":true,"rules":[{"action":"route","outbound":"proxy"}]}
        }
        """.trimIndent(),
    ) as JsonObject
}
