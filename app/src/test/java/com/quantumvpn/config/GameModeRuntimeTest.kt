package com.quantumvpn.config

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class GameModeRuntimeTest {
    private fun rulesOf(json: String): JsonArray {
        val root = JsonConfig.parse(json) as JsonObject
        return (root["route"] as JsonObject)["rules"] as JsonArray
    }

    @Test
    fun `game packages go direct in a single first rule`() {
        val stored = validConfig()
        val result = RuntimeConfigBuilder.build(
            stored,
            options = RuntimeConfigOptions(
                gameModePackages = listOf("com.tencent.ig", "com.mobile.legends"),
            ),
        ) as RuntimeConfigResult.Ready
        val rules = rulesOf(result.json)
        val first = rules[0] as JsonObject

        val packages = (first["package_name"] as JsonArray).map { (it as JsonPrimitive).content }
        assertEquals(listOf("com.tencent.ig", "com.mobile.legends"), packages)
        assertEquals("route", (first["action"] as JsonPrimitive).content)
        assertEquals("direct", (first["outbound"] as JsonPrimitive).content)
        assertTrue("stored profile must stay untouched", "package_name" !in stored)
    }

    @Test
    fun `game rule wins over blocked packages`() {
        val result = RuntimeConfigBuilder.build(
            validConfig(),
            options = RuntimeConfigOptions(
                blockedPackageNames = listOf("com.tencent.ig"),
                gameModePackages = listOf("com.tencent.ig"),
            ),
        ) as RuntimeConfigResult.Ready
        val rules = rulesOf(result.json).map { it as JsonObject }

        // Игровое правило — всегда первое (применяется последним).
        assertEquals("direct", (rules[0]["outbound"] as JsonPrimitive).content)
        // Block-правило живо, но стоит ниже — игра побеждает.
        assertTrue(
            "blocked rule must survive below the game rule",
            rules.drop(1).any { (it["action"] as? JsonPrimitive)?.content == "reject" },
        )
    }

    @Test
    fun `invalid package names are dropped`() {
        val result = RuntimeConfigBuilder.build(
            validConfig(),
            options = RuntimeConfigOptions(
                gameModePackages = listOf("com.tencent.ig", "not a package!!", ""),
            ),
        ) as RuntimeConfigResult.Ready
        val first = rulesOf(result.json)[0] as JsonObject
        val packages = (first["package_name"] as JsonArray)
            .map { (it as JsonPrimitive).content }

        assertEquals(listOf("com.tencent.ig"), packages)
    }

    @Test
    fun `empty game list adds no package rule`() {
        val result = RuntimeConfigBuilder.build(validConfig()) as RuntimeConfigResult.Ready
        val root = JsonConfig.parse(result.json) as JsonObject
        val rules = ((root["route"] as JsonObject)["rules"] as? JsonArray).orEmpty()

        assertTrue(
            "no package_name rule without game mode",
            rules.none { "package_name" in (it as JsonObject) },
        )
    }

    @Test
    fun `duplicates collapse to one entry`() {
        val result = RuntimeConfigBuilder.build(
            validConfig(),
            options = RuntimeConfigOptions(
                gameModePackages = listOf("com.tencent.ig", "com.tencent.ig"),
            ),
        ) as RuntimeConfigResult.Ready
        val packages = ((rulesOf(result.json)[0] as JsonObject)["package_name"] as JsonArray)
            .map { (it as JsonPrimitive).content }

        assertEquals(listOf("com.tencent.ig"), packages)
    }

    private fun validConfig(): String = """
        {
          "inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"auto_route":true}],
          "outbounds":[
            {"type":"direct","tag":"server-a"},
            {"type":"selector","tag":"zapret-proxy","outbounds":["server-a"],"default":"server-a"},
            {"type":"direct","tag":"direct"}
          ],
          "route":{"auto_detect_interface":true,"final":"zapret-proxy"}
        }
    """.trimIndent()
}
