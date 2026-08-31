package com.quantumvpn.hardening

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

/**
 * Reject mDNS and common WebRTC/STUN endpoints in the runtime VPN copy only.
 */
object WebRtcMdnsHardening {
    fun apply(root: JsonObject, enabled: Boolean): JsonObject {
        if (!enabled) return root
        val route = root["route"] as? JsonObject ?: return root
        val rules = (route["rules"] as? JsonArray)?.toMutableList() ?: mutableListOf()
        rules.removeAll(::isManaged)
        rules.add(
            0,
            buildJsonObject {
                put("action", "reject")
                put("domain_suffix", JsonArray(STUN_SUFFIXES.map { JsonPrimitive(it) }))
            },
        )
        rules.add(
            0,
            buildJsonObject {
                put("action", "reject")
                put("port", 5353)
                put("network", "udp")
            },
        )
        rules.add(
            0,
            buildJsonObject {
                put("action", "reject")
                put("port_range", "19302:19309")
                put("network", "udp")
            },
        )
        return JsonObject(
            root.toMutableMap().apply {
                this["route"] = JsonObject(
                    route.toMutableMap().apply {
                        this["rules"] = JsonArray(rules)
                    },
                )
            },
        )
    }

    private fun isManaged(element: JsonElement): Boolean {
        val rule = element as? JsonObject ?: return false
        if (rule.string("action") != "reject") return false
        val port = (rule["port"] as? JsonPrimitive)?.contentOrNull
        val range = (rule["port_range"] as? JsonPrimitive)?.contentOrNull
        if (port == "5353" || range == "19302:19309") return true
        val suffixes = (rule["domain_suffix"] as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            .orEmpty()
        return suffixes.contains("stun.l.google.com")
    }

    private fun JsonObject.string(name: String): String? =
        (get(name) as? JsonPrimitive)?.contentOrNull

    private val STUN_SUFFIXES = listOf(
        "stun.l.google.com",
        "stun1.l.google.com",
        "stun2.l.google.com",
        "stun3.l.google.com",
        "stun4.l.google.com",
        "stun.cloudflare.com",
        "global.stun.twilio.com",
    )
}
