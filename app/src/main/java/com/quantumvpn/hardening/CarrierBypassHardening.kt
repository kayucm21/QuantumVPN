package com.quantumvpn.hardening

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

/**
 * Happ-like DPI / carrier-throttle mitigations for the runtime JSON copy only.
 *
 * Applies to **all carriers** and proxy types including VLESS/Trojan/Hysteria/TUIC:
 * - Outbound TLS fragment / record_fragment (not on Reality ClientHello)
 * - udp_fragment for UDP-based proxies (Hysteria etc.)
 * - route-options tls_record_fragment (never global tls_fragment — breaks traffic)
 */
data class CarrierBypassOptions(
    val enabled: Boolean = true,
    val aggressive: Boolean = true,
    val preset: BypassPreset = BypassPreset.Standard,
)

enum class BypassPreset {
    Soft,
    Standard,
    /** Strong carrier mode (all mobile operators, not only Т2). */
    Tele2,
    Aggressive,
}

fun BypassPreset.toOptions(enabled: Boolean): CarrierBypassOptions = when (this) {
    BypassPreset.Soft -> CarrierBypassOptions(enabled = enabled, aggressive = false, preset = this)
    BypassPreset.Standard, BypassPreset.Tele2, BypassPreset.Aggressive ->
        CarrierBypassOptions(enabled = enabled, aggressive = true, preset = this)
}

fun resolveBypassOptions(
    enabled: Boolean,
    preset: BypassPreset,
    alwaysAggressive: Boolean,
): CarrierBypassOptions {
    if (!enabled) {
        return CarrierBypassOptions(enabled = false, aggressive = false, preset = preset)
    }
    // Operator / Aggressive always keep reinforced (aggressive) mode.
    // alwaysAggressive only upgrades Soft/Standard → Aggressive; never downgrades Tele2.
    val effective = when {
        preset == BypassPreset.Tele2 || preset == BypassPreset.Aggressive -> preset
        alwaysAggressive -> BypassPreset.Aggressive
        else -> preset
    }
    return effective.toOptions(enabled = true)
}

data class CarrierBypassResult(
    val root: JsonObject,
    val patchedTlsCount: Int,
    val routeOptionsInjected: Boolean,
)

object CarrierBypassHardening {
    data class RuntimePresence(
        val tlsFragmentOutboundCount: Int,
        val routeOptionsPresent: Boolean,
        val udpFragmentOutboundCount: Int = 0,
    )

    fun inspect(root: JsonObject): RuntimePresence {
        fun countTls(key: String): Int =
            ((root[key] as? JsonArray)?.mapNotNull { it as? JsonObject }.orEmpty())
                .count { outbound ->
                    val tls = outbound["tls"] as? JsonObject ?: return@count false
                    tls.boolean("fragment") == true || tls.boolean("record_fragment") == true
                }
        fun countUdp(key: String): Int =
            ((root[key] as? JsonArray)?.mapNotNull { it as? JsonObject }.orEmpty())
                .count { it.boolean("udp_fragment") == true }
        val route = root["route"] as? JsonObject
        val routePresent = ((route?.get("rules") as? JsonArray)
            ?.mapNotNull { it as? JsonObject }
            .orEmpty())
            .any {
                it.string("action") == "route-options" &&
                    (it.boolean("tls_fragment") == true || it.boolean("tls_record_fragment") == true)
            }
        return RuntimePresence(
            tlsFragmentOutboundCount = countTls("outbounds") + countTls("endpoints"),
            routeOptionsPresent = routePresent,
            udpFragmentOutboundCount = countUdp("outbounds") + countUdp("endpoints"),
        )
    }

    fun apply(root: JsonObject, options: CarrierBypassOptions): CarrierBypassResult {
        if (!options.enabled) {
            return CarrierBypassResult(root, patchedTlsCount = 0, routeOptionsInjected = false)
        }
        var next = root
        var patched = 0
        val out = patchArrayKey(next, "outbounds", options.preset)
        next = out.root
        patched += out.patched
        val ep = patchArrayKey(next, "endpoints", options.preset)
        next = ep.root
        patched += ep.patched
        val withRoute = injectRouteOptions(next, options.preset)
        return CarrierBypassResult(
            root = withRoute.root,
            patchedTlsCount = patched,
            routeOptionsInjected = withRoute.injected,
        )
    }

    fun applyRoot(root: JsonObject, options: CarrierBypassOptions): JsonObject =
        apply(root, options).root

    private data class ArrayPatch(val root: JsonObject, val patched: Int)
    private data class RoutePatch(val root: JsonObject, val injected: Boolean)

    private fun patchArrayKey(root: JsonObject, key: String, preset: BypassPreset): ArrayPatch {
        val array = root[key] as? JsonArray ?: return ArrayPatch(root, 0)
        var patched = 0
        val next = JsonArray(
            array.map { element ->
                val obj = element as? JsonObject ?: return@map element
                val result = patchProxy(obj, preset)
                if (result.changed) patched += 1
                result.outbound
            },
        )
        return ArrayPatch(
            root = JsonObject(root.toMutableMap().apply { this[key] = next }),
            patched = patched,
        )
    }

    private data class ProxyPatch(val outbound: JsonObject, val changed: Boolean)

    private fun patchProxy(outbound: JsonObject, preset: BypassPreset): ProxyPatch {
        val type = outbound.string("type") ?: return ProxyPatch(outbound, false)
        if (type in SKIP_TYPES) return ProxyPatch(outbound, false)

        var changed = false
        val map = outbound.toMutableMap()
        val udpProxy = type in UDP_PROXY_TYPES
        if (preset != BypassPreset.Soft || udpProxy) {
            if (map["udp_fragment"] == null) {
                map["udp_fragment"] = JsonPrimitive(true)
                changed = true
            }
        }
        if (preset == BypassPreset.Tele2 || preset == BypassPreset.Aggressive) {
            if (!udpProxy && map["tcp_fast_open"] == null) {
                map["tcp_fast_open"] = JsonPrimitive(true)
                changed = true
            }
        }

        val tls = outbound["tls"] as? JsonObject
        if (tls != null && tls.boolean("enabled") != false) {
            map["tls"] = patchTls(tls, preset)
            return ProxyPatch(JsonObject(map), true)
        }
        // Hysteria / TUIC without nested tls still count as patched when udp_fragment applied.
        return ProxyPatch(JsonObject(map), changed)
    }

    private fun patchTls(tls: JsonObject, preset: BypassPreset): JsonObject {
        val tlsMap = tls.toMutableMap()
        val hasReality = (tls["reality"] as? JsonObject)?.boolean("enabled") == true
        val utlsEnabled = (tls["utls"] as? JsonObject)?.boolean("enabled") == true
        val delay = when (preset) {
            BypassPreset.Soft -> "200ms"
            BypassPreset.Standard -> FALLBACK_DELAY_STANDARD
            BypassPreset.Tele2, BypassPreset.Aggressive -> FALLBACK_DELAY_CARRIER
        }

        if (hasReality) {
            tlsMap["record_fragment"] = JsonPrimitive(true)
            tlsMap.remove("fragment")
            tlsMap.remove("fragment_fallback_delay")
            return JsonObject(tlsMap)
        }

        tlsMap["record_fragment"] = JsonPrimitive(true)
        when (preset) {
            BypassPreset.Soft -> {
                if (tlsMap["fragment"] != null) {
                    tlsMap["fragment_fallback_delay"] = JsonPrimitive(delay)
                }
            }
            BypassPreset.Standard, BypassPreset.Tele2, BypassPreset.Aggressive -> {
                tlsMap["fragment"] = JsonPrimitive(true)
                tlsMap["fragment_fallback_delay"] = JsonPrimitive(delay)
            }
        }

        if (preset == BypassPreset.Aggressive && !utlsEnabled) {
            tlsMap["utls"] = buildJsonObject {
                put("enabled", true)
                put("fingerprint", "chrome")
            }
        }
        return JsonObject(tlsMap)
    }

    private fun injectRouteOptions(root: JsonObject, preset: BypassPreset): RoutePatch {
        if (preset == BypassPreset.Soft) {
            return RoutePatch(root, injected = false)
        }
        val route = root["route"] as? JsonObject ?: return RoutePatch(root, false)
        val rules = (route["rules"] as? JsonArray)?.toMutableList() ?: mutableListOf()
        rules.removeAll(::isManagedRouteOptions)

        val delay = when (preset) {
            BypassPreset.Tele2, BypassPreset.Aggressive -> FALLBACK_DELAY_CARRIER
            else -> FALLBACK_DELAY_STANDARD
        }
        val optionsRule = buildJsonObject {
            put("action", "route-options")
            put("tls_record_fragment", true)
            if (preset == BypassPreset.Tele2 || preset == BypassPreset.Aggressive) {
                put("tls_fragment_fallback_delay", delay)
            }
        }
        rules.add(0, optionsRule)
        val nextRoute = JsonObject(route.toMutableMap().apply {
            this["rules"] = JsonArray(rules)
        })
        return RoutePatch(
            root = JsonObject(root.toMutableMap().apply { this["route"] = nextRoute }),
            injected = true,
        )
    }

    private fun isManagedRouteOptions(element: kotlinx.serialization.json.JsonElement): Boolean {
        val rule = element as? JsonObject ?: return false
        if (rule.string("action") != "route-options") return false
        val hasFragment =
            rule.boolean("tls_fragment") == true || rule.boolean("tls_record_fragment") == true
        if (!hasFragment) return false
        val allowed = setOf(
            "action",
            "tls_fragment",
            "tls_record_fragment",
            "tls_fragment_fallback_delay",
        )
        return rule.keys.all { it in allowed }
    }

    private fun JsonObject.string(name: String): String? =
        (get(name) as? JsonPrimitive)?.contentOrNull

    private fun JsonObject.boolean(name: String): Boolean? =
        (get(name) as? JsonPrimitive)?.booleanOrNull

    private val SKIP_TYPES = setOf(
        "direct", "block", "dns", "selector", "urltest", "tor", "ssh", "wireguard",
    )

    private val UDP_PROXY_TYPES = setOf(
        "hysteria", "hysteria2", "tuic", "shadowquic",
    )

    private const val FALLBACK_DELAY_STANDARD = "500ms"
    private const val FALLBACK_DELAY_CARRIER = "800ms"
}
