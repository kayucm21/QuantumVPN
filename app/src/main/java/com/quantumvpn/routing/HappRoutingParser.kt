package com.quantumvpn.routing

import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

/**
 * Happ-compatible routing profile carried in subscription bodies / `routing` headers
 * (`happ://routing/add|onadd/{base64}`, `happ://routing/off`).
 */
data class HappRoutingProfile(
    val name: String,
    val globalProxy: Boolean = true,
    val directSites: List<String> = emptyList(),
    val directIp: List<String> = emptyList(),
    val proxySites: List<String> = emptyList(),
    val proxyIp: List<String> = emptyList(),
    val blockSites: List<String> = emptyList(),
    val blockIp: List<String> = emptyList(),
    val routeOrder: String = "block-proxy-direct",
)

data class HappRoutingProfileUpdate(
    val profile: HappRoutingProfile,
    val activate: Boolean,
)

sealed interface HappRoutingImport {
    data object None : HappRoutingImport
    data object Disable : HappRoutingImport
    data class Profiles(
        val updates: List<HappRoutingProfileUpdate>,
    ) : HappRoutingImport
}

data class HappRoutingExtract(
    val bodyWithoutRouting: String,
    val import: HappRoutingImport,
)

object HappRoutingParser {
    private val LINK = Regex(
        """(?i)^happ://routing/(add|onadd)/([A-Za-z0-9+/=_-]+)$""",
    )
    private val OFF = Regex("""(?i)^happ://routing/off$""")

    fun extractFromBody(raw: String): HappRoutingExtract {
        val lines = raw.removePrefix("\uFEFF").lineSequence().toList()
        val kept = mutableListOf<String>()
        val updates = mutableListOf<HappRoutingProfileUpdate>()
        var disable = false
        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) {
                kept += line
                continue
            }
            when {
                OFF.matches(trimmed) -> disable = true
                else -> {
                    val match = LINK.matchEntire(trimmed)
                    if (match != null) {
                        val activate = match.groupValues[1].equals("onadd", ignoreCase = true)
                        val profile = decodeProfile(match.groupValues[2])
                        updates += HappRoutingProfileUpdate(profile, activate)
                    } else {
                        kept += line
                    }
                }
            }
        }
        val import = when {
            disable && updates.isEmpty() -> HappRoutingImport.Disable
            updates.isNotEmpty() -> HappRoutingImport.Profiles(updates)
            disable -> HappRoutingImport.Disable
            else -> HappRoutingImport.None
        }
        return HappRoutingExtract(
            bodyWithoutRouting = kept.joinToString("\n").trim(),
            import = mergeDisable(import, disable),
        )
    }

    fun parseHeader(value: String?): HappRoutingImport {
        val trimmed = value?.trim().orEmpty()
        if (trimmed.isEmpty()) return HappRoutingImport.None
        // Header may contain one link or comma-separated links.
        val parts = trimmed.split(',', '\n').map(String::trim).filter(String::isNotEmpty)
        val updates = mutableListOf<HappRoutingProfileUpdate>()
        var disable = false
        for (part in parts) {
            when {
                OFF.matches(part) -> disable = true
                else -> {
                    val match = LINK.matchEntire(part) ?: continue
                    val activate = match.groupValues[1].equals("onadd", ignoreCase = true)
                    updates += HappRoutingProfileUpdate(decodeProfile(match.groupValues[2]), activate)
                }
            }
        }
        return when {
            updates.isNotEmpty() -> HappRoutingImport.Profiles(updates)
            disable -> HappRoutingImport.Disable
            else -> HappRoutingImport.None
        }
    }

    fun merge(primary: HappRoutingImport, secondary: HappRoutingImport): HappRoutingImport {
        val updates = mutableListOf<HappRoutingProfileUpdate>()
        var disable = false
        fun absorb(item: HappRoutingImport) {
            when (item) {
                HappRoutingImport.None -> Unit
                HappRoutingImport.Disable -> disable = true
                is HappRoutingImport.Profiles -> updates += item.updates
            }
        }
        absorb(primary)
        absorb(secondary)
        return when {
            updates.isNotEmpty() -> HappRoutingImport.Profiles(updates)
            disable -> HappRoutingImport.Disable
            else -> HappRoutingImport.None
        }
    }

    fun decodeProfile(base64: String): HappRoutingProfile {
        val jsonText = try {
            val padded = base64.replace('-', '+').replace('_', '/')
            val rem = padded.length % 4
            val normalized = if (rem == 0) padded else padded + "=".repeat(4 - rem)
            String(Base64.getDecoder().decode(normalized), Charsets.UTF_8)
        } catch (error: Exception) {
            throw IllegalArgumentException("Некорректный Base64 профиля маршрутизации Happ.", error)
        }
        val root = try {
            com.quantumvpn.config.JsonConfig.parse(jsonText) as? JsonObject
                ?: throw IllegalArgumentException("Профиль маршрутизации Happ должен быть JSON-объектом.")
        } catch (error: Exception) {
            throw IllegalArgumentException("Не удалось разобрать JSON профиля маршрутизации Happ.", error)
        }
        val name = root.string("Name")?.trim().orEmpty()
            .ifEmpty { throw IllegalArgumentException("В профиле маршрутизации Happ нет Name.") }
        return HappRoutingProfile(
            name = name,
            globalProxy = root.boolish("GlobalProxy", default = true),
            directSites = root.stringList("DirectSites"),
            directIp = root.stringList("DirectIp"),
            proxySites = root.stringList("ProxySites"),
            proxyIp = root.stringList("ProxyIp"),
            blockSites = root.stringList("BlockSites"),
            blockIp = root.stringList("BlockIp"),
            routeOrder = root.string("RouteOrder") ?: "block-proxy-direct",
        )
    }

    private fun mergeDisable(import: HappRoutingImport, disable: Boolean): HappRoutingImport =
        if (disable && import is HappRoutingImport.None) HappRoutingImport.Disable else import

    private fun JsonObject.string(key: String): String? =
        (this[key] as? JsonPrimitive)?.contentOrNull

    private fun JsonObject.boolish(key: String, default: Boolean): Boolean {
        val value = this[key] ?: return default
        val primitive = value as? JsonPrimitive ?: return default
        primitive.booleanOrNull?.let { return it }
        return when (primitive.contentOrNull?.lowercase()) {
            "true", "1", "yes", "on" -> true
            "false", "0", "no", "off" -> false
            else -> default
        }
    }

    private fun JsonObject.stringList(key: String): List<String> {
        val element = this[key] ?: return emptyList()
        return when (element) {
            is JsonArray -> element.mapNotNull { (it as? JsonPrimitive)?.contentOrNull?.trim() }
                .filter(String::isNotEmpty)
            is JsonPrimitive -> element.contentOrNull?.trim()?.takeIf(String::isNotEmpty)?.let(::listOf).orEmpty()
            else -> emptyList()
        }
    }
}
