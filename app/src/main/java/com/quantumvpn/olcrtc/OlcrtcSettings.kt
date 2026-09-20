package com.quantumvpn.olcrtc

import com.quantumvpn.config.OutboundDescription
import java.security.MessageDigest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Engine parameters for an olcRTC (OlConnect WebRTC) server. These values are
 * NOT stored inside the sing-box config (the extended core rejects unknown
 * fields); they live in a SecureVault-sealed sidecar keyed by profile id and
 * outbound tag.
 */
data class OlcrtcSettings(
    val provider: String,
    val transport: String,
    val compatibilityMode: String,
    val roomId: String,
    val clientId: String,
    val keyHex: String,
    val dnsServer: String? = null,
    val roomPassword: String? = null,
    val vp8Fps: Int = DEFAULT_VP8_FPS,
    val vp8BatchSize: Int = DEFAULT_VP8_BATCH,
    val keepaliveSeconds: Int = DEFAULT_KEEPALIVE_SECONDS,
    val udpEnabled: Boolean = true,
    val socksPort: Int,
) {
    init {
        require(provider.lowercase() in PROVIDERS) { "Неизвестный olcRTC provider: $provider" }
        require(transport.lowercase() in TRANSPORTS.values) {
            "Неизвестный olcRTC transport: $transport"
        }
        val supported = SUPPORTED_TRANSPORTS.getValue(provider.lowercase())
        require(transport.lowercase() in supported) {
            "Provider $provider не поддерживает transport $transport (нужен ${supported.first()})."
        }
        require(keyHex.length == KEY_HEX_LENGTH && Regex("^[0-9a-fA-F]{$KEY_HEX_LENGTH}$").matches(keyHex)) {
            "olcRTC key должен быть 64 hex-символа."
        }
        require(roomId.isNotBlank() && clientId.isNotBlank()) {
            "olcRTC требует roomId и clientId."
        }
        require(socksPort in SOCKS_PORT_RANGE_FIRST..SOCKS_PORT_RANGE_LAST) {
            "Некорректный SOCKS-порт olcRTC: $socksPort."
        }
    }

    fun readyTimeoutMillis(): Long = when (provider.lowercase()) {
        "telemost" -> TELEMOST_READY_TIMEOUT_MILLIS
        else -> LONG_READY_TIMEOUT_MILLIS
    }

    fun toJson(): JsonObject = buildJsonObject {
        put("provider", provider)
        put("transport", transport)
        put("core", compatibilityMode)
        put("room", roomId)
        put("client", clientId)
        put("key", keyHex)
        dnsServer?.takeIf(String::isNotBlank)?.let { put("dns", it) }
        roomPassword?.takeIf(String::isNotBlank)?.let { put("rp", it) }
        put("f", vp8Fps)
        put("b", vp8BatchSize)
        put("ka", keepaliveSeconds)
        put("udp", udpEnabled)
        put("sport", socksPort)
    }

    companion object {
        const val SCHEME_OLCRTC = "olcrtc://"
        const val SCHEME_OLCONNECT = "olconnect://"
        const val KEY_HEX_LENGTH = 64
        const val DEFAULT_VP8_FPS = 120
        const val DEFAULT_VP8_BATCH = 64
        const val DEFAULT_KEEPALIVE_SECONDS = 15
        const val TELEMOST_READY_TIMEOUT_MILLIS = 15_000L
        const val LONG_READY_TIMEOUT_MILLIS = 45_000L
        const val SOCKS_PORT_BASE = 27_100
        const val SOCKS_PORT_RANGE = 300
        const val SOCKS_PORT_RANGE_FIRST = SOCKS_PORT_BASE
        const val SOCKS_PORT_RANGE_LAST = SOCKS_PORT_BASE + SOCKS_PORT_RANGE - 1

        val PROVIDERS = setOf("jitsi", "telemost", "wbstream")
        val TRANSPORTS = mapOf(
            "jitsi" to "datachannel",
            "telemost" to "vp8channel",
            "wbstream" to "vp8channel",
        )

        private val SUPPORTED_TRANSPORTS = mapOf(
            "jitsi" to setOf("datachannel", "vp8channel"),
            "telemost" to setOf("vp8channel"),
            "wbstream" to setOf("vp8channel"),
        )

        fun deterministicSocksPort(identityKey: String): Int {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(identityKey.toByteArray(Charsets.UTF_8))
            val value = ((digest[0].toInt() and 0xff) shl 8) or (digest[1].toInt() and 0xff)
            return SOCKS_PORT_BASE + value % SOCKS_PORT_RANGE
        }

        fun fromJson(json: JsonObject): OlcrtcSettings? {
            val provider = json.string("provider") ?: return null
            val transport = json.string("transport") ?: return null
            val roomId = json.string("room") ?: return null
            val clientId = json.string("client") ?: return null
            val keyHex = json.string("key") ?: return null
            val socksPort = json.int("sport") ?: return null
            return runCatching {
                OlcrtcSettings(
                    provider = provider,
                    transport = transport,
                    compatibilityMode = json.string("core") ?: "current",
                    roomId = roomId,
                    clientId = clientId,
                    keyHex = keyHex,
                    dnsServer = json.string("dns"),
                    roomPassword = json.string("rp"),
                    vp8Fps = json.int("f") ?: DEFAULT_VP8_FPS,
                    vp8BatchSize = json.int("b") ?: DEFAULT_VP8_BATCH,
                    keepaliveSeconds = json.int("ka") ?: DEFAULT_KEEPALIVE_SECONDS,
                    udpEnabled = json["udp"]?.let { (it as? JsonPrimitive)?.booleanOrNull } ?: true,
                    socksPort = socksPort,
                )
            }.getOrNull()
        }
    }
}

private fun JsonObject.string(key: String): String? =
    (this[key] as? JsonPrimitive)?.contentOrNull

private fun JsonObject.int(key: String): Int? =
    (this[key] as? JsonPrimitive)?.intOrNull