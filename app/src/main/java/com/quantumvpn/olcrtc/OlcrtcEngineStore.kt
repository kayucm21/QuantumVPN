package com.quantumvpn.olcrtc

import com.quantumvpn.config.OutboundDescription
import com.quantumvpn.config.JsonConfig
import com.quantumvpn.security.SecureVault
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

/** Detects our engine-backed servers ("socks" outbound to the local engine port). */
object OlcrtcProtocol {
    const val LABEL = "olcrtc"
    private val LOOPBACK = setOf("127.0.0.1", "::1", "localhost")

    fun isLoopbackSocks(description: OutboundDescription?): Boolean =
        description?.type == "socks" && description.serverHost in LOOPBACK

    /** Display type: local socks outbounds created by the olcrtc importer read as "olcrtc". */
    fun displayType(description: OutboundDescription?): String? =
        if (isLoopbackSocks(description)) LABEL else description?.type

    fun isLoopbackHost(hostname: String?): Boolean = hostname?.lowercase() in LOOPBACK
}

/**
 * SecureVault-sealed sidecar for olcRTC engine parameters. sing-box extended
 * rejects unknown config fields, so engine settings are stored separately and
 * keyed by `profileId -> outbound tag`.
 */
class OlcrtcEngineStore(
    private val root: File,
    private val vault: SecureVault = SecureVault(),
) {
    private val mutex = Mutex()
    private val file = File(root, "engines.json")

    suspend fun read(profileId: String): Map<String, OlcrtcSettings> = io {
        mutex.withLock { load()[profileId].orEmpty() }
    }

    suspend fun write(profileId: String, engines: Map<String, OlcrtcSettings>) = io {
        mutex.withLock {
            if (engines.isEmpty()) {
                val current = load()
                if (profileId !in current) return@withLock
                save(current - profileId)
            } else {
                save(load() + (profileId to engines))
            }
        }
    }

    suspend fun remove(profileId: String) = io {
        mutex.withLock {
            val current = load()
            if (profileId in current) save(current - profileId)
        }
    }

    suspend fun wipe() = io {
        mutex.withLock {
            if (file.exists()) file.delete()
        }
    }

    private fun load(): Map<String, Map<String, OlcrtcSettings>> {
        if (!file.isFile) return emptyMap()
        val root = runCatching {
            val plain = vault.open(file.readBytes()).toString(Charsets.UTF_8)
            JsonConfig.parse(plain) as? JsonObject
        }.getOrNull() ?: return emptyMap()
        return root.mapNotNull { (profileId, element) ->
            val byTag = (element as? JsonObject)
                ?.mapNotNull { (tag, settingsJson) ->
                    (settingsJson as? JsonObject)
                        ?.let { OlcrtcSettings.fromJson(it) }
                        ?.let { tag to it }
                }
                ?.toMap()
                .orEmpty()
            if (byTag.isEmpty()) null else profileId to byTag
        }.toMap()
    }

    private fun save(value: Map<String, Map<String, OlcrtcSettings>>) {
        root.mkdirs()
        val json = buildJsonObject {
            value.forEach { (profileId, engines) ->
                put(
                    profileId,
                    buildJsonObject {
                        engines.forEach { (tag, settings) -> put(tag, settings.toJson()) }
                    },
                )
            }
        }
        file.writeBytes(vault.seal(JsonConfig.format(json).toByteArray(Charsets.UTF_8)))
    }

    private suspend fun <T> io(block: suspend () -> T): T = withContext(Dispatchers.IO) { block() }
}