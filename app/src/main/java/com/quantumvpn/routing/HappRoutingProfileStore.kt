package com.quantumvpn.routing

import com.quantumvpn.config.JsonConfig
import com.quantumvpn.importer.ImportException
import com.quantumvpn.profiles.AndroidAtomicProfileWriter
import com.quantumvpn.profiles.AtomicProfileWriter
import com.quantumvpn.security.SecureVault
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

data class HappRoutingCatalog(
    val enabled: Boolean = true,
    val activeName: String? = null,
    val profiles: List<HappRoutingProfile> = emptyList(),
) {
    val active: HappRoutingProfile?
        get() = profiles.firstOrNull { it.name == activeName } ?: profiles.firstOrNull()

    val displayName: String
        get() = when {
            !enabled -> "Выкл"
            active != null -> active!!.name
            else -> "Нет профилей"
        }
}

/** Per-subscription Happ routing profiles (sidecar, like subscription URLs). */
class HappRoutingProfileStore(
    private val root: File,
    private val writer: AtomicProfileWriter = AndroidAtomicProfileWriter(),
    private val vault: SecureVault = SecureVault(),
) {
    private val mutex = Mutex()

    suspend fun get(profileId: String): HappRoutingCatalog = withContext(Dispatchers.IO) {
        mutex.withLock { read()[profileId] ?: HappRoutingCatalog() }
    }

    suspend fun put(profileId: String, catalog: HappRoutingCatalog) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val entries = read().toMutableMap()
            if (catalog.profiles.isEmpty() && !catalog.enabled) {
                entries.remove(profileId)
            } else {
                entries[profileId] = catalog
            }
            write(entries)
        }
    }

    suspend fun applyImport(profileId: String, import: HappRoutingImport): HappRoutingCatalog =
        withContext(Dispatchers.IO) {
            mutex.withLock {
                val entries = read().toMutableMap()
                val current = entries[profileId] ?: HappRoutingCatalog()
                val next = when (import) {
                    HappRoutingImport.None -> current
                    HappRoutingImport.Disable -> current.copy(enabled = false)
                    is HappRoutingImport.Profiles -> mergeProfiles(current, import.updates)
                }
                if (next.profiles.isEmpty() && !next.enabled) entries.remove(profileId)
                else entries[profileId] = next
                write(entries)
                next
            }
        }

    suspend fun setEnabled(profileId: String, enabled: Boolean): HappRoutingCatalog =
        withContext(Dispatchers.IO) {
            mutex.withLock {
                val entries = read().toMutableMap()
                val current = entries[profileId] ?: HappRoutingCatalog()
                val next = current.copy(enabled = enabled)
                entries[profileId] = next
                write(entries)
                next
            }
        }

    suspend fun setActive(profileId: String, name: String): HappRoutingCatalog =
        withContext(Dispatchers.IO) {
            mutex.withLock {
                val entries = read().toMutableMap()
                val current = entries[profileId] ?: error("Нет профилей маршрутизации для подписки.")
                require(current.profiles.any { it.name == name }) {
                    "Профиль маршрутизации '$name' не найден."
                }
                val next = current.copy(enabled = true, activeName = name)
                entries[profileId] = next
                write(entries)
                next
            }
        }

    suspend fun remove(profileId: String) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val entries = read().toMutableMap()
            if (entries.remove(profileId) != null) write(entries)
        }
    }

    suspend fun retain(profileIds: Set<String>) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val entries = read()
            val retained = entries.filterKeys(profileIds::contains)
            if (retained.size != entries.size) write(retained)
        }
    }

    private fun mergeProfiles(
        current: HappRoutingCatalog,
        updates: List<HappRoutingProfileUpdate>,
    ): HappRoutingCatalog {
        val byName = current.profiles.associateBy { it.name }.toMutableMap()
        var active = current.activeName
        var enabled = current.enabled
        for (update in updates) {
            byName[update.profile.name] = update.profile
            if (update.activate) {
                active = update.profile.name
                enabled = true
            }
        }
        if (active == null || active !in byName) {
            active = byName.keys.firstOrNull()
        }
        if (current.profiles.isEmpty() && updates.any { it.activate }) {
            enabled = true
        }
        if (current.profiles.isEmpty() && updates.isNotEmpty() && active == null) {
            active = updates.first().profile.name
            enabled = true
        }
        return HappRoutingCatalog(
            enabled = enabled,
            activeName = active,
            profiles = byName.values.sortedBy { it.name.lowercase() },
        )
    }

    private fun read(): Map<String, HappRoutingCatalog> {
        if (!file.isFile) return emptyMap()
        return try {
            val sealed = file.readBytes()
            val plain = vault.open(sealed)
            if (!vault.isSealed(sealed) && plain.isNotEmpty()) {
                runCatching { write(parse(plain.toString(Charsets.UTF_8))) }
            }
            parse(plain.toString(Charsets.UTF_8))
        } catch (error: Exception) {
            throw ImportException("Не удалось прочитать профили маршрутизации Happ.", cause = error)
        }
    }

    private fun parse(text: String): Map<String, HappRoutingCatalog> {
        val root = JsonConfig.parse(text) as? JsonObject
            ?: throw ImportException("Хранилище маршрутизации Happ повреждено.")
        return root.mapNotNull { (id, value) ->
            val obj = value as? JsonObject ?: return@mapNotNull null
            id to HappRoutingCatalog(
                enabled = (obj["enabled"] as? JsonPrimitive)?.contentOrNull?.toBooleanStrictOrNull() ?: true,
                activeName = (obj["activeName"] as? JsonPrimitive)?.contentOrNull,
                profiles = ((obj["profiles"] as? JsonArray) ?: JsonArray(emptyList())).mapNotNull { element ->
                    val item = element as? JsonObject ?: return@mapNotNull null
                    runCatching { decodeStored(item) }.getOrNull()
                },
            )
        }.toMap()
    }

    private fun decodeStored(obj: JsonObject): HappRoutingProfile {
        return HappRoutingProfile(
            name = (obj["name"] as? JsonPrimitive)?.contentOrNull?.trim().orEmpty()
                .ifEmpty { error("name") },
            globalProxy = (obj["globalProxy"] as? JsonPrimitive)?.contentOrNull?.toBooleanStrictOrNull() ?: true,
            directSites = stringList(obj["directSites"]),
            directIp = stringList(obj["directIp"]),
            proxySites = stringList(obj["proxySites"]),
            proxyIp = stringList(obj["proxyIp"]),
            blockSites = stringList(obj["blockSites"]),
            blockIp = stringList(obj["blockIp"]),
            routeOrder = (obj["routeOrder"] as? JsonPrimitive)?.contentOrNull ?: "block-proxy-direct",
        )
    }

    private fun stringList(element: kotlinx.serialization.json.JsonElement?): List<String> =
        ((element as? JsonArray) ?: JsonArray(emptyList())).mapNotNull {
            (it as? JsonPrimitive)?.contentOrNull?.trim()?.takeIf(String::isNotEmpty)
        }

    private fun write(entries: Map<String, HappRoutingCatalog>) {
        val json = buildJsonObject {
            entries.toSortedMap().forEach { (id, catalog) ->
                put(
                    id,
                    buildJsonObject {
                        put("enabled", catalog.enabled)
                        catalog.activeName?.let { put("activeName", it) }
                        put(
                            "profiles",
                            buildJsonArray {
                                catalog.profiles.forEach { profile ->
                                    add(
                                        buildJsonObject {
                                            put("name", profile.name)
                                            put("globalProxy", profile.globalProxy)
                                            put("routeOrder", profile.routeOrder)
                                            put("directSites", JsonArray(profile.directSites.map(::JsonPrimitive)))
                                            put("directIp", JsonArray(profile.directIp.map(::JsonPrimitive)))
                                            put("proxySites", JsonArray(profile.proxySites.map(::JsonPrimitive)))
                                            put("proxyIp", JsonArray(profile.proxyIp.map(::JsonPrimitive)))
                                            put("blockSites", JsonArray(profile.blockSites.map(::JsonPrimitive)))
                                            put("blockIp", JsonArray(profile.blockIp.map(::JsonPrimitive)))
                                        },
                                    )
                                }
                            },
                        )
                    },
                )
            }
        }
        writer.writeAtomic(file, vault.seal(JsonConfig.format(json).toByteArray(Charsets.UTF_8)))
    }

    private val file: File get() = File(root, "index.json")
}
