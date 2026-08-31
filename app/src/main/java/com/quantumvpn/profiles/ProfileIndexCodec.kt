package com.quantumvpn.profiles

import com.quantumvpn.config.JsonConfig
import com.quantumvpn.config.string
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

object ProfileIndexCodec {
    const val VERSION = 1

    fun encode(profiles: List<ProfileMetadata>): String = JsonConfig.format(
        buildJsonObject {
            put("version", VERSION)
            put(
                "profiles",
                buildJsonArray {
                    profiles.forEach { profile ->
                        add(
                            buildJsonObject {
                                put("id", profile.id)
                                put("name", profile.name)
                                put("source", profile.source.storageValue)
                                put("created_at", profile.createdAtEpochMillis)
                                put("updated_at", profile.updatedAtEpochMillis)
                            },
                        )
                    }
                },
            )
        },
    )

    fun decode(raw: String): List<ProfileMetadata> {
        val root = JsonConfig.parse(raw) as? JsonObject
            ?: throw ProfileStoreException("Повреждён индекс профилей.")
        val version = (root["version"] as? JsonPrimitive)?.longOrNull?.toInt()
        if (version != VERSION) throw ProfileStoreException("Неподдерживаемая версия индекса: $version.")
        val items = root["profiles"] as? JsonArray
            ?: throw ProfileStoreException("В индексе отсутствует список профилей.")
        val result = items.map { element ->
            val item = element as? JsonObject
                ?: throw ProfileStoreException("Повреждена запись профиля в индексе.")
            val id = item.string("id")
                ?.takeIf(ID_PATTERN::matches)
                ?: throw ProfileStoreException("Некорректный id профиля в индексе.")
            val name = item.string("name")
                ?.trim()
                ?.takeIf(String::isNotEmpty)
                ?: throw ProfileStoreException("У профиля отсутствует имя.")
            val createdAt = item.long("created_at")
            val updatedAt = item.long("updated_at")
            ProfileMetadata(
                id = id,
                name = name,
                source = ProfileSource.fromStorage(item.string("source").orEmpty()),
                createdAtEpochMillis = createdAt,
                updatedAtEpochMillis = updatedAt,
            )
        }
        if (result.map(ProfileMetadata::id).distinct().size != result.size) {
            throw ProfileStoreException("Индекс содержит повторяющиеся id.")
        }
        return result
    }

    private fun JsonObject.long(key: String): Long =
        (this[key] as? JsonPrimitive)?.longOrNull
            ?: throw ProfileStoreException("В индексе отсутствует '$key'.")

    private val ID_PATTERN = Regex("[0-9a-f]{32}")
}
