package com.quantumvpn.vpn

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import java.io.IOException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import com.quantumvpn.config.JsonConfig

data class RecentServer(
    val profileId: String,
    val groupTag: String,
    val outboundTag: String,
    val displayName: String,
    val countryCode: String? = null,
    val flagEmoji: String? = null,
    val usedAtEpochMillis: Long,
)

private val Context.recentServersDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "recent_servers",
)

class RecentServersStore(context: Context) {
    private val dataStore = context.applicationContext.recentServersDataStore

    val recents: Flow<List<RecentServer>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { preferences ->
            decode(preferences[RECENTS_JSON].orEmpty())
                .sortedByDescending { it.usedAtEpochMillis }
                .take(MAX_RECENTS)
        }

    suspend fun record(entry: RecentServer) {
        dataStore.edit { preferences ->
            val current = decode(preferences[RECENTS_JSON].orEmpty())
            val next = listOf(entry) + current.filterNot {
                it.profileId == entry.profileId &&
                    it.groupTag == entry.groupTag &&
                    it.outboundTag == entry.outboundTag
            }
            preferences[RECENTS_JSON] = encode(next.take(MAX_RECENTS))
        }
    }

    suspend fun clear() {
        dataStore.edit { it.remove(RECENTS_JSON) }
    }

    private fun decode(raw: String): List<RecentServer> {
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val array = JsonConfig.parse(raw) as? JsonArray ?: return emptyList()
            array.mapNotNull { element ->
                val obj = element as? JsonObject ?: return@mapNotNull null
                RecentServer(
                    profileId = obj.string("profileId") ?: return@mapNotNull null,
                    groupTag = obj.string("groupTag") ?: return@mapNotNull null,
                    outboundTag = obj.string("outboundTag") ?: return@mapNotNull null,
                    displayName = obj.string("displayName") ?: return@mapNotNull null,
                    countryCode = obj.string("countryCode"),
                    flagEmoji = obj.string("flagEmoji"),
                    usedAtEpochMillis = (obj["usedAtEpochMillis"] as? JsonPrimitive)?.longOrNull ?: 0L,
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun encode(items: List<RecentServer>): String =
        JsonConfig.format(
            buildJsonArray {
                items.forEach { item ->
                    add(
                        buildJsonObject {
                            put("profileId", item.profileId)
                            put("groupTag", item.groupTag)
                            put("outboundTag", item.outboundTag)
                            put("displayName", item.displayName)
                            item.countryCode?.let { put("countryCode", it) }
                            item.flagEmoji?.let { put("flagEmoji", it) }
                            put("usedAtEpochMillis", item.usedAtEpochMillis)
                        },
                    )
                }
            },
        )

    private fun JsonObject.string(key: String): String? =
        (this[key] as? JsonPrimitive)?.contentOrNull

    private companion object {
        val RECENTS_JSON = stringPreferencesKey("recents_json")
        const val MAX_RECENTS = 8
    }
}
