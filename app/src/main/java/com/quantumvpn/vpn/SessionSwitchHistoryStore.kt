package com.quantumvpn.vpn

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.quantumvpn.config.JsonConfig
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
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

data class ServerSwitchEvent(
    val epochMillis: Long,
    val profileId: String,
    val outboundTag: String,
    val countryCode: String? = null,
)

private val Context.sessionHistoryDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "session_switch_history",
)

class SessionSwitchHistoryStore(context: Context) {
    private val dataStore = context.applicationContext.sessionHistoryDataStore

    val events: Flow<List<ServerSwitchEvent>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { decode(it[EVENTS].orEmpty()) }

    suspend fun record(profileId: String, outboundTag: String, countryCode: String?) {
        dataStore.edit { preferences ->
            val next = listOf(
                ServerSwitchEvent(
                    epochMillis = System.currentTimeMillis(),
                    profileId = profileId,
                    outboundTag = outboundTag.take(120),
                    countryCode = countryCode?.take(8),
                ),
            ) + decode(preferences[EVENTS].orEmpty())
            preferences[EVENTS] = encode(next.take(MAX))
        }
    }

    suspend fun clear() {
        dataStore.edit { it.remove(EVENTS) }
    }

    private fun decode(raw: String): List<ServerSwitchEvent> {
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val array = JsonConfig.parse(raw) as? JsonArray ?: return emptyList()
            array.mapNotNull { element ->
                val obj = element as? JsonObject ?: return@mapNotNull null
                ServerSwitchEvent(
                    epochMillis = (obj["t"] as? JsonPrimitive)?.longOrNull ?: return@mapNotNull null,
                    profileId = (obj["p"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null,
                    outboundTag = (obj["o"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null,
                    countryCode = (obj["c"] as? JsonPrimitive)?.contentOrNull,
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun encode(items: List<ServerSwitchEvent>): String =
        JsonConfig.format(
            buildJsonArray {
                items.forEach { item ->
                    add(
                        buildJsonObject {
                            put("t", item.epochMillis)
                            put("p", item.profileId)
                            put("o", item.outboundTag)
                            item.countryCode?.let { put("c", it) }
                        },
                    )
                }
            },
        )

    private companion object {
        val EVENTS = stringPreferencesKey("events_json")
        const val MAX = 40
    }
}
