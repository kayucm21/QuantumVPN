package com.quantumvpn.diagnostics

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

data class AppEvent(
    val epochMillis: Long,
    val kind: String,
    val message: String,
)

private val Context.eventJournalDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "event_journal",
)

/** Durable redacted event journal for reconnect / ping / import / diagnosis. */
class EventJournalStore(context: Context) {
    private val dataStore = context.applicationContext.eventJournalDataStore

    val events: Flow<List<AppEvent>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { decode(it[EVENTS].orEmpty()) }

    suspend fun append(kind: String, message: String) {
        val clean = SecretRedactor.redactInline(message.take(280))
        dataStore.edit { preferences ->
            val next = listOf(
                AppEvent(System.currentTimeMillis(), kind.take(32), clean),
            ) + decode(preferences[EVENTS].orEmpty())
            preferences[EVENTS] = encode(next.take(MAX))
        }
    }

    suspend fun clear() {
        dataStore.edit { it.remove(EVENTS) }
    }

    private fun decode(raw: String): List<AppEvent> {
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val array = JsonConfig.parse(raw) as? JsonArray ?: return emptyList()
            array.mapNotNull { element ->
                val obj = element as? JsonObject ?: return@mapNotNull null
                AppEvent(
                    epochMillis = (obj["t"] as? JsonPrimitive)?.longOrNull ?: return@mapNotNull null,
                    kind = (obj["k"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null,
                    message = (obj["m"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null,
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun encode(items: List<AppEvent>): String =
        JsonConfig.format(
            buildJsonArray {
                items.forEach { item ->
                    add(
                        buildJsonObject {
                            put("t", item.epochMillis)
                            put("k", item.kind)
                            put("m", item.message)
                        },
                    )
                }
            },
        )

    private companion object {
        val EVENTS = stringPreferencesKey("events_json")
        const val MAX = 80
    }
}
