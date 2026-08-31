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
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

data class SettingsAuditEvent(
    val epochMillis: Long,
    val key: String,
    val value: String,
)

private val Context.settingsAuditDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "settings_audit",
)

class SettingsAuditStore(context: Context) {
    private val dataStore = context.applicationContext.settingsAuditDataStore

    val events: Flow<List<SettingsAuditEvent>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { decode(it[EVENTS].orEmpty()) }

    suspend fun append(key: String, value: String) {
        val cleanKey = key.take(48)
        val cleanValue = SecretRedactor.redactInline(value.take(120))
        dataStore.edit { preferences ->
            val next = listOf(
                SettingsAuditEvent(System.currentTimeMillis(), cleanKey, cleanValue),
            ) + decode(preferences[EVENTS].orEmpty())
            preferences[EVENTS] = encode(next.take(MAX))
        }
    }

    suspend fun clear() {
        dataStore.edit { it.remove(EVENTS) }
    }

    private fun decode(raw: String): List<SettingsAuditEvent> {
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val array = JsonConfig.parse(raw) as? JsonArray ?: return emptyList()
            array.mapNotNull { element ->
                val obj = element as? JsonObject ?: return@mapNotNull null
                SettingsAuditEvent(
                    epochMillis = (obj["t"] as? JsonPrimitive)?.longOrNull ?: return@mapNotNull null,
                    key = (obj["k"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null,
                    value = (obj["v"] as? JsonPrimitive)?.contentOrNull ?: "",
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun encode(items: List<SettingsAuditEvent>): String =
        JsonConfig.format(
            buildJsonArray {
                items.forEach { item ->
                    add(
                        buildJsonObject {
                            put("t", item.epochMillis)
                            put("k", item.key)
                            put("v", item.value)
                        },
                    )
                }
            },
        )

    private companion object {
        val EVENTS = stringPreferencesKey("events_json")
        const val MAX = 100
    }
}
