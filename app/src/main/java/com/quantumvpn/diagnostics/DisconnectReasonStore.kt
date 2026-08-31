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

data class DisconnectEvent(
    val epochMillis: Long,
    val reason: String,
)

private val Context.disconnectReasonDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "disconnect_reason",
)

/** Last disconnect reason + short durable history for Settings. */
class DisconnectReasonStore(context: Context) {
    private val dataStore = context.applicationContext.disconnectReasonDataStore

    val lastReason: Flow<String?> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { it[REASON] }

    val history: Flow<List<DisconnectEvent>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { decode(it[HISTORY].orEmpty()) }

    suspend fun set(reason: String) {
        val clean = SecretRedactor.redactInline(reason.take(280))
        dataStore.edit { preferences ->
            preferences[REASON] = clean
            val next = listOf(DisconnectEvent(System.currentTimeMillis(), clean)) +
                decode(preferences[HISTORY].orEmpty())
            preferences[HISTORY] = encode(next.take(MAX))
        }
    }

    suspend fun clear() {
        dataStore.edit {
            it.remove(REASON)
            it.remove(HISTORY)
        }
    }

    private fun decode(raw: String): List<DisconnectEvent> {
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val array = JsonConfig.parse(raw) as? JsonArray ?: return emptyList()
            array.mapNotNull { element ->
                val obj = element as? JsonObject ?: return@mapNotNull null
                DisconnectEvent(
                    epochMillis = (obj["t"] as? JsonPrimitive)?.longOrNull ?: return@mapNotNull null,
                    reason = (obj["r"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null,
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun encode(items: List<DisconnectEvent>): String =
        JsonConfig.format(
            buildJsonArray {
                items.forEach { item ->
                    add(
                        buildJsonObject {
                            put("t", item.epochMillis)
                            put("r", item.reason)
                        },
                    )
                }
            },
        )

    private companion object {
        val REASON = stringPreferencesKey("last_reason")
        val HISTORY = stringPreferencesKey("history_json")
        const val MAX = 20
    }
}
