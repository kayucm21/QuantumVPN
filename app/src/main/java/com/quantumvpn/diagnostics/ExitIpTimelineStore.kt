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

data class ExitIpEvent(
    val epochMillis: Long,
    val ip: String,
    val note: String,
)

private val Context.exitIpTimelineStore: DataStore<Preferences> by preferencesDataStore(
    name = "exit_ip_timeline",
)

class ExitIpTimelineStore(context: Context) {
    private val dataStore = context.applicationContext.exitIpTimelineStore

    val events: Flow<List<ExitIpEvent>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { decode(it[RECORDS].orEmpty()) }

    suspend fun append(ip: String, note: String) {
        val cleanIp = ip.trim()
        if (cleanIp.isBlank()) return
        dataStore.edit { preferences ->
            val prev = decode(preferences[RECORDS].orEmpty())
            if (prev.firstOrNull()?.ip == cleanIp) return@edit
            val next = listOf(
                ExitIpEvent(
                    epochMillis = System.currentTimeMillis(),
                    ip = SecretRedactor.redactInline(cleanIp.take(64)),
                    note = SecretRedactor.redactInline(note.take(80)),
                ),
            ) + prev
            preferences[RECORDS] = encode(next.take(MAX))
        }
    }

    suspend fun clear() {
        dataStore.edit { it.remove(RECORDS) }
    }

    private fun decode(raw: String): List<ExitIpEvent> {
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val array = JsonConfig.parse(raw) as? JsonArray ?: return emptyList()
            array.mapNotNull { el ->
                val obj = el as? JsonObject ?: return@mapNotNull null
                ExitIpEvent(
                    epochMillis = (obj["t"] as? JsonPrimitive)?.longOrNull ?: return@mapNotNull null,
                    ip = (obj["ip"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null,
                    note = (obj["n"] as? JsonPrimitive)?.contentOrNull.orEmpty(),
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun encode(items: List<ExitIpEvent>): String =
        JsonConfig.format(
            buildJsonArray {
                items.forEach { item ->
                    add(
                        buildJsonObject {
                            put("t", item.epochMillis)
                            put("ip", item.ip)
                            put("n", item.note)
                        },
                    )
                }
            },
        )

    private companion object {
        val RECORDS = stringPreferencesKey("events_json")
        const val MAX = 40
    }
}
