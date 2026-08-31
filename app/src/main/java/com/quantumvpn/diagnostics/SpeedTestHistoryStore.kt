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

data class SpeedTestRecord(
    val epochMillis: Long,
    val detail: String,
    val ok: Boolean,
)

private val Context.speedTestHistoryDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "speedtest_history",
)

class SpeedTestHistoryStore(context: Context) {
    private val dataStore = context.applicationContext.speedTestHistoryDataStore

    val records: Flow<List<SpeedTestRecord>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { decode(it[RECORDS].orEmpty()) }

    suspend fun add(detail: String, ok: Boolean) {
        dataStore.edit { preferences ->
            val next = listOf(
                SpeedTestRecord(
                    epochMillis = System.currentTimeMillis(),
                    detail = SecretRedactor.redactInline(detail.take(240)),
                    ok = ok,
                ),
            ) + decode(preferences[RECORDS].orEmpty())
            preferences[RECORDS] = encode(next.take(MAX))
        }
    }

    suspend fun clear() {
        dataStore.edit { it.remove(RECORDS) }
    }

    private fun decode(raw: String): List<SpeedTestRecord> {
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val array = JsonConfig.parse(raw) as? JsonArray ?: return emptyList()
            array.mapNotNull { element ->
                val obj = element as? JsonObject ?: return@mapNotNull null
                SpeedTestRecord(
                    epochMillis = (obj["t"] as? JsonPrimitive)?.longOrNull ?: return@mapNotNull null,
                    detail = (obj["d"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null,
                    ok = (obj["ok"] as? JsonPrimitive)?.contentOrNull != "0",
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun encode(items: List<SpeedTestRecord>): String =
        JsonConfig.format(
            buildJsonArray {
                items.forEach { item ->
                    add(
                        buildJsonObject {
                            put("t", item.epochMillis)
                            put("d", item.detail)
                            put("ok", if (item.ok) "1" else "0")
                        },
                    )
                }
            },
        )

    private companion object {
        val RECORDS = stringPreferencesKey("records_json")
        const val MAX = 30
    }
}
