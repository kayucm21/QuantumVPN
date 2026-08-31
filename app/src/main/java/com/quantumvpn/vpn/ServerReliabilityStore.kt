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
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

data class ReliabilityEntry(
    val successes: Int = 0,
    val failures: Int = 0,
) {
    val score: Int
        get() {
            val total = successes + failures
            if (total == 0) return 50
            return ((successes * 100) / total).coerceIn(0, 100)
        }
}

class ServerReliabilityStore(context: Context) {
    private val dataStore = context.applicationContext.serverReliabilityDataStore

    val entries: Flow<Map<String, ReliabilityEntry>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { prefs ->
            prefs.asMap().mapNotNull { (key, value) ->
                decode(value as? String)?.let { key.name to it }
            }.toMap()
        }

    suspend fun recordSuccess(key: String) = record(key, success = true)

    suspend fun recordFailure(key: String) = record(key, success = false)

    suspend fun topKeys(limit: Int = 5): List<Pair<String, Int>> {
        val map = entries.first()
        return map.entries
            .filter { it.value.successes + it.value.failures >= 2 }
            .sortedByDescending { it.value.score }
            .take(limit)
            .map { it.key to it.value.score }
    }

    fun score(key: String, map: Map<String, ReliabilityEntry>): Int =
        map[key]?.score ?: 50

    private suspend fun record(key: String, success: Boolean) {
        dataStore.edit { prefs ->
            val current = decode(prefs[stringPreferencesKey(key)]) ?: ReliabilityEntry()
            val next = if (success) {
                current.copy(successes = current.successes + 1)
            } else {
                current.copy(failures = current.failures + 1)
            }
            prefs[stringPreferencesKey(key)] = encode(next)
        }
    }

    private fun encode(entry: ReliabilityEntry): String = JsonConfig.format(
        buildJsonObject {
            put("s", entry.successes)
            put("f", entry.failures)
        },
    )

    private fun decode(raw: String?): ReliabilityEntry? {
        if (raw.isNullOrBlank()) return null
        return runCatching {
            val obj = JsonConfig.parse(raw) as? JsonObject ?: return null
            ReliabilityEntry(
                successes = obj["s"]?.jsonPrimitive?.intOrNull ?: 0,
                failures = obj["f"]?.jsonPrimitive?.intOrNull ?: 0,
            )
        }.getOrNull()
    }
}

private val Context.serverReliabilityDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "server_reliability",
)
