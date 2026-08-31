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
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.longOrNull

private val Context.connectDurationDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "connect_duration",
)

/** Recent successful connect durations for ETA on Home. */
class ConnectDurationStore(context: Context) {
    private val dataStore = context.applicationContext.connectDurationDataStore

    val samples: Flow<List<Long>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { decode(it[SAMPLES].orEmpty()) }

    suspend fun record(durationMillis: Long) {
        if (durationMillis !in 200L..120_000L) return
        dataStore.edit { preferences ->
            val next = (listOf(durationMillis) + decode(preferences[SAMPLES].orEmpty())).take(MAX)
            preferences[SAMPLES] = encode(next)
        }
    }

    suspend fun medianMillis(): Long? {
        val values = samples.first().sorted()
        if (values.isEmpty()) return null
        return values[values.size / 2]
    }

    private fun decode(raw: String): List<Long> {
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val array = JsonConfig.parse(raw) as? JsonArray ?: return emptyList()
            array.mapNotNull { (it as? JsonPrimitive)?.longOrNull }
        }.getOrDefault(emptyList())
    }

    private fun encode(items: List<Long>): String =
        JsonConfig.format(buildJsonArray { items.forEach { add(JsonPrimitive(it)) } })

    private companion object {
        val SAMPLES = stringPreferencesKey("samples_json")
        const val MAX = 20
    }
}
