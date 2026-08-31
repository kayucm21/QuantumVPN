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

data class SessionTrafficRecord(
    val epochMillis: Long,
    val profileName: String,
    val downloadBytes: Long,
    val uploadBytes: Long,
    val durationSec: Long,
)

private val Context.sessionTrafficDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "session_traffic_history",
)

class SessionTrafficHistoryStore(context: Context) {
    private val dataStore = context.applicationContext.sessionTrafficDataStore

    val records: Flow<List<SessionTrafficRecord>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { decode(it[RECORDS].orEmpty()) }

    suspend fun record(
        profileName: String,
        downloadBytes: Long,
        uploadBytes: Long,
        durationSec: Long,
    ) {
        if (downloadBytes + uploadBytes < 64_000L && durationSec < 30L) return
        dataStore.edit { preferences ->
            val next = listOf(
                SessionTrafficRecord(
                    epochMillis = System.currentTimeMillis(),
                    profileName = profileName.take(64),
                    downloadBytes = downloadBytes.coerceAtLeast(0),
                    uploadBytes = uploadBytes.coerceAtLeast(0),
                    durationSec = durationSec.coerceAtLeast(0),
                ),
            ) + decode(preferences[RECORDS].orEmpty())
            preferences[RECORDS] = encode(next.take(MAX))
        }
    }

    suspend fun clear() {
        dataStore.edit { it.remove(RECORDS) }
    }

    private fun decode(raw: String): List<SessionTrafficRecord> {
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val array = JsonConfig.parse(raw) as? JsonArray ?: return emptyList()
            array.mapNotNull { element ->
                val obj = element as? JsonObject ?: return@mapNotNull null
                SessionTrafficRecord(
                    epochMillis = (obj["t"] as? JsonPrimitive)?.longOrNull ?: return@mapNotNull null,
                    profileName = (obj["n"] as? JsonPrimitive)?.contentOrNull ?: "?",
                    downloadBytes = (obj["d"] as? JsonPrimitive)?.longOrNull ?: 0L,
                    uploadBytes = (obj["u"] as? JsonPrimitive)?.longOrNull ?: 0L,
                    durationSec = (obj["s"] as? JsonPrimitive)?.longOrNull ?: 0L,
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun encode(items: List<SessionTrafficRecord>): String =
        JsonConfig.format(
            buildJsonArray {
                items.forEach { item ->
                    add(
                        buildJsonObject {
                            put("t", item.epochMillis)
                            put("n", item.profileName)
                            put("d", item.downloadBytes)
                            put("u", item.uploadBytes)
                            put("s", item.durationSec)
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
