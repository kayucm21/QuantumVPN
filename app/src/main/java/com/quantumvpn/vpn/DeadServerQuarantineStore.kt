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
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

data class QuarantineEntry(
    val failCount: Int = 0,
    val quarantineUntilEpochMillis: Long = 0L,
)

class DeadServerQuarantineStore(context: Context) {
    private val dataStore = context.applicationContext.deadServerQuarantineDataStore

    val entries: Flow<Map<String, QuarantineEntry>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { prefs ->
            prefs.asMap().mapNotNull { (key, value) ->
                val raw = value as? String ?: return@mapNotNull null
                decode(raw)?.let { key.name to it }
            }.toMap()
        }

    suspend fun isQuarantined(key: String): Boolean {
        val now = System.currentTimeMillis()
        val entry = entries.first()[key] ?: return false
        return entry.quarantineUntilEpochMillis > now
    }

    suspend fun recordFailure(key: String) {
        val now = System.currentTimeMillis()
        dataStore.edit { prefs ->
            val current = decode(prefs[stringPreferencesKey(key)]) ?: QuarantineEntry()
            val fails = current.failCount + 1
            val until = if (fails >= FAIL_THRESHOLD) {
                now + QUARANTINE_MS
            } else {
                current.quarantineUntilEpochMillis
            }
            prefs[stringPreferencesKey(key)] = encode(QuarantineEntry(fails, until))
        }
    }

    suspend fun recordSuccess(key: String) {
        dataStore.edit { it.remove(stringPreferencesKey(key)) }
    }

    private fun encode(entry: QuarantineEntry): String = JsonConfig.format(
        buildJsonObject {
            put("f", entry.failCount)
            put("u", entry.quarantineUntilEpochMillis)
        },
    )

    private fun decode(raw: String?): QuarantineEntry? {
        if (raw.isNullOrBlank()) return null
        return runCatching {
            val obj = JsonConfig.parse(raw) as? JsonObject ?: return null
            QuarantineEntry(
                failCount = obj["f"]?.jsonPrimitive?.intOrNull ?: 0,
                quarantineUntilEpochMillis = obj["u"]?.jsonPrimitive?.longOrNull ?: 0L,
            )
        }.getOrNull()
    }

    companion object {
        const val FAIL_THRESHOLD = 3
        const val QUARANTINE_MS = 24 * 60 * 60 * 1000L

        fun serverKey(profileId: String, groupTag: String, outboundTag: String): String =
            "$profileId|$groupTag|$outboundTag"
    }
}

private val Context.deadServerQuarantineDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "dead_server_quarantine",
)
