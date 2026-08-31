package com.quantumvpn.importer

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.quantumvpn.config.JsonConfig
import java.io.IOException
import java.security.MessageDigest
import kotlinx.coroutines.flow.first
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

class SubscriptionSourceHealthStore(context: Context) {
    private val dataStore = context.applicationContext.subscriptionHealthDataStore

    suspend fun canFetch(url: String): Boolean {
        val key = keyFor(url)
        val now = System.currentTimeMillis()
        val raw = dataStore.data.first()[stringPreferencesKey(key)] ?: return true
        val until = decode(raw)?.quarantineUntil ?: 0L
        return until <= now
    }

    suspend fun backoffMessage(url: String): String? {
        val key = keyFor(url)
        val raw = dataStore.data.first()[stringPreferencesKey(key)] ?: return null
        val entry = decode(raw) ?: return null
        val now = System.currentTimeMillis()
        if (entry.quarantineUntil > now) {
            val mins = ((entry.quarantineUntil - now) / 60_000L).coerceAtLeast(1L)
            return "Источник в карантине ещё ~$mins мин."
        }
        if (entry.backoffUntil > now) {
            val mins = ((entry.backoffUntil - now) / 60_000L).coerceAtLeast(1L)
            return "Подождите ~$mins мин (backoff после 429)."
        }
        return null
    }

    suspend fun record429(url: String) {
        val key = keyFor(url)
        val now = System.currentTimeMillis()
        dataStore.edit { prefs ->
            val prev = decode(prefs[stringPreferencesKey(key)])
            val strikes = (prev?.rateLimitStrikes ?: 0) + 1
            val backoffMs = (60_000L * strikes * strikes).coerceAtMost(6 * 60 * 60_000L)
            prefs[stringPreferencesKey(key)] = encode(
                HealthEntry(
                    rateLimitStrikes = strikes,
                    backoffUntil = now + backoffMs,
                    quarantineUntil = prev?.quarantineUntil ?: 0L,
                ),
            )
        }
    }

    suspend fun recordHardFailure(url: String) {
        val key = keyFor(url)
        val now = System.currentTimeMillis()
        dataStore.edit { prefs ->
            val prev = decode(prefs[stringPreferencesKey(key)])
            val fails = (prev?.hardFails ?: 0) + 1
            val quarantine = if (fails >= 3) now + 24 * 60 * 60_000L else prev?.quarantineUntil ?: 0L
            prefs[stringPreferencesKey(key)] = encode(
                HealthEntry(
                    rateLimitStrikes = prev?.rateLimitStrikes ?: 0,
                    backoffUntil = prev?.backoffUntil ?: 0L,
                    quarantineUntil = quarantine,
                    hardFails = fails,
                ),
            )
        }
    }

    suspend fun recordSuccess(url: String) {
        dataStore.edit { it.remove(stringPreferencesKey(keyFor(url))) }
    }

    private data class HealthEntry(
        val rateLimitStrikes: Int = 0,
        val backoffUntil: Long = 0L,
        val quarantineUntil: Long = 0L,
        val hardFails: Int = 0,
    )

    private fun keyFor(url: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(url.trim().toByteArray())
        return digest.joinToString("") { "%02x".format(it) }.take(24)
    }

    private fun encode(entry: HealthEntry): String = JsonConfig.format(
        buildJsonObject {
            put("rl", entry.rateLimitStrikes)
            put("bo", entry.backoffUntil)
            put("q", entry.quarantineUntil)
            put("hf", entry.hardFails)
        },
    )

    private fun decode(raw: String?): HealthEntry? {
        if (raw.isNullOrBlank()) return null
        return runCatching {
            val obj = JsonConfig.parse(raw) as? JsonObject ?: return null
            HealthEntry(
                rateLimitStrikes = obj["rl"]?.jsonPrimitive?.content?.toIntOrNull() ?: 0,
                backoffUntil = obj["bo"]?.jsonPrimitive?.longOrNull ?: 0L,
                quarantineUntil = obj["q"]?.jsonPrimitive?.longOrNull ?: 0L,
                hardFails = obj["hf"]?.jsonPrimitive?.content?.toIntOrNull() ?: 0,
            )
        }.getOrNull()
    }
}

private val Context.subscriptionHealthDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "subscription_source_health",
)
