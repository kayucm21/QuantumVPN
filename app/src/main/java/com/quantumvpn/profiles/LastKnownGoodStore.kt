package com.quantumvpn.profiles

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

class LastKnownGoodStore(context: Context) {
    private val dataStore = context.applicationContext.lastKnownGoodDataStore

    private val failCounts: Flow<Map<String, Int>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { prefs ->
            prefs.asMap().mapNotNull { (key, value) ->
                if (!key.name.startsWith("fail:")) return@mapNotNull null
                val profileId = key.name.removePrefix("fail:")
                val count = (value as? String)?.toIntOrNull() ?: return@mapNotNull null
                profileId to count
            }.toMap()
        }

    suspend fun pin(profileId: String, json: String) {
        dataStore.edit { prefs ->
            prefs[stringPreferencesKey("json:$profileId")] = json
            prefs.remove(stringPreferencesKey("fail:$profileId"))
        }
    }

    suspend fun snapshot(profileId: String): String? =
        dataStore.data.first()[stringPreferencesKey("json:$profileId")]

    suspend fun recordConnectFail(profileId: String): Int {
        var next = 0
        dataStore.edit { prefs ->
            val key = stringPreferencesKey("fail:$profileId")
            next = ((prefs[key] as? String)?.toIntOrNull() ?: 0) + 1
            prefs[key] = next.toString()
        }
        return next
    }

    suspend fun resetFails(profileId: String) {
        dataStore.edit { it.remove(stringPreferencesKey("fail:$profileId")) }
    }

    suspend fun failCount(profileId: String): Int =
        failCounts.first()[profileId] ?: 0

    companion object {
        const val ROLLBACK_THRESHOLD = 3
    }
}

private val Context.lastKnownGoodDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "last_known_good",
)
