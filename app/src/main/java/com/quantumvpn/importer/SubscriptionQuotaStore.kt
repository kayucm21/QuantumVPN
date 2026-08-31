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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

private val Context.subscriptionQuotaDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "subscription_quota",
)

class SubscriptionQuotaStore(context: Context) {
    private val dataStore = context.applicationContext.subscriptionQuotaDataStore

    val byProfileId: Flow<Map<String, SubscriptionUserInfo>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { preferences ->
            preferences.asMap().mapNotNull { (key, value) ->
                val raw = value as? String ?: return@mapNotNull null
                val info = decode(raw) ?: return@mapNotNull null
                key.name to info
            }.toMap()
        }

    suspend fun put(profileId: String, info: SubscriptionUserInfo) {
        dataStore.edit { it[stringPreferencesKey(profileId)] = encode(info) }
    }

    suspend fun remove(profileId: String) {
        dataStore.edit { it.remove(stringPreferencesKey(profileId)) }
    }

    suspend fun retain(ids: Set<String>) {
        dataStore.edit { preferences ->
            preferences.asMap().keys
                .filter { it.name !in ids }
                .forEach { key -> preferences.remove(key) }
        }
    }

    private fun encode(info: SubscriptionUserInfo): String =
        JsonConfig.format(
            buildJsonObject {
                info.uploadBytes?.let { put("u", it) }
                info.downloadBytes?.let { put("d", it) }
                info.totalBytes?.let { put("t", it) }
                info.expireEpochSeconds?.let { put("e", it) }
            },
        )

    private fun decode(raw: String): SubscriptionUserInfo? = runCatching {
        val obj = JsonConfig.parse(raw) as? JsonObject ?: return null
        SubscriptionUserInfo(
            uploadBytes = (obj["u"] as? JsonPrimitive)?.longOrNull,
            downloadBytes = (obj["d"] as? JsonPrimitive)?.longOrNull,
            totalBytes = (obj["t"] as? JsonPrimitive)?.longOrNull,
            expireEpochSeconds = (obj["e"] as? JsonPrimitive)?.longOrNull,
        )
    }.getOrNull()
}
