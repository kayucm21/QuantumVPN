package com.quantumvpn.state

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.edit
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/**
 * Сохранение состояния последнего подключения и автовключение при старте
 */
class LastConnectionState(
    private val context: Context,
    private val dataStore: DataStore<Preferences>
) {
    companion object {
        private val LAST_PROFILE_ID_KEY = stringPreferencesKey("last_profile_id")
        private val LAST_SERVER_TAG_KEY = stringPreferencesKey("last_server_tag")
        private val AUTO_START_ENABLED_KEY = booleanPreferencesKey("auto_start_vpn_enabled")
        private val WAS_VPN_ACTIVE_KEY = booleanPreferencesKey("was_vpn_active")
    }

    fun getLastProfileId(): Flow<String?> = dataStore.data.map { prefs ->
        prefs[LAST_PROFILE_ID_KEY]
    }

    suspend fun saveLastProfileId(profileId: String) {
        dataStore.edit { prefs ->
            prefs[LAST_PROFILE_ID_KEY] = profileId
        }
    }

    fun getLastServerTag(): Flow<String?> = dataStore.data.map { prefs ->
        prefs[LAST_SERVER_TAG_KEY]
    }

    suspend fun saveLastServerTag(serverTag: String) {
        dataStore.edit { prefs ->
            prefs[LAST_SERVER_TAG_KEY] = serverTag
        }
    }

    fun isAutoStartEnabled(): Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[AUTO_START_ENABLED_KEY] ?: false
    }

    suspend fun setAutoStartEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[AUTO_START_ENABLED_KEY] = enabled
        }
    }

    fun wasVpnActive(): Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[WAS_VPN_ACTIVE_KEY] ?: false
    }

    suspend fun setVpnWasActive(wasActive: Boolean) {
        dataStore.edit { prefs ->
            prefs[WAS_VPN_ACTIVE_KEY] = wasActive
        }
    }

    /**
     * Инициирует восстановление последнего подключения при старте
     */
    suspend fun shouldRestoreLastConnection(): Pair<String?, String?> {
        val autoStartEnabled = isAutoStartEnabled().map { it }.let {
            var result = false
            it.collect { result = it }
            result
        }

        if (!autoStartEnabled) return Pair(null, null)

        val profileId = getLastProfileId().map { it }.let {
            var result: String? = null
            it.collect { result = it }
            result
        }

        val serverTag = getLastServerTag().map { it }.let {
            var result: String? = null
            it.collect { result = it }
            result
        }

        return Pair(profileId, serverTag)
    }

    /**
     * Сохраняет текущее состояние для восстановления
     */
    suspend fun saveCurrentState(
        profileId: String,
        serverTag: String,
        isVpnActive: Boolean
    ) {
        saveLastProfileId(profileId)
        saveLastServerTag(serverTag)
        setVpnWasActive(isVpnActive)
    }
}
