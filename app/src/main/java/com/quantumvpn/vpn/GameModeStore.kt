package com.quantumvpn.vpn

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import java.io.IOException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

/**
 * Состояние игрового режима (GearUP-подобный fast path).
 *
 * Выбранные игры допускаются в TUN и маршрутизируются runtime-правилом
 * в outbound `direct` — напрямую через сеть Android, минуя VPN-сервер.
 */
data class GameMode(
    val enabled: Boolean = false,
    val packages: Set<String> = emptySet(),
)

private val Context.gameModeDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "game_mode",
)

class GameModeStore(context: Context) {
    private val appContext = context.applicationContext
    private val dataStore = appContext.gameModeDataStore

    val snapshot: Flow<GameMode> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { preferences ->
            GameMode(
                enabled = preferences[ENABLED] ?: false,
                packages = normalizePackageNames(
                    preferences[PACKAGES].orEmpty(),
                    appContext.packageName,
                ),
            )
        }

    suspend fun setEnabled(enabled: Boolean) {
        dataStore.edit { preferences ->
            preferences[ENABLED] = enabled
        }
    }

    suspend fun setGameEnabled(packageName: String, enabled: Boolean) {
        dataStore.edit { preferences ->
            val packages = normalizePackageNames(
                preferences[PACKAGES].orEmpty(),
                appContext.packageName,
            ).toMutableSet()
            val normalized = packageName.trim()
            if (normalized.isNotEmpty() && normalized != appContext.packageName) {
                if (enabled) packages += normalized else packages -= normalized
            }
            preferences[PACKAGES] = packages
        }
    }

    suspend fun replaceGames(packages: Set<String>) {
        dataStore.edit { preferences ->
            preferences[PACKAGES] = normalizePackageNames(
                packages,
                appContext.packageName,
            )
        }
    }

    private companion object {
        val ENABLED = booleanPreferencesKey("game_mode_enabled")
        val PACKAGES = stringSetPreferencesKey("game_mode_packages")
    }
}
