package com.quantumvpn.vpn

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import java.io.IOException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

private val Context.pinnedServersDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "pinned_servers",
)

/** Up to 3 pinned servers shown at top of Servers list. */
class PinnedServersStore(context: Context) {
    private val dataStore = context.applicationContext.pinnedServersDataStore

    val pins: Flow<List<String>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { prefs ->
            prefs[ORDERED_KEYS].orEmpty()
                .split('\n')
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .take(MAX_PINS)
        }

    suspend fun toggle(profileId: String, groupTag: String, outboundTag: String): Boolean {
        var nowPinned = false
        dataStore.edit { preferences ->
            val current = preferences[ORDERED_KEYS].orEmpty()
                .split('\n')
                .filter { it.isNotBlank() }
                .toMutableList()
            val key = FavoriteServersStore.key(profileId, groupTag, outboundTag)
            if (key in current) {
                current.remove(key)
                nowPinned = false
            } else {
                current.remove(key)
                current.add(0, key)
                while (current.size > MAX_PINS) current.removeAt(current.lastIndex)
                nowPinned = true
            }
            preferences[ORDERED_KEYS] = current.joinToString("\n")
        }
        return nowPinned
    }

    companion object {
        const val MAX_PINS = 3

        private val ORDERED_KEYS = stringPreferencesKey("pinned_ordered")
    }
}
