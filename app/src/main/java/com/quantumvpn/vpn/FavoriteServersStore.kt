package com.quantumvpn.vpn

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import java.io.IOException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

private val Context.favoriteServersDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "favorite_servers",
)

/** Keys are "profileId|groupTag|outboundTag". */
class FavoriteServersStore(context: Context) {
    private val dataStore = context.applicationContext.favoriteServersDataStore

    val favorites: Flow<Set<String>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { it[KEYS].orEmpty() }

    suspend fun toggle(profileId: String, groupTag: String, outboundTag: String): Boolean {
        var nowFavorite = false
        dataStore.edit { preferences ->
            val current = preferences[KEYS].orEmpty().toMutableSet()
            val key = key(profileId, groupTag, outboundTag)
            if (key in current) {
                current -= key
                nowFavorite = false
            } else {
                current += key
                nowFavorite = true
            }
            preferences[KEYS] = current
        }
        return nowFavorite
    }

    fun isFavorite(keys: Set<String>, profileId: String, groupTag: String, outboundTag: String): Boolean =
        key(profileId, groupTag, outboundTag) in keys

    companion object {
        fun key(profileId: String, groupTag: String, outboundTag: String): String =
            "$profileId|$groupTag|$outboundTag"

        private val KEYS = stringSetPreferencesKey("favorite_keys")
    }
}
