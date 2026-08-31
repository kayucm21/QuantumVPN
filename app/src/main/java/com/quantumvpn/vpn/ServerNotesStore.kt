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
import kotlinx.coroutines.flow.map
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

private val Context.serverNotesDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "server_notes",
)

/** Local notes keyed by profileId|groupTag|outboundTag. */
class ServerNotesStore(context: Context) {
    private val dataStore = context.applicationContext.serverNotesDataStore

    val notes: Flow<Map<String, String>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { decode(it[NOTES].orEmpty()) }

    suspend fun set(key: String, note: String) {
        val cleanKey = key.take(160)
        if (cleanKey.isBlank()) return
        val cleanNote = note.trim().take(120)
        dataStore.edit { preferences ->
            val map = decode(preferences[NOTES].orEmpty()).toMutableMap()
            if (cleanNote.isBlank()) map.remove(cleanKey) else map[cleanKey] = cleanNote
            preferences[NOTES] = encode(map.toList().take(200).toMap())
        }
    }

    private fun decode(raw: String): Map<String, String> {
        if (raw.isBlank()) return emptyMap()
        return runCatching {
            val obj = JsonConfig.parse(raw) as? JsonObject ?: return emptyMap()
            obj.mapNotNull { (k, v) ->
                (v as? JsonPrimitive)?.contentOrNull?.let { k to it }
            }.toMap()
        }.getOrDefault(emptyMap())
    }

    private fun encode(map: Map<String, String>): String =
        JsonConfig.format(
            buildJsonObject {
                map.forEach { (k, v) -> put(k, v) }
            },
        )

    companion object {
        fun key(profileId: String, groupTag: String, outboundTag: String): String =
            "$profileId|$groupTag|$outboundTag"

        private val NOTES = stringPreferencesKey("notes_json")
    }
}
