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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

data class NamedAppSet(
    val name: String,
    val packages: Set<String>,
)

private val Context.namedAppSetsDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "named_app_sets",
)

class NamedAppSetsStore(context: Context) {
    private val dataStore = context.applicationContext.namedAppSetsDataStore

    val sets: Flow<List<NamedAppSet>> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { decode(it[SETS].orEmpty()) }

    suspend fun save(name: String, packages: Set<String>) {
        val cleanName = name.trim().take(40).ifBlank { return }
        dataStore.edit { preferences ->
            val next = listOf(NamedAppSet(cleanName, packages)) +
                decode(preferences[SETS].orEmpty()).filterNot { it.name.equals(cleanName, true) }
            preferences[SETS] = encode(next.take(MAX))
        }
    }

    suspend fun delete(name: String) {
        dataStore.edit { preferences ->
            preferences[SETS] = encode(
                decode(preferences[SETS].orEmpty()).filterNot { it.name.equals(name, true) },
            )
        }
    }

    private fun decode(raw: String): List<NamedAppSet> {
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val array = JsonConfig.parse(raw) as? JsonArray ?: return emptyList()
            array.mapNotNull { element ->
                val obj = element as? JsonObject ?: return@mapNotNull null
                val name = (obj["n"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null
                val packages = ((obj["p"] as? JsonArray)?.mapNotNull {
                    (it as? JsonPrimitive)?.contentOrNull
                } ?: emptyList()).toSet()
                NamedAppSet(name, packages)
            }
        }.getOrDefault(emptyList())
    }

    private fun encode(items: List<NamedAppSet>): String =
        JsonConfig.format(
            buildJsonArray {
                items.forEach { item ->
                    add(
                        buildJsonObject {
                            put("n", item.name)
                            put(
                                "p",
                                buildJsonArray {
                                    item.packages.forEach { add(JsonPrimitive(it)) }
                                },
                            )
                        },
                    )
                }
            },
        )

    private companion object {
        val SETS = stringPreferencesKey("sets_json")
        const val MAX = 12
    }
}
