package com.quantumvpn.protection

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.edit
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/**
 * DOS-over-HTTPS (DoH) и защита от блокировок операторов
 */
class OperatorBypassProtection(
    private val context: Context,
    private val dataStore: DataStore<Preferences>
) {
    companion object {
        private val DOH_ENABLED_KEY = booleanPreferencesKey("doh_enabled")
        private val DOH_SERVER_KEY = stringPreferencesKey("doh_server")
        private val ANTI_BLOCK_MODE_KEY = stringPreferencesKey("anti_block_mode")
        private val SNI_OBFUSCATION_KEY = booleanPreferencesKey("sni_obfuscation")
        private val ECH_ENABLED_KEY = booleanPreferencesKey("ech_enabled")
    }

    fun isDohEnabled(): Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[DOH_ENABLED_KEY] ?: true
    }

    suspend fun setDohEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[DOH_ENABLED_KEY] = enabled
        }
    }

    fun getDohServer(): Flow<String> = dataStore.data.map { prefs ->
        prefs[DOH_SERVER_KEY] ?: "https://dns.google/dns-query"
    }

    suspend fun setDohServer(server: String) {
        dataStore.edit { prefs ->
            prefs[DOH_SERVER_KEY] = server
        }
    }

    /**
     * Режимы обхода блокировок операторов:
     * AGGRESSIVE - максимальная скрытность
     * BALANCED - баланс скрытности и скорости
     * MINIMAL - минимальный оверхед
     */
    fun getAntiBlockMode(): Flow<String> = dataStore.data.map { prefs ->
        prefs[ANTI_BLOCK_MODE_KEY] ?: "BALANCED"
    }

    suspend fun setAntiBlockMode(mode: String) {
        require(mode in listOf("AGGRESSIVE", "BALANCED", "MINIMAL")) {
            "Неизвестный режим: $mode"
        }
        dataStore.edit { prefs ->
            prefs[ANTI_BLOCK_MODE_KEY] = mode
        }
    }

    fun isSniObfuscationEnabled(): Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[SNI_OBFUSCATION_KEY] ?: true
    }

    suspend fun setSniObfuscationEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[SNI_OBFUSCATION_KEY] = enabled
        }
    }

    fun isEchEnabled(): Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[ECH_ENABLED_KEY] ?: true
    }

    suspend fun setEchEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[ECH_ENABLED_KEY] = enabled
        }
    }

    /**
     * Получает текущие параметры обхода
     */
    suspend fun getBypassConfig(): BypassConfig {
        var doh = true
        var dohServer = "https://dns.google/dns-query"
        var mode = "BALANCED"
        var sniObfuscation = true
        var echEnabled = true

        isDohEnabled().collect { doh = it }
        getDohServer().collect { dohServer = it }
        getAntiBlockMode().collect { mode = it }
        isSniObfuscationEnabled().collect { sniObfuscation = it }
        isEchEnabled().collect { echEnabled = it }

        return BypassConfig(
            dohEnabled = doh,
            dohServer = dohServer,
            antiBlockMode = mode,
            sniObfuscation = sniObfuscation,
            echEnabled = echEnabled
        )
    }

    data class BypassConfig(
        val dohEnabled: Boolean,
        val dohServer: String,
        val antiBlockMode: String,
        val sniObfuscation: Boolean,
        val echEnabled: Boolean
    )
}
