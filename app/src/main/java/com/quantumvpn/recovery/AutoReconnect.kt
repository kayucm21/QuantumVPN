package com.quantumvpn.recovery

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.edit
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/**
 * Автоматическое переподключение при разрыве соединения
 */
class AutoReconnect(
    private val context: Context,
    private val dataStore: DataStore<Preferences>
) {
    companion object {
        private val AUTO_RECONNECT_ENABLED_KEY = booleanPreferencesKey("auto_reconnect_enabled")
        private val AUTO_RECONNECT_DELAY_KEY = intPreferencesKey("auto_reconnect_delay_seconds")
        private val AUTO_RECONNECT_MAX_ATTEMPTS_KEY = intPreferencesKey("auto_reconnect_max_attempts")
    }

    fun isAutoReconnectEnabled(): Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[AUTO_RECONNECT_ENABLED_KEY] ?: true
    }

    suspend fun setAutoReconnectEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[AUTO_RECONNECT_ENABLED_KEY] = enabled
        }
    }

    fun getAutoReconnectDelay(): Flow<Int> = dataStore.data.map { prefs ->
        prefs[AUTO_RECONNECT_DELAY_KEY] ?: 5 // 5 секунд по умолчанию
    }

    suspend fun setAutoReconnectDelay(seconds: Int) {
        require(seconds in 1..60) { "Задержка должна быть между 1 и 60 секундами" }
        dataStore.edit { prefs ->
            prefs[AUTO_RECONNECT_DELAY_KEY] = seconds
        }
    }

    fun getMaxReconnectAttempts(): Flow<Int> = dataStore.data.map { prefs ->
        prefs[AUTO_RECONNECT_MAX_ATTEMPTS_KEY] ?: 5 // 5 попыток по умолчанию
    }

    suspend fun setMaxReconnectAttempts(attempts: Int) {
        require(attempts in 1..20) { "Количество попыток должно быть между 1 и 20" }
        dataStore.edit { prefs ->
            prefs[AUTO_RECONNECT_MAX_ATTEMPTS_KEY] = attempts
        }
    }

    /**
     * Проверяет, нужно ли переподключаться
     */
    suspend fun shouldReconnect(
        currentAttempt: Int,
        lastError: String?
    ): Pair<Boolean, Long?> {
        val enabled = isAutoReconnectEnabled().map { it }.let {
            var result = false
            it.collect { result = it }
            result
        }

        if (!enabled) return Pair(false, null)

        val maxAttempts = getMaxReconnectAttempts().map { it }.let {
            var result = 5
            it.collect { result = it }
            result
        }

        if (currentAttempt >= maxAttempts) return Pair(false, null)

        val delay = getAutoReconnectDelay().map { it }.let {
            var result = 5
            it.collect { result = it }
            result
        }

        // Экспоненциальная задержка: 5s, 10s, 15s, 20s, 25s
        val exponentialDelay = delay * (currentAttempt + 1)
        val maxDelay = 60L // максимум 60 секунд

        return Pair(true, minOf(exponentialDelay.toLong(), maxDelay) * 1000L)
    }
}
