package com.quantumvpn.diagnostics

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import java.io.IOException
import java.util.Calendar
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

data class ReliabilitySummary(
    val weekLabel: String,
    val connectSuccess: Int,
    val connectFail: Int,
    val disconnects: Int,
    val totalSessionSec: Long,
    val uptimePercent: Int,
) {
    val summaryRu: String
        get() = buildString {
            append("Неделя $weekLabel: ")
            append("успех $connectSuccess")
            if (connectFail > 0) append(", ошибки $connectFail")
            if (disconnects > 0) append(", обрывы $disconnects")
            append(", uptime ~$uptimePercent%")
            if (totalSessionSec > 0) append(", сессии ${totalSessionSec / 3600}ч")
        }
}

private val Context.reliabilityDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "reliability_report",
)

class ReliabilityReportStore(context: Context) {
    private val dataStore = context.applicationContext.reliabilityDataStore

    val summary: Flow<ReliabilitySummary> = dataStore.data
        .catch { error ->
            if (error is IOException) emit(emptyPreferences()) else throw error
        }
        .map { prefs -> prefs.toSummary() }

    suspend fun recordConnectSuccess() = edit { it[SUCCESS] = it[SUCCESS].orZero() + 1 }
    suspend fun recordConnectFail() = edit { it[FAIL] = it[FAIL].orZero() + 1 }
    suspend fun recordDisconnect() = edit { it[DISCONNECT] = it[DISCONNECT].orZero() + 1 }
    suspend fun addSessionSeconds(seconds: Long) {
        if (seconds <= 0) return
        edit { it[SESSION_SEC] = (it[SESSION_SEC] ?: 0L) + seconds }
    }

    private suspend fun edit(mutate: (MutablePreferences) -> Unit) {
        dataStore.edit { prefs ->
            rollWeekIfNeeded(prefs)
            mutate(prefs)
        }
    }

    private fun rollWeekIfNeeded(prefs: MutablePreferences) {
        val week = currentWeekKey()
        if (prefs[WEEK_KEY] == week) return
        prefs[WEEK_KEY] = week
        prefs[SUCCESS] = 0
        prefs[FAIL] = 0
        prefs[DISCONNECT] = 0
        prefs[SESSION_SEC] = 0L
    }

    private fun Preferences.toSummary(): ReliabilitySummary {
        val week = this[WEEK_KEY].orEmpty().ifBlank { currentWeekKey() }
        val success = this[SUCCESS].orZero()
        val fail = this[FAIL].orZero()
        val disc = this[DISCONNECT].orZero()
        val sessionSec = this[SESSION_SEC] ?: 0L
        val attempts = success + fail
        val uptime = if (attempts == 0) 100 else ((success * 100) / attempts)
        return ReliabilitySummary(week, success, fail, disc, sessionSec, uptime)
    }

    private fun Int?.orZero() = this ?: 0

    companion object {
        private val WEEK_KEY = stringPreferencesKey("week")
        private val SUCCESS = intPreferencesKey("success")
        private val FAIL = intPreferencesKey("fail")
        private val DISCONNECT = intPreferencesKey("disconnect")
        private val SESSION_SEC = longPreferencesKey("session_sec")

        fun currentWeekKey(): String {
            val cal = Calendar.getInstance()
            return "${cal.get(Calendar.YEAR)}-W${cal.get(Calendar.WEEK_OF_YEAR)}"
        }
    }
}
