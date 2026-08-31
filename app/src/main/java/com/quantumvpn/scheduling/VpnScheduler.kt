package com.quantumvpn.scheduling

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject
import java.time.LocalTime

/**
 * Расписание автоматического включения/отключения VPN
 */
data class VpnSchedule(
    val isEnabled: Boolean = false,
    val startHour: Int = 8,
    val startMinute: Int = 0,
    val endHour: Int = 22,
    val endMinute: Int = 0,
    val daysOfWeek: Set<Int> = setOf(1, 2, 3, 4, 5, 6, 7),
    val profileId: String = "",
)

class VpnScheduler(
    private val context: Context,
    private val dataStore: DataStore<Preferences>,
) {
    companion object {
        private val SCHEDULE_KEY = stringPreferencesKey("vpn_schedule")
        private val SCHEDULE_ENABLED_KEY = booleanPreferencesKey("schedule_enabled")

        private fun encode(schedule: VpnSchedule): String = JSONObject().apply {
            put("isEnabled", schedule.isEnabled)
            put("startHour", schedule.startHour)
            put("startMinute", schedule.startMinute)
            put("endHour", schedule.endHour)
            put("endMinute", schedule.endMinute)
            put("daysOfWeek", JSONArray(schedule.daysOfWeek.toList()))
            put("profileId", schedule.profileId)
        }.toString()

        private fun decode(raw: String): VpnSchedule {
            if (raw.isBlank() || raw == "{}") return VpnSchedule()
            val o = JSONObject(raw)
            val days = buildSet {
                val arr = o.optJSONArray("daysOfWeek") ?: return@buildSet
                for (i in 0 until arr.length()) add(arr.optInt(i))
            }.ifEmpty { setOf(1, 2, 3, 4, 5, 6, 7) }
            return VpnSchedule(
                isEnabled = o.optBoolean("isEnabled", false),
                startHour = o.optInt("startHour", 8),
                startMinute = o.optInt("startMinute", 0),
                endHour = o.optInt("endHour", 22),
                endMinute = o.optInt("endMinute", 0),
                daysOfWeek = days,
                profileId = o.optString("profileId", ""),
            )
        }
    }

    fun getSchedule(): Flow<VpnSchedule> = dataStore.data.map { prefs ->
        runCatching { decode(prefs[SCHEDULE_KEY].orEmpty()) }.getOrDefault(VpnSchedule())
    }

    suspend fun setSchedule(schedule: VpnSchedule) {
        dataStore.edit { prefs ->
            prefs[SCHEDULE_KEY] = encode(schedule)
            prefs[SCHEDULE_ENABLED_KEY] = schedule.isEnabled
        }
    }

    fun isScheduleEnabled(): Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[SCHEDULE_ENABLED_KEY] ?: false
    }

    suspend fun shouldVpnBeActive(): Boolean {
        val schedule = getSchedule().first()
        if (!schedule.isEnabled) return false

        val now = LocalTime.now()
        val currentDayOfWeek = java.time.LocalDate.now().dayOfWeek.value
        if (currentDayOfWeek !in schedule.daysOfWeek) return false

        val startTime = LocalTime.of(schedule.startHour, schedule.startMinute)
        val endTime = LocalTime.of(schedule.endHour, schedule.endMinute)
        return if (startTime < endTime) {
            now >= startTime && now < endTime
        } else {
            now >= startTime || now < endTime
        }
    }

    fun getNextScheduleEvent(): Flow<Long> = dataStore.data.map { prefs ->
        val schedule = runCatching { decode(prefs[SCHEDULE_KEY].orEmpty()) }.getOrDefault(VpnSchedule())
        if (!schedule.isEnabled) return@map Long.MAX_VALUE

        val now = java.time.LocalDateTime.now()
        val todayStart = now.withHour(schedule.startHour).withMinute(schedule.startMinute).withSecond(0)
        val todayEnd = now.withHour(schedule.endHour).withMinute(schedule.endMinute).withSecond(0)
        val nextEvent = when {
            now < todayStart -> todayStart
            now < todayEnd -> todayEnd
            else -> todayStart.plusDays(1)
        }
        nextEvent.toInstant(java.time.ZoneOffset.UTC).toEpochMilli()
    }
}
