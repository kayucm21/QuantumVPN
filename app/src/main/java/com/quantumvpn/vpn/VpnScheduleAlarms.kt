package com.quantumvpn.vpn

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import com.quantumvpn.QuantumVpnApplication
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import java.util.Calendar

object VpnScheduleAlarms {
    fun reschedule(context: Context) {
        val app = context.applicationContext as? QuantumVpnApplication ?: return
        val settings = runBlocking { app.container.uiSettingsStore.settings.first() }
        scheduleNight(context, settings.scheduleNightAutoConnect)
        scheduleMorning(context, settings.scheduleMorningDisconnect)
        scheduleWork(context, settings.scheduleWorkConnect)
    }

    private fun scheduleNight(context: Context, enabled: Boolean) {
        val am = context.getSystemService(AlarmManager::class.java)
        val pi = pending(context, VpnScheduleAlarmReceiver.ACTION_NIGHT_CONNECT, 1)
        am.cancel(pi)
        if (!enabled) return
        am.setInexactRepeating(
            AlarmManager.RTC_WAKEUP,
            nextTime(23, 0),
            AlarmManager.INTERVAL_DAY,
            pi,
        )
    }

    private fun scheduleMorning(context: Context, enabled: Boolean) {
        val am = context.getSystemService(AlarmManager::class.java)
        val pi = pending(context, VpnScheduleAlarmReceiver.ACTION_MORNING_DISCONNECT, 2)
        am.cancel(pi)
        if (!enabled) return
        am.setInexactRepeating(
            AlarmManager.RTC_WAKEUP,
            nextTime(7, 0),
            AlarmManager.INTERVAL_DAY,
            pi,
        )
    }

    private fun scheduleWork(context: Context, enabled: Boolean) {
        val am = context.getSystemService(AlarmManager::class.java)
        val pi = pending(context, VpnScheduleAlarmReceiver.ACTION_WORK_CONNECT, 3)
        am.cancel(pi)
        if (!enabled) return
        am.setInexactRepeating(
            AlarmManager.RTC_WAKEUP,
            nextTime(9, 0),
            AlarmManager.INTERVAL_DAY,
            pi,
        )
    }

    private fun nextTime(hour: Int, minute: Int): Long {
        val cal = Calendar.getInstance().apply {
            set(Calendar.HOUR_OF_DAY, hour)
            set(Calendar.MINUTE, minute)
            set(Calendar.SECOND, 0)
            set(Calendar.MILLISECOND, 0)
            if (timeInMillis <= System.currentTimeMillis()) add(Calendar.DAY_OF_YEAR, 1)
        }
        return cal.timeInMillis
    }

    private fun pending(context: Context, action: String, requestCode: Int): PendingIntent {
        val intent = Intent(context, VpnScheduleAlarmReceiver::class.java).setAction(action)
        return PendingIntent.getBroadcast(
            context,
            requestCode,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }
}
