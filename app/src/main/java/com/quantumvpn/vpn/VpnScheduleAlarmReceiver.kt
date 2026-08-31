package com.quantumvpn.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.quantumvpn.QuantumVpnApplication
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking

class VpnScheduleAlarmReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        val app = context.applicationContext as? QuantumVpnApplication ?: return
        val container = app.container
        runBlocking {
            val settings = container.uiSettingsStore.settings.first()
            if (settings.snoozeReconnectUntilEpochMillis > System.currentTimeMillis()) return@runBlocking
            when (action) {
                ACTION_NIGHT_CONNECT -> {
                    if (!settings.scheduleNightAutoConnect) return@runBlocking
                    val vpn = container.vpnController.state.value
                    if (vpn is VpnConnectionState.Connected || vpn is VpnConnectionState.Starting) return@runBlocking
                    val profileId = settings.activeProfileId ?: return@runBlocking
                    container.eventJournalStore.append("schedule", "Night alarm connect")
                    container.vpnController.start(profileId)
                }
                ACTION_MORNING_DISCONNECT -> {
                    if (!settings.scheduleMorningDisconnect) return@runBlocking
                    val vpn = container.vpnController.state.value
                    if (vpn !is VpnConnectionState.Connected && vpn !is VpnConnectionState.Starting) return@runBlocking
                    container.eventJournalStore.append("schedule", "Morning alarm disconnect")
                    container.vpnController.stop()
                }
                ACTION_WORK_CONNECT -> {
                    if (!settings.scheduleWorkConnect) return@runBlocking
                    val day = java.util.Calendar.getInstance().get(java.util.Calendar.DAY_OF_WEEK)
                    if (day == java.util.Calendar.SATURDAY || day == java.util.Calendar.SUNDAY) return@runBlocking
                    val vpn = container.vpnController.state.value
                    if (vpn is VpnConnectionState.Connected || vpn is VpnConnectionState.Starting) return@runBlocking
                    val profileId = settings.activeProfileId ?: return@runBlocking
                    container.eventJournalStore.append("schedule", "Work alarm connect")
                    container.vpnController.start(profileId)
                }
            }
        }
        VpnScheduleAlarms.reschedule(context.applicationContext)
    }

    companion object {
        const val ACTION_NIGHT_CONNECT = "com.quantumvpn.schedule.NIGHT_CONNECT"
        const val ACTION_MORNING_DISCONNECT = "com.quantumvpn.schedule.MORNING_DISCONNECT"
        const val ACTION_WORK_CONNECT = "com.quantumvpn.schedule.WORK_CONNECT"
    }
}
