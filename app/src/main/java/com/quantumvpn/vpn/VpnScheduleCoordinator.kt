package com.quantumvpn.vpn

import android.content.Context
import com.quantumvpn.diagnostics.EventJournalStore
import com.quantumvpn.policy.ClientFeatureGate
import com.quantumvpn.ui.UiSettingsStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.Calendar

/**
 * Lightweight local schedules without exact alarms:
 * - night auto-connect around 23:00
 * - morning disconnect around 07:00
 */
class VpnScheduleCoordinator(
    private val context: Context,
    private val settingsStore: UiSettingsStore,
    private val vpnController: VpnController,
    private val eventJournal: EventJournalStore,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var started = false
    private var lastNightFireDay = -1
    private var lastMorningFireDay = -1

    fun start() {
        if (started) return
        started = true
        VpnScheduleAlarms.reschedule(context.applicationContext)
        scope.launch {
            while (isActive) {
                tick()
                delay(60_000L)
            }
        }
    }

    private suspend fun tick() {
        if (!ClientFeatureGate.features().vpnSchedule) return
        val settings = settingsStore.settings.first()
        if (settings.snoozeReconnectUntilEpochMillis > System.currentTimeMillis()) return
        val cal = Calendar.getInstance()
        val hour = cal.get(Calendar.HOUR_OF_DAY)
        val dayOfYear = cal.get(Calendar.DAY_OF_YEAR)
        val vpn = vpnController.state.value

        if (settings.scheduleNightAutoConnect && hour == 23 && lastNightFireDay != dayOfYear) {
            lastNightFireDay = dayOfYear
            if (ClientFeatureGate.features().vpnConnect &&
                vpn !is VpnConnectionState.Connected && vpn !is VpnConnectionState.Starting
            ) {
                val profileId = settings.activeProfileId
                if (!profileId.isNullOrBlank()) {
                    eventJournal.append("schedule", "Night auto-connect")
                    vpnController.start(profileId)
                }
            }
        }

        if (settings.scheduleMorningDisconnect && hour == 7 && lastMorningFireDay != dayOfYear) {
            lastMorningFireDay = dayOfYear
            if (vpn is VpnConnectionState.Connected || vpn is VpnConnectionState.Starting) {
                eventJournal.append("schedule", "Morning disconnect")
                vpnController.stop()
            }
        }
    }
}
