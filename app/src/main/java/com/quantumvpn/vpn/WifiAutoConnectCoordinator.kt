package com.quantumvpn.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.telephony.TelephonyManager
import com.quantumvpn.diagnostics.EventJournalStore
import com.quantumvpn.policy.ClientFeatureGate
import com.quantumvpn.ui.UiSettingsStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Optional auto-start when joining a trusted Wi‑Fi SSID or cellular (if enabled).
 * Requires location/nearby permission to read SSID on modern Android.
 */
class WifiAutoConnectCoordinator(
    private val context: Context,
    private val settingsStore: UiSettingsStore,
    private val vpnController: VpnController,
    private val eventJournal: EventJournalStore,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var registered = false

    fun start() {
        if (registered) return
        registered = true
        val cm = context.getSystemService(ConnectivityManager::class.java)
        cm.registerNetworkCallback(
            NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .build(),
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    scope.launch { maybeAutoconnectWifi() }
                }
            },
        )
        cm.registerNetworkCallback(
            NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                .build(),
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    scope.launch { maybeAutoconnectCellular() }
                }
            },
        )
    }

    private suspend fun shouldSkipForRoaming(settings: com.quantumvpn.ui.UiSettings): Boolean {
        if (!settings.skipAutoConnectWhenRoaming) return false
        val tm = context.getSystemService(TelephonyManager::class.java)
        return runCatching { tm.isNetworkRoaming }.getOrDefault(false)
    }

    private suspend fun maybeAutoconnectWifi() {
        if (!ClientFeatureGate.features().autoConnect || !ClientFeatureGate.features().vpnConnect) return
        val settings = settingsStore.settings.first()
        if (!settings.autoConnectTrustedWifi || settings.autoConnectOnCellular) return
        if (shouldSkipForRoaming(settings)) return
        if (settings.snoozeReconnectUntilEpochMillis > System.currentTimeMillis()) return
        if (vpnController.state.value is VpnConnectionState.Connected ||
            vpnController.state.value is VpnConnectionState.Starting
        ) {
            return
        }
        val profileId = settings.activeProfileId ?: return
        val ssid = WifiSsidReader.currentSsid(context) ?: return
        val trusted = settings.trustedWifiSsids
            .split(',', '\n')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        if (trusted.none { it.equals(ssid, ignoreCase = true) }) return
        eventJournal.append("wifi", "Автоподключение на Wi‑Fi «$ssid»")
        vpnController.start(profileId)
    }

    private suspend fun maybeAutoconnectCellular() {
        if (!ClientFeatureGate.features().autoConnect || !ClientFeatureGate.features().vpnConnect) return
        val settings = settingsStore.settings.first()
        if (!settings.autoConnectOnCellular) return
        if (shouldSkipForRoaming(settings)) return
        if (settings.snoozeReconnectUntilEpochMillis > System.currentTimeMillis()) return
        if (vpnController.state.value is VpnConnectionState.Connected ||
            vpnController.state.value is VpnConnectionState.Starting
        ) {
            return
        }
        val profileId = settings.activeProfileId ?: return
        eventJournal.append("cellular", "Автоподключение на mobile data")
        vpnController.start(profileId)
    }
}
