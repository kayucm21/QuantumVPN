package com.quantumvpn.vpn

import android.content.Context
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.telephony.TelephonyManager
import android.os.Build
import androidx.core.app.NotificationCompat
import com.quantumvpn.MainActivity
import com.quantumvpn.diagnostics.EventJournalStore
import com.quantumvpn.policy.ClientFeatureGate
import com.quantumvpn.ui.UiSettingsStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
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
    private var lastPublicWifiPrompt: Pair<String, Long>? = null
    private var lastTransport: String? = null
    private var handoffJob: Job? = null

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

                override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                    scope.launch { maybeSuggestProtection(capabilities) }
                }
            },
        )
        // Keep an established session aligned with the active physical network.
        // Android's default-network callback is available from API 24 and does not
        // require location permission. The short debounce avoids restarting twice
        // while Android publishes Wi-Fi/LTE capabilities during a handover.
        runCatching {
            cm.registerDefaultNetworkCallback(
                object : ConnectivityManager.NetworkCallback() {
                    override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                        scope.launch { handleTransportChange(cm, capabilities) }
                    }

                    override fun onLost(network: Network) {
                        scope.launch {
                            delay(350)
                            val active = cm.activeNetwork
                            val capabilities = active?.let { cm.getNetworkCapabilities(it) }
                            if (capabilities != null) handleTransportChange(cm, capabilities)
                        }
                    }
                },
            )
        }
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

    /**
     * Unknown Wi-Fi is never connected automatically while Android is showing a captive
     * portal. Once the network is validated, offer one explicit VPN action to the user.
     */
    private suspend fun maybeSuggestProtection(capabilities: NetworkCapabilities) {
        if (!ClientFeatureGate.features().autoConnect || !ClientFeatureGate.features().vpnConnect) return
        if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)) return
        if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) return
        val settings = settingsStore.settings.first()
        if (!settings.protectUnknownWifi) return
        if (vpnController.state.value is VpnConnectionState.Connected ||
            vpnController.state.value is VpnConnectionState.Starting
        ) return
        val ssid = WifiSsidReader.currentSsid(context) ?: return
        val trusted = settings.trustedWifiSsids
            .split(',', '\n')
            .map(String::trim)
            .filter(String::isNotEmpty)
        if (trusted.any { it.equals(ssid, ignoreCase = true) }) return
        val now = System.currentTimeMillis()
        val last = lastPublicWifiPrompt
        if (last?.first == ssid && now - last.second < PUBLIC_WIFI_PROMPT_COOLDOWN_MS) return
        lastPublicWifiPrompt = ssid to now
        eventJournal.append("wifi", "Предложена защита незнакомой Wi-Fi сети")
        showPublicWifiNotification(ssid)
    }

    private fun showPublicWifiNotification(ssid: String) {
        val manager = context.getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(
                    PUBLIC_WIFI_CHANNEL,
                    "Защита Wi-Fi",
                    NotificationManager.IMPORTANCE_DEFAULT,
                ).apply { description = "Предложения включить VPN в незнакомых Wi-Fi сетях" },
            )
        }
        val open = PendingIntent.getActivity(
            context,
            41,
            Intent(context, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(context, PUBLIC_WIFI_CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Незнакомая Wi-Fi сеть")
            .setContentText("$ssid: откройте QuantumVPN, чтобы защитить соединение")
            .setStyle(NotificationCompat.BigTextStyle().bigText("Сеть $ssid прошла страницу входа и доступна. Нажмите, чтобы включить VPN."))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        manager.notify(PUBLIC_WIFI_NOTIFICATION_ID, notification)
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

    private suspend fun handleTransportChange(
        cm: ConnectivityManager,
        capabilities: NetworkCapabilities,
    ) {
        val transport = when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi‑Fi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "мобильная сеть"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            // The VPN itself can become Android's default network. It is not a
            // physical handoff and must not trigger a restart loop.
            else -> return
        }
        val previous = lastTransport
        lastTransport = transport
        if (previous.isNullOrBlank() || previous == transport) return
        if (!ClientFeatureGate.features().autoFailover) return
        val settings = settingsStore.settings.first()
        if (!settings.autoFailoverEnabled) return
        if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) return
        if (vpnController.state.value !is VpnConnectionState.Connected) return
        handoffJob?.cancel()
        handoffJob = scope.launch {
            delay(900)
            if (vpnController.state.value is VpnConnectionState.Connected) {
                eventJournal.append("network", "Смена сети: $previous → $transport; переподключение")
                vpnController.restartIfConnected("Автопереход $previous → $transport")
            }
        }
    }

    private companion object {
        const val PUBLIC_WIFI_CHANNEL = "vpn_public_wifi"
        const val PUBLIC_WIFI_NOTIFICATION_ID = 1041
        const val PUBLIC_WIFI_PROMPT_COOLDOWN_MS = 12 * 60 * 60 * 1000L
    }
}
