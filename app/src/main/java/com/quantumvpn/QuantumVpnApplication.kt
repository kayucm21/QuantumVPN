package com.quantumvpn

import android.app.Application
import com.quantumvpn.diagnostics.AppCrashStore
import com.quantumvpn.policy.ClientFeatureGate
import com.quantumvpn.vpn.VpnScheduleAlarms
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import com.quantumvpn.updates.UpdateState
import kotlinx.coroutines.flow.collectLatest
import com.quantumvpn.vpn.VpnConnectionState

class QuantumVpnApplication : Application() {
    private val crashStore: AppCrashStore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        AppCrashStore(File(noBackupFilesDir, "diagnostics"))
    }

    val container: AppContainer by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        AppContainer(applicationContext, crashStore)
    }

    override fun onCreate() {
        super.onCreate()
        crashStore.install()
        ClientFeatureGate.provider = { container.clientPolicyRepository.policy.value.features }
        container.wifiAutoConnect.start()
        container.vpnSchedule.start()
        container.clientPolicyRepository.start()
        container.updateController.checkOnce(
            com.quantumvpn.updates.UpdateChannel.Stable,
            autoDownload = true,
        )
        VpnScheduleAlarms.reschedule(this)
        com.quantumvpn.vpn.SubscriptionRefreshAlarms.reschedule(this)
        CoroutineScope(Dispatchers.IO).launch {
            container.profileStore.initialize()
            val names = container.profileStore.profiles.value.associate { it.id to it.name }
            com.quantumvpn.vpn.SubscriptionExpiryNotifier.checkAndNotify(
                this@QuantumVpnApplication,
                container.subscriptionQuotaStore,
                names,
            )
        }
        CoroutineScope(Dispatchers.IO).launch {
            container.updateController.state.collectLatest { state ->
                if (state is UpdateState.Available) {
                    val prefs = getSharedPreferences("update_notifications", MODE_PRIVATE)
                    val version = state.candidate.metadata.versionName
                    if (prefs.getString("last_version", "") != version) {
                        container.notificationManager.showUpdateAvailableNotification(version)
                        prefs.edit().putString("last_version", version).apply()
                    }
                }
            }
        }
        CoroutineScope(Dispatchers.IO).launch {
            val prefs = getSharedPreferences("service_notifications", MODE_PRIVATE)
            container.clientPolicyRepository.policy.collectLatest { policy ->
                val known = prefs.contains("maintenance")
                val previous = prefs.getBoolean("maintenance", false)
                if (policy.maintenance) {
                    when (container.vpnController.state.value) {
                        is VpnConnectionState.Connected,
                        is VpnConnectionState.Starting -> container.vpnController.stop()
                        else -> Unit
                    }
                }
                if (policy.maintenance && (!known || !previous)) {
                    container.notificationManager.showMaintenanceNotification(policy.maintenanceMessage)
                } else if (known && previous && !policy.maintenance) {
                    container.notificationManager.showServiceRestoredNotification()
                }
                prefs.edit().putBoolean("maintenance", policy.maintenance).apply()
            }
        }
    }
}
