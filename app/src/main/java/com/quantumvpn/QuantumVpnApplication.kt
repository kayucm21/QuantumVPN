package com.quantumvpn

import android.app.Application
import com.quantumvpn.diagnostics.AppCrashStore
import com.quantumvpn.policy.ClientFeatureGate
import com.quantumvpn.vpn.VpnScheduleAlarms
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

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
        VpnScheduleAlarms.reschedule(this)
        CoroutineScope(Dispatchers.IO).launch {
            container.profileStore.initialize()
            val names = container.profileStore.profiles.value.associate { it.id to it.name }
            com.quantumvpn.vpn.SubscriptionExpiryNotifier.checkAndNotify(
                this@QuantumVpnApplication,
                container.subscriptionQuotaStore,
                names,
            )
        }
    }
}
