package com.quantumvpn.debug

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.quantumvpn.BuildConfig
import com.quantumvpn.QuantumVpnApplication
import com.quantumvpn.config.DnsMode
import com.quantumvpn.profiles.ProfileSource
import com.quantumvpn.ui.ThemeMode
import com.quantumvpn.updates.UpdateChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/** Debug-only data-preservation probe driven by scripts/verify-same-key-upgrade.sh. */
class Gate7UpgradeProbeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        check(BuildConfig.DEBUG)
        val pending = goAsync()
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            val result = runCatching {
                val container = (context.applicationContext as QuantumVpnApplication).container
                when (intent.action) {
                    ACTION_SEED -> seed(container)
                    ACTION_STATUS -> status(container)
                    else -> error("unknown-action")
                }
            }.getOrElse { error ->
                "error=${error.javaClass.simpleName}:${error.message.orEmpty().replace(';', ',')}"
            }
            pending.resultData = result
            pending.finish()
        }
    }

    private suspend fun seed(container: com.quantumvpn.AppContainer): String {
        container.profileStore.initialize()
        container.profileStore.profiles.value
            .filter { it.name == PROFILE_NAME }
            .forEach { container.profileStore.delete(it.id) }
        val profile = container.profileStore.create(PROFILE_NAME, DIRECT_CONFIG, ProfileSource.RawJson)
        container.uiSettingsStore.setActiveProfile(profile.id)
        container.uiSettingsStore.setThemeMode(ThemeMode.Dark)
        container.uiSettingsStore.setUpdateChannel(UpdateChannel.Beta)
        container.uiSettingsStore.setDnsMode(DnsMode.FromJson)
        container.appSelectionStore.replaceAllowlist(setOf("com.android.settings"))
        return status(container)
    }

    private suspend fun status(container: com.quantumvpn.AppContainer): String {
        container.profileStore.initialize()
        val settings = container.uiSettingsStore.settings.first()
        val profiles = container.profileStore.profiles.value.filter { it.name == PROFILE_NAME }
        val allowed = container.appSelectionStore.selection.first().allowedPackages
        return listOf(
            "version=${BuildConfig.VERSION_CODE}",
            "profiles=${profiles.size}",
            "active=${profiles.singleOrNull()?.id == settings.activeProfileId}",
            "theme=${settings.themeMode.name}",
            "channel=${settings.updateChannel.name}",
            "apps=${allowed.size}",
        ).joinToString(";")
    }

    companion object {
        const val ACTION_SEED = "com.quantumvpn.debug.GATE7_SEED"
        const val ACTION_STATUS = "com.quantumvpn.debug.GATE7_STATUS"
        private const val PROFILE_NAME = "__gate7_upgrade_probe__"
        private const val DIRECT_CONFIG = """
            {
              "inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"auto_route":true}],
              "outbounds":[{"type":"direct","tag":"direct"}],
              "route":{"auto_detect_interface":true,"final":"direct"}
            }
        """
    }
}
