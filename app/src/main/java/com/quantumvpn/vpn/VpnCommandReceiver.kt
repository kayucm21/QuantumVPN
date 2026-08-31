package com.quantumvpn.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.widget.Toast
import com.quantumvpn.QuantumVpnApplication
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking

/**
 * Same-app Intent API for connect / disconnect / status (not exported).
 */
class VpnCommandReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        val app = context.applicationContext as? QuantumVpnApplication ?: return
        val container = app.container
        when (action) {
            VpnIntentActions.ACTION_CONNECT -> {
                val profileId = intent.getStringExtra(VpnIntentActions.EXTRA_PROFILE_ID)
                    ?: runBlocking { container.uiSettingsStore.settings.first().activeProfileId }
                if (profileId.isNullOrBlank()) {
                    Toast.makeText(context, "QuantumVPN: нет активного профиля", Toast.LENGTH_SHORT).show()
                    return
                }
                container.vpnController.start(profileId)
                Toast.makeText(context, "QuantumVPN: подключение…", Toast.LENGTH_SHORT).show()
            }
            VpnIntentActions.ACTION_DISCONNECT -> {
                container.vpnController.stop()
                Toast.makeText(context, "QuantumVPN: отключение…", Toast.LENGTH_SHORT).show()
            }
            VpnIntentActions.ACTION_STATUS -> {
                val state = container.vpnController.state.value
                Toast.makeText(context, "QuantumVPN: $state", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
