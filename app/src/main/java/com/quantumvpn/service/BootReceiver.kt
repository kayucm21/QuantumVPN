package com.quantumvpn.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import com.quantumvpn.data.CurrentServer
import com.quantumvpn.data.ServerStorage
import kotlinx.coroutines.runBlocking

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return

        val prefs = context.getSharedPreferences("vpn_prefs", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("auto_connect", false)) return

        try {
            val selectedId = prefs.getString("selected_server_id", null)
            if (selectedId != null) {
                val servers = runBlocking { ServerStorage.loadServers(context) }
                servers.find { it.id == selectedId }?.let { CurrentServer.set(it) }
            }
        } catch (_: Exception) {}

        if (CurrentServer.get() == null) return

        val serviceIntent = Intent(context, VPNService::class.java).apply {
            action = "com.quantumvpn.START"
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(serviceIntent)
        } else {
            context.startService(serviceIntent)
        }
    }
}
