package com.quantumvpn.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            val prefs = context.getSharedPreferences("vpn_prefs", Context.MODE_PRIVATE)
            val autoConnect = prefs.getBoolean("auto_connect", false)
            if (autoConnect) {
                val serviceIntent = Intent(context, VPNService::class.java).apply {
                    action = "com.quantumvpn.START"
                }
                context.startForegroundService(serviceIntent)
            }
        }
    }
}
