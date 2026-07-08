package com.quantumvpn.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.quantumvpn.data.CurrentServer
import com.quantumvpn.data.VPNServer
import java.io.File

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return

        val prefs = context.getSharedPreferences("vpn_prefs", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("auto_connect", false)) return

        try {
            val serversFile = File(context.filesDir, "servers.json")
            val selectedId = prefs.getString("selected_server_id", null)
            if (serversFile.exists() && selectedId != null) {
                val type = object : TypeToken<List<VPNServer>>() {}.type
                val servers = Gson().fromJson<List<VPNServer>>(serversFile.readText(), type)
                servers?.find { it.id == selectedId }?.let { CurrentServer.set(it) }
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
