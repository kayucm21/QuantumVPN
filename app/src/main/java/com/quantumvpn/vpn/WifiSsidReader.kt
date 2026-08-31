package com.quantumvpn.vpn

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat

object WifiSsidReader {
    fun currentSsid(context: Context): String? {
        if (!hasPermission(context)) return null
        val wifi = context.applicationContext.getSystemService(WifiManager::class.java) ?: return null
        @Suppress("DEPRECATION")
        val info = wifi.connectionInfo ?: return null
        @Suppress("DEPRECATION")
        val raw = info.ssid ?: return null
        val cleaned = raw.trim().removePrefix("\"").removeSuffix("\"")
        if (cleaned.isBlank() || cleaned == "<unknown ssid>" || cleaned.equals("unknown ssid", true)) {
            return null
        }
        return cleaned
    }

    fun hasPermission(context: Context): Boolean {
        val fine = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_FINE_LOCATION,
        ) == PackageManager.PERMISSION_GRANTED
        val coarse = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_COARSE_LOCATION,
        ) == PackageManager.PERMISSION_GRANTED
        val nearby = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.NEARBY_WIFI_DEVICES,
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            false
        }
        return fine || coarse || nearby
    }
}
