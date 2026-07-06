package com.quantumvpn.service

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.quantumvpn.MainActivity
import com.quantumvpn.QuantumVPNApp
import com.quantumvpn.R
import com.quantumvpn.core.VPNCore
import kotlinx.coroutines.*

class VPNService : VpnService() {
    companion object {
        private const val TAG = "VPNService"
        private const val NOTIFICATION_ID = 1
        private const val ACTION_START = "com.quantumvpn.START"
        private const val ACTION_STOP = "com.quantumvpn.STOP"

        var isRunning = false
            private set
    }

    private val binder = LocalBinder()
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    inner class LocalBinder : Binder() {
        fun getService(): VPNService = this@VPNService
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                scope.launch { stopVpn() }
                return START_NOT_STICKY
            }
            ACTION_START -> {
                scope.launch { startVpn() }
            }
        }
        return START_STICKY
    }

    private suspend fun startVpn() {
        try {
            startForeground(NOTIFICATION_ID, createNotification("Connecting..."))

            VPNCore.setVpnService(this)

            val builder = Builder()
            val tunFd = VPNCore.establishVPN(builder)

            if (tunFd != null) {
                VPNCore.startPacketForwarding(tunFd)
                isRunning = true
                updateNotification("Connected")
                Log.d(TAG, "VPN connected")
            } else {
                updateNotification("Connection failed")
                stopSelf()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN", e)
            updateNotification("Error: ${e.message}")
            stopSelf()
        }
    }

    private suspend fun stopVpn() {
        try {
            updateNotification("Disconnecting...")
            VPNCore.stop()
            isRunning = false
            updateNotification("Disconnected")
            delay(500)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            Log.d(TAG, "VPN disconnected")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop VPN", e)
        }
    }

    private fun createNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, VPNService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, QuantumVPNApp.NOTIFICATION_CHANNEL_ID)
            .setContentTitle("QuantumVPN")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(pendingIntent)
            .addAction(R.drawable.ic_stop, "Disconnect", stopIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val notificationManager = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
        notificationManager.notify(NOTIFICATION_ID, createNotification(text))
    }

    override fun onDestroy() {
        scope.cancel()
        VPNCore.stop()
        isRunning = false
        super.onDestroy()
    }
}
