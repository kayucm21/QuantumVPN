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
        var isRunning = false; private set
    }

    private val binder = LocalBinder()
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var trafficJob: Job? = null

    inner class LocalBinder : Binder() {
        fun getService(): VPNService = this@VPNService
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { scope.launch { stopVpn() }; return START_NOT_STICKY }
            ACTION_START -> { scope.launch { startVpn() } }
        }
        return START_STICKY
    }

    private suspend fun startVpn() {
        try {
            startForeground(NOTIFICATION_ID, createNotification("Подключение..."))
            VPNCore.setVpnService(this)
            val builder = Builder()
            val fd = VPNCore.establishVPN(builder)
            if (fd != null) {
                val server = com.quantumvpn.data.CurrentServer.get()
                if (server != null) {
                    VPNCore.startForwarding(fd, server)
                }
                isRunning = true
                startTrafficUpdates()
                updateNotification("Подключено")
            } else {
                updateNotification("Ошибка")
                stopSelf()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Start failed", e)
            updateNotification("Ошибка: ${e.message}")
            stopSelf()
        }
    }

    private fun startTrafficUpdates() {
        trafficJob = scope.launch {
            while (isActive) {
                delay(1000)
                if (isRunning) updateNotification("Подключено")
            }
        }
    }

    private suspend fun stopVpn() {
        try {
            trafficJob?.cancel()
            updateNotification("Отключение...")
            VPNCore.stop()
            isRunning = false
            delay(300)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        } catch (e: Exception) { Log.e(TAG, "Stop failed", e) }
    }

    private fun createNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stopIntent = PendingIntent.getService(this, 1,
            Intent(this, VPNService::class.java).apply { action = ACTION_STOP }, PendingIntent.FLAG_IMMUTABLE)

        val dl = VPNCore.totalDownload
        val ul = VPNCore.totalUpload
        val traffic = "↓ ${formatBytes(dl)}  ↑ ${formatBytes(ul)}"

        val bigText = "Статус: $text\nТрафик: $traffic"

        return NotificationCompat.Builder(this, QuantumVPNApp.NOTIFICATION_CHANNEL_ID)
            .setContentTitle("QuantumVPN — $text")
            .setContentText(traffic)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(pi)
            .addAction(R.drawable.ic_stop, "Отключить", stopIntent)
            .setOngoing(true)
            .setStyle(NotificationCompat.BigTextStyle().bigText(bigText))
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
        nm.notify(NOTIFICATION_ID, createNotification(text))
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1024 -> "${bytes}B"
        bytes < 1048576 -> "${bytes / 1024}KB"
        bytes < 1073741824 -> "${"%.1f".format(bytes / 1048576.0)}MB"
        else -> "${"%.2f".format(bytes / 1073741824.0)}GB"
    }

    override fun onDestroy() {
        scope.cancel()
        VPNCore.stop()
        isRunning = false
        super.onDestroy()
    }
}
