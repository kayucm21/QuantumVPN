package com.quantumvpn.service

import android.app.Notification
import android.app.PendingIntent
import android.content.Intent
import android.net.TrafficStats
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
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
    private var vpnInterface: ParcelFileDescriptor? = null
    private var lastRxBytes = 0L
    private var lastTxBytes = 0L

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

    private fun establishVPN(): ParcelFileDescriptor? {
        return try {
            val builder = Builder()
            builder.setSession("QuantumVPN")
            builder.addAddress("172.19.0.1", 30)
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
            builder.addDnsServer("8.8.8.8")
            builder.addDnsServer("1.1.1.1")
            builder.setMtu(1500)
            // sing-box runs in our process — exclude it from the tunnel to avoid routing loops
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "Could not exclude app from VPN", e)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }
            val fd = builder.establish()
            vpnInterface = fd
            Log.d(TAG, "VPN interface established, fd=${fd?.fd}")
            fd
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN", e)
            null
        }
    }

    private fun sendVpnState(state: String, error: String? = null) {
        sendBroadcast(
            Intent("com.quantumvpn.VPN_STATE").apply {
                setPackage(packageName)
                putExtra("state", state)
                if (error != null) putExtra("error", error)
            }
        )
    }

    private suspend fun startVpn() {
        try {
            startForeground(NOTIFICATION_ID, createNotification("Подключение..."))

            val server = com.quantumvpn.data.CurrentServer.get()
            if (server == null) {
                updateNotification("Ошибка: сервер не выбран")
                sendVpnState("error", "Сервер не выбран")
                stopSelf()
                return
            }

            val vpnFd = establishVPN()
            if (vpnFd == null) {
                updateNotification("Ошибка создания VPN-интерфейса")
                sendVpnState("error", "Не удалось создать VPN-интерфейс")
                stopSelf()
                return
            }

            VPNCore.init(this@VPNService)

            val configPath = com.quantumvpn.core.ConfigGenerator.generate(this@VPNService, server)
            if (configPath == null) {
                updateNotification("Ошибка генерации конфига")
                sendVpnState("error", "Ошибка генерации конфига")
                stopSelf()
                return
            }

            Log.d(TAG, "Starting sing-box with config: $configPath")
            val started = withContext(Dispatchers.IO) {
                VPNCore.start(configPath, this@VPNService, vpnFd.fd)
            }
            if (started) {
                isRunning = true
                lastRxBytes = TrafficStats.getTotalRxBytes()
                lastTxBytes = TrafficStats.getTotalTxBytes()
                startTrafficUpdates()
                updateNotification("Подключено: ${server.name}")
                sendVpnState("connected")
            } else {
                updateNotification("Ошибка запуска ядра")
                sendVpnState("error", "sing-box не запустился. ${VPNCore.getLastError()}")
                stopSelf()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Start failed", e)
            updateNotification("Ошибка: ${e.message}")
            sendVpnState("error", e.message ?: "Ошибка подключения")
            stopSelf()
        }
    }

    private fun startTrafficUpdates() {
        trafficJob = scope.launch {
            while (isActive) {
                delay(1000)
                if (isRunning) {
                    val currentRx = TrafficStats.getTotalRxBytes()
                    val currentTx = TrafficStats.getTotalTxBytes()
                    VPNCore.totalDownload = currentRx - lastRxBytes
                    VPNCore.totalUpload = currentTx - lastTxBytes
                    updateNotification("Подключено  ↓${formatBytes(VPNCore.totalDownload)}  ↑${formatBytes(VPNCore.totalUpload)}")
                }
            }
        }
    }

    private suspend fun stopVpn() {
        try {
            trafficJob?.cancel()
            updateNotification("Отключение...")
            VPNCore.stop()
            try { vpnInterface?.close() } catch (_: Exception) {}
            vpnInterface = null
            isRunning = false
            sendVpnState("disconnected")
            delay(300)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        } catch (e: Exception) { Log.e(TAG, "Stop failed", e) }
    }

    private fun createNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stopIntent = PendingIntent.getService(this, 1,
            Intent(this, VPNService::class.java).apply { action = ACTION_STOP }, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

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
        try { vpnInterface?.close() } catch (_: Exception) {}
        isRunning = false
        super.onDestroy()
    }
}
