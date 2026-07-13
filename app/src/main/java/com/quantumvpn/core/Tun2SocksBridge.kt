package com.quantumvpn.core

import android.content.Context
import android.util.Log
import com.v2ray.ang.service.TProxyService
import java.io.File

object Tun2SocksBridge {
    private const val TAG = "Tun2SocksBridge"
    private var running = false

    fun start(context: Context, tunFd: Int): Boolean {
        return try {
            if (running) stop()
            val configFile = File(context.filesDir, "hev-socks5-tunnel.yaml")
            configFile.writeText(buildConfig())
            Log.d(TAG, "Starting tun2socks, config=${configFile.absolutePath}, fd=$tunFd")
            TProxyService.TProxyStartService(configFile.absolutePath, tunFd)
            running = true
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start tun2socks", e)
            false
        }
    }

    fun stop() {
        if (!running) return
        try {
            TProxyService.TProxyStopService()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop tun2socks", e)
        } finally {
            running = false
        }
    }

    fun isRunning(): Boolean = running

    private fun buildConfig(): String = buildString {
        appendLine("tunnel:")
        appendLine("  mtu: ${VpnConstants.MTU}")
        appendLine("  ipv4: ${VpnConstants.TUN_ADDRESS}")
        appendLine("socks5:")
        appendLine("  port: ${VpnConstants.SOCKS_PORT}")
        appendLine("  address: ${VpnConstants.LOOPBACK}")
        appendLine("  udp: 'udp'")
        appendLine("misc:")
        appendLine("  tcp-read-write-timeout: 300000")
        appendLine("  udp-read-write-timeout: 60000")
        appendLine("  log-level: warn")
    }
}
