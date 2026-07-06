package com.quantumvpn.utils

import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object PingUtils {

    suspend fun tcpPing(host: String, port: Int, timeout: Int = 5000): Long {
        return withContext(Dispatchers.IO) {
            try {
                val startTime = System.currentTimeMillis()
                val socket = Socket()
                socket.connect(InetSocketAddress(host, port), timeout)
                val latency = System.currentTimeMillis() - startTime
                socket.close()
                latency
            } catch (e: Exception) {
                -1L
            }
        }
    }

    suspend fun httpPing(url: String, timeout: Int = 5000): Long {
        return withContext(Dispatchers.IO) {
            try {
                val startTime = System.currentTimeMillis()
                val connection = java.net.URL(url).openConnection()
                connection.connectTimeout = timeout
                connection.readTimeout = timeout
                connection.connect()
                val latency = System.currentTimeMillis() - startTime
                latency
            } catch (e: Exception) {
                -1L
            }
        }
    }

    fun formatPing(ping: Long): String {
        return when {
            ping < 0 -> "Timeout"
            ping < 100 -> "${ping}ms (Excellent)"
            ping < 200 -> "${ping}ms (Good)"
            ping < 500 -> "${ping}ms (Fair)"
            else -> "${ping}ms (Poor)"
        }
    }
}
