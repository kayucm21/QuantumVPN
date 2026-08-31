package com.quantumvpn.vpn

import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocketFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

data class LiveServerCheckResult(
    val ok: Boolean,
    val latencyMillis: Long,
    val detail: String,
)

/** TCP/TLS reachability check for a server host before connect. */
object LiveServerChecker {
    suspend fun check(host: String?, port: Int?, useTls: Boolean = true): LiveServerCheckResult =
        withContext(Dispatchers.IO) {
            val h = host?.trim().orEmpty()
            val p = port ?: return@withContext LiveServerCheckResult(false, 0, "Нет endpoint")
            if (h.isBlank() || p !in 1..65535) {
                return@withContext LiveServerCheckResult(false, 0, "Некорректный host/port")
            }
            withTimeout(5_000) {
                val started = System.nanoTime()
                runCatching {
                    if (useTls) {
                        val factory = SSLSocketFactory.getDefault()
                        factory.createSocket().use { socket ->
                            socket.connect(InetSocketAddress(h, p), 4_000)
                            socket.soTimeout = 2_000
                        }
                    } else {
                        Socket().use { socket ->
                            socket.connect(InetSocketAddress(h, p), 4_000)
                        }
                    }
                    val ms = (System.nanoTime() - started) / 1_000_000
                    LiveServerCheckResult(true, ms, "OK · ${ms} ms · $h:$p")
                }.getOrElse {
                    LiveServerCheckResult(
                        false,
                        0,
                        "FAIL · $h:$p · ${it.message ?: it.javaClass.simpleName}",
                    )
                }
            }
        }
}
