package com.quantumvpn.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.os.SystemClock
import java.net.InetSocketAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

/** Measures server reachability over the active Wi-Fi/mobile network, even while VPN is off. */
object UnderlyingServerPing {
    suspend fun measure(context: Context, items: List<RuntimeOutboundItem>): Map<String, Int> =
        withContext(Dispatchers.IO) {
            val network = context.getSystemService(ConnectivityManager::class.java).activeNetwork
                ?: return@withContext emptyMap()
            val probe = IcmpPingProbe()
            buildMap {
                items.distinctBy(RuntimeOutboundItem::tag).take(MAX_SERVERS).chunked(PARALLEL_PROBES).forEach { batch ->
                    coroutineScope {
                        batch.map { item -> async {
                    val target = parseEndpoint(item.endpoint) ?: return@async item.tag to null
                    val elapsed = runCatching {
                        probe.measure(network, ServerPingTarget(item.tag, target.first)).toInt()
                    }.getOrElse {
                        runCatching {
                            val started = SystemClock.elapsedRealtime()
                            network.socketFactory.createSocket().use { socket ->
                                socket.connect(InetSocketAddress(target.first, target.second), TCP_TIMEOUT_MS)
                            }
                            (SystemClock.elapsedRealtime() - started).toInt().coerceAtLeast(1)
                        }.getOrNull()
                    }
                            item.tag to elapsed
                        } }.awaitAll()
                    }.forEach { (tag, elapsed) -> if (elapsed != null) put(tag, elapsed) }
                }
            }
        }

    internal fun parseEndpoint(value: String?): Pair<String, Int>? {
        val raw = value?.trim().orEmpty()
        if (raw.isBlank()) return null
        if (raw.startsWith("[")) {
            val end = raw.indexOf(']')
            if (end <= 1) return null
            return raw.substring(1, end) to raw.substring(end + 1).removePrefix(":").toIntOrNull().orDefaultPort()
        }
        val lastColon = raw.lastIndexOf(':')
        if (lastColon <= 0 || raw.indexOf(':') != lastColon) return raw to DEFAULT_PORT
        return raw.substring(0, lastColon) to raw.substring(lastColon + 1).toIntOrNull().orDefaultPort()
    }

    private fun Int?.orDefaultPort(): Int = this?.takeIf { it in 1..65535 } ?: DEFAULT_PORT

    private const val DEFAULT_PORT = 443
    private const val TCP_TIMEOUT_MS = 1_200
    private const val MAX_SERVERS = 24
    private const val PARALLEL_PROBES = 6
}
