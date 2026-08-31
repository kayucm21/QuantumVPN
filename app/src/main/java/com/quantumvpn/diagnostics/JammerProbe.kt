package com.quantumvpn.diagnostics

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import com.quantumvpn.hardening.BypassPreset

data class JammerProbeResult(
    val dnsOk: Boolean,
    val httpsOk: Boolean,
    val udpOk: Boolean,
    val httpsLatencyMs: Long?,
    val recommendedPreset: BypassPreset,
    val summary: String,
    val points: List<String>,
)

/**
 * ~15s jammer / DPI smoke suite for cellular and Wi‑Fi.
 * Recommends Soft / Standard / Tele2 / Aggressive without mutating settings.
 */
object JammerProbe {
    suspend fun run(isCellular: Boolean = true): JammerProbeResult = withContext(Dispatchers.IO) {
        withTimeout(15_000) {
            coroutineScope {
                val dns = async { probeDns() }
                val https = async { probeHttps() }
                val udp = async { probeUdp() }
                val dnsOk = dns.await()
                val httpsResult = https.await()
                val udpOk = udp.await()
                val points = mutableListOf<String>()
                points += if (dnsOk) "DNS резолв OK" else "DNS резолв FAIL — похоже на глушение/фильтр"
                points += if (httpsResult != null) {
                    "HTTPS TTFB ${httpsResult} ms"
                } else {
                    "HTTPS FAIL — TLS/DPI блокировка вероятна"
                }
                points += if (udpOk) "UDP echo OK" else "UDP FAIL — Hysteria/QUIC могут не пройти без обхода"
                if (isCellular) points += "Сотовая сеть: рекомендован усиленный обход"

                val preset = when {
                    !dnsOk && httpsResult == null -> BypassPreset.Aggressive
                    !dnsOk || httpsResult == null || !udpOk -> BypassPreset.Tele2
                    (httpsResult ?: 0) > 2_500 -> BypassPreset.Tele2
                    isCellular -> BypassPreset.Tele2
                    else -> BypassPreset.Standard
                }
                val label = when (preset) {
                    BypassPreset.Soft -> "Мягкий"
                    BypassPreset.Standard -> "Стандарт"
                    BypassPreset.Tele2 -> "Оператор"
                    BypassPreset.Aggressive -> "Агрессивный"
                }
                JammerProbeResult(
                    dnsOk = dnsOk,
                    httpsOk = httpsResult != null,
                    udpOk = udpOk,
                    httpsLatencyMs = httpsResult,
                    recommendedPreset = preset,
                    summary = "Тест глушилки: рекомендуем «$label»",
                    points = points,
                )
            }
        }
    }

    fun isCellular(context: Context): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
        val caps = cm.activeNetwork?.let(cm::getNetworkCapabilities) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
    }

    private fun probeDns(): Boolean = runCatching {
        InetAddress.getByName("www.google.com").hostAddress != null
    }.getOrDefault(false)

    private fun probeHttps(): Long? = runCatching {
        val started = System.nanoTime()
        val conn = URL("https://www.gstatic.com/generate_204").openConnection() as HttpsURLConnection
        try {
            conn.connectTimeout = 4_000
            conn.readTimeout = 4_000
            conn.instanceFollowRedirects = false
            conn.useCaches = false
            val code = conn.responseCode
            if (code !in 200..299 && code != 204) return@runCatching null
            (System.nanoTime() - started) / 1_000_000
        } finally {
            conn.disconnect()
        }
    }.getOrNull()

    private fun probeUdp(): Boolean = runCatching {
        DatagramSocket().use { socket ->
            socket.soTimeout = 2_500
            // Cloudflare DNS — small query-like payload; success = any reply or no immediate block.
            val addr = InetSocketAddress("1.1.1.1", 53)
            val payload = byteArrayOf(
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x03, 'w'.code.toByte(), 'w'.code.toByte(), 'w'.code.toByte(),
                0x06, 'g'.code.toByte(), 'o'.code.toByte(), 'o'.code.toByte(),
                'g'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
                0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00,
                0x00, 0x01, 0x00, 0x01,
            )
            socket.send(DatagramPacket(payload, payload.size, addr))
            val buf = ByteArray(512)
            socket.receive(DatagramPacket(buf, buf.size))
            true
        }
    }.getOrDefault(false)
}
