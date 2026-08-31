package com.quantumvpn.vpn

import java.io.OutputStream
import java.net.URL
import java.util.concurrent.ThreadLocalRandom
import javax.net.ssl.HttpsURLConnection
import kotlin.math.sqrt
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

data class SpeedTestResult(
    val downloadKbps: Long,
    val uploadKbps: Long = 0,
    val latencyMillis: Long,
    val jitterMillis: Long = 0,
    val ok: Boolean,
    val detail: String,
    /** True when measured while VPN session was Connected. */
    val vpnActive: Boolean = false,
    val downloadMbps: Double = downloadKbps / 1000.0,
    val uploadMbps: Double = uploadKbps / 1000.0,
)

/**
 * Full on-demand speed probe: TTFB, download Mbps, upload Mbps, jitter.
 * Works with VPN on or off — traffic follows the active Android default route.
 */
object SpeedTestProbe {
    suspend fun run(vpnActive: Boolean = false): SpeedTestResult = withContext(Dispatchers.IO) {
        withTimeout(TIMEOUT_MS) {
            val vpnLabel = if (vpnActive) "VPN вкл" else "VPN выкл"
            val latencySamples = mutableListOf<Long>()
            repeat(3) {
                runCatching { probeLatency() }.getOrNull()?.let(latencySamples::add)
            }
            val latency = latencySamples.minOrNull() ?: 0L
            val jitter = if (latencySamples.size >= 2) {
                val mean = latencySamples.average()
                sqrt(latencySamples.map { (it - mean) * (it - mean) }.average()).toLong()
            } else {
                0L
            }
            var lastError: String? = null
            var download: Pair<Long, Long>? = null
            for (url in DOWNLOAD_URLS) {
                download = runCatching { probeDownload(url) }.getOrElse {
                    lastError = it.message ?: it.javaClass.simpleName
                    null
                }
                if (download != null) break
            }
            val uploadKbps = runCatching { probeUpload() }.getOrDefault(0L)
            if (download == null) {
                return@withTimeout SpeedTestResult(
                    downloadKbps = 0,
                    uploadKbps = uploadKbps,
                    latencyMillis = latency,
                    jitterMillis = jitter,
                    ok = false,
                    detail = "$vpnLabel · ошибка: ${lastError ?: "нет ответа"}",
                    vpnActive = vpnActive,
                )
            }
            val (kbps, bytes) = download
            val upPart = if (uploadKbps > 0) " · ↑ ${formatRate(uploadKbps)}" else ""
            val jitPart = if (jitter > 0) " · jitter ${jitter} ms" else ""
            SpeedTestResult(
                downloadKbps = kbps,
                uploadKbps = uploadKbps,
                latencyMillis = latency,
                jitterMillis = jitter,
                ok = bytes > 8_000,
                detail = "$vpnLabel · ↓ ${formatRate(kbps)}$upPart · TTFB ${latency} ms$jitPart",
                vpnActive = vpnActive,
                downloadMbps = kbps / 1000.0,
                uploadMbps = uploadKbps / 1000.0,
            )
        }
    }

    private fun probeLatency(): Long {
        val started = System.nanoTime()
        val connection = URL(LATENCY_URL).openConnection() as HttpsURLConnection
        try {
            connection.connectTimeout = 4_000
            connection.readTimeout = 4_000
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.requestMethod = "HEAD"
            connection.setRequestProperty("User-Agent", "QuantumVPN-SpeedTest/5.4")
            val code = connection.responseCode
            if (code !in 200..399) error("HTTP $code")
            return (System.nanoTime() - started) / 1_000_000
        } finally {
            connection.disconnect()
        }
    }

    private fun probeDownload(url: String): Pair<Long, Long> {
        val started = System.nanoTime()
        val connection = URL(url).openConnection() as HttpsURLConnection
        try {
            connection.connectTimeout = 6_000
            connection.readTimeout = 14_000
            connection.instanceFollowRedirects = true
            connection.useCaches = false
            connection.setRequestProperty("User-Agent", "QuantumVPN-SpeedTest/5.4")
            val code = connection.responseCode
            if (code !in 200..299) error("HTTP $code")
            val bytes = connection.inputStream.use { input ->
                var total = 0L
                val buffer = ByteArray(32 * 1024)
                val deadline = System.nanoTime() + READ_BUDGET_NS
                while (System.nanoTime() < deadline) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    total += read
                    if (total >= MAX_BYTES) break
                }
                total
            }
            val elapsedMs = ((System.nanoTime() - started) / 1_000_000).coerceAtLeast(1)
            val kbps = (bytes * 8L) / elapsedMs
            return kbps to bytes
        } finally {
            connection.disconnect()
        }
    }

    private fun probeUpload(): Long {
        val started = System.nanoTime()
        val connection = URL(UPLOAD_URL).openConnection() as HttpsURLConnection
        try {
            connection.connectTimeout = 6_000
            connection.readTimeout = 10_000
            connection.doOutput = true
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.setRequestProperty("Content-Type", "application/octet-stream")
            connection.setRequestProperty("User-Agent", "QuantumVPN-SpeedTest/5.4")
            connection.setFixedLengthStreamingMode(UPLOAD_BYTES.toInt())
            connection.outputStream.use { out -> writeRandom(out, UPLOAD_BYTES) }
            val code = connection.responseCode
            // Cloudflare may return 200 or 400; count bytes sent either way if connection held.
            if (code !in 200..499) error("HTTP $code")
            val elapsedMs = ((System.nanoTime() - started) / 1_000_000).coerceAtLeast(1)
            return (UPLOAD_BYTES * 8L) / elapsedMs
        } finally {
            connection.disconnect()
        }
    }

    private fun writeRandom(out: OutputStream, size: Long) {
        val buffer = ByteArray(16 * 1024)
        var left = size
        val rnd = ThreadLocalRandom.current()
        while (left > 0) {
            val n = minOf(left, buffer.size.toLong()).toInt()
            rnd.nextBytes(buffer)
            out.write(buffer, 0, n)
            left -= n
        }
        out.flush()
    }

    fun formatRate(kbps: Long): String = when {
        kbps >= 1_000 -> String.format("%.2f Mbps", kbps / 1000.0)
        else -> "$kbps kbps"
    }

    private val DOWNLOAD_URLS = listOf(
        "https://speed.cloudflare.com/__down?bytes=2500000",
        "https://proof.ovh.net/files/1Mb.dat",
        "https://www.gstatic.com/generate_204",
    )
    private const val LATENCY_URL = "https://www.gstatic.com/generate_204"
    private const val UPLOAD_URL = "https://speed.cloudflare.com/__up"
    private const val UPLOAD_BYTES = 512L * 1024L
    private const val MAX_BYTES = 4L * 1024L * 1024L
    private const val TIMEOUT_MS = 28_000L
    private const val READ_BUDGET_NS = 12_000_000_000L
}
