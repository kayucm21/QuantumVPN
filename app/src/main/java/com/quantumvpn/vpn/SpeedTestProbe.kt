package com.quantumvpn.vpn

import java.io.OutputStream
import java.net.URL
import java.util.concurrent.ThreadLocalRandom
import javax.net.ssl.HttpsURLConnection
import kotlin.math.sqrt
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
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
                attempt { probeLatency() }?.let(latencySamples::add)
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
                download = attempt(onFailure = {
                    lastError = it.message ?: it.javaClass.simpleName
                }) { probeDownload(url) }
                if (download != null) break
            }
            val uploadKbps = attempt { probeUpload() } ?: 0L
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
            val upPart = if (uploadKbps > 0) " · ↑ ${formatRate(uploadKbps)}" else " · ↑ недоступно"
            val jitPart = if (jitter > 0) " · jitter ${jitter} ms" else ""
            SpeedTestResult(
                downloadKbps = kbps,
                uploadKbps = uploadKbps,
                latencyMillis = latency,
                jitterMillis = jitter,
                ok = bytes >= MIN_MEASUREMENT_BYTES,
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
            connection.setRequestProperty("User-Agent", USER_AGENT)
            val code = connection.responseCode
            if (code !in 200..399) error("HTTP $code")
            return (System.nanoTime() - started) / 1_000_000
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun probeDownload(url: String): Pair<Long, Long> {
        val connection = URL(url).openConnection() as HttpsURLConnection
        try {
            connection.connectTimeout = 6_000
            connection.readTimeout = 4_000
            connection.instanceFollowRedirects = true
            connection.useCaches = false
            connection.setRequestProperty("User-Agent", USER_AGENT)
            connection.setRequestProperty("Accept-Encoding", "identity")
            val code = connection.responseCode
            if (code !in 200..299) error("HTTP $code")
            // HTTP headers have arrived: DNS, TCP and TLS setup belong to TTFB,
            // not to sustained transfer speed. Small files used to mix both.
            val sample = connection.inputStream.use { input ->
                val started = System.nanoTime()
                var total = 0L
                val buffer = ByteArray(64 * 1024)
                val deadline = started + READ_BUDGET_NS
                while (System.nanoTime() < deadline) {
                    coroutineContext.ensureActive()
                    val read = input.read(buffer)
                    if (read <= 0) break
                    total += read
                    if (total >= MAX_BYTES) break
                }
                SpeedTransferMeasurement(total, System.nanoTime() - started)
            }
            require(sample.bytes >= MIN_MEASUREMENT_BYTES) { "Слишком короткий ответ для замера скорости" }
            return sample.kbps to sample.bytes
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun probeUpload(): Long {
        val connection = URL(UPLOAD_URL).openConnection() as HttpsURLConnection
        try {
            connection.connectTimeout = 6_000
            connection.readTimeout = 10_000
            connection.doOutput = true
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.setRequestProperty("Content-Type", "application/octet-stream")
            connection.setRequestProperty("User-Agent", USER_AGENT)
            connection.setFixedLengthStreamingMode(UPLOAD_BYTES.toInt())
            val payload = ByteArray(64 * 1024).also { ThreadLocalRandom.current().nextBytes(it) }
            // Obtaining the stream completes connection setup before timing.
            val output = connection.outputStream
            val started = System.nanoTime()
            output.use { out -> writePayload(out, UPLOAD_BYTES, payload) }
            val code = connection.responseCode
            // A rejection is not a completed upload and must not become a speed.
            if (code !in 200..299) error("HTTP $code")
            return SpeedTransferMeasurement(UPLOAD_BYTES, System.nanoTime() - started).kbps
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun writePayload(out: OutputStream, size: Long, buffer: ByteArray) {
        var left = size
        while (left > 0) {
            coroutineContext.ensureActive()
            val n = minOf(left, buffer.size.toLong()).toInt()
            out.write(buffer, 0, n)
            left -= n
        }
        out.flush()
    }

    fun formatRate(kbps: Long): String = when {
        kbps >= 1_000 -> String.format("%.2f Mbps", kbps / 1000.0)
        else -> "$kbps kbps"
    }

    private inline fun <T> attempt(onFailure: (Throwable) -> Unit = {}, block: () -> T): T? =
        try {
            block()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            onFailure(error)
            null
        }

    private val DOWNLOAD_URLS = listOf(
        "https://speed.cloudflare.com/__down?bytes=32000000",
        "https://proof.ovh.net/files/10Mb.dat",
    )
    private const val LATENCY_URL = "https://www.gstatic.com/generate_204"
    private const val UPLOAD_URL = "https://speed.cloudflare.com/__up"
    private const val UPLOAD_BYTES = 4L * 1024L * 1024L
    private const val MAX_BYTES = 32_000_000L
    private const val MIN_MEASUREMENT_BYTES = 64L * 1024L
    private const val TIMEOUT_MS = 45_000L
    private const val READ_BUDGET_NS = 8_000_000_000L
    private const val USER_AGENT = "QuantumVPN-SpeedTest/6"
}

/** Rate over body transfer time, retaining precision for fast subsecond samples. */
internal data class SpeedTransferMeasurement(val bytes: Long, val elapsedNanos: Long) {
    val kbps: Long
        get() = if (bytes <= 0 || elapsedNanos <= 0) 0L else
            (bytes.toDouble() * 8_000_000.0 / elapsedNanos).toLong()
}
