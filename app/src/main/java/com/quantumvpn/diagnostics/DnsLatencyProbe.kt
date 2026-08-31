package com.quantumvpn.diagnostics

import com.quantumvpn.config.DnsPreset
import com.quantumvpn.config.DnsPresetCatalog
import java.net.InetAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

data class DnsLatencySample(
    val title: String,
    val ipv4: String,
    val millis: Long?,
)

object DnsLatencyProbe {
    suspend fun race(
        presets: List<DnsPreset> = DnsPresetCatalog.presets,
        timeoutMs: Long = 2_500,
    ): List<DnsLatencySample> = coroutineScope {
        presets.map { preset ->
            async {
                val ms = withTimeoutOrNull(timeoutMs) {
                    withContext(Dispatchers.IO) {
                        val start = System.nanoTime()
                        runCatching { InetAddress.getByName(preset.ipv4) }.getOrNull()
                            ?: return@withContext null
                        ((System.nanoTime() - start) / 1_000_000L).coerceAtLeast(1L)
                    }
                }
                DnsLatencySample(preset.title, preset.ipv4, ms)
            }
        }.awaitAll().sortedWith(compareBy({ it.millis == null }, { it.millis ?: Long.MAX_VALUE }))
    }

    fun format(samples: List<DnsLatencySample>): String {
        if (samples.isEmpty()) return "DNS latency: нет данных"
        return samples.joinToString(" · ") { sample ->
            val ping = sample.millis?.let { "$it ms" } ?: "timeout"
            "${sample.title} $ping"
        }
    }
}
