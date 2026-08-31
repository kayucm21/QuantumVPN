package com.quantumvpn.diagnostics

import android.content.Context
import android.net.ConnectivityManager
import com.quantumvpn.vpn.BootstrapResolver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class DnsPreviewResult(
    val hostname: String,
    val addresses: List<String>,
    val resolverLabel: String,
    val error: String? = null,
) {
    val summaryRu: String
        get() = when {
            error != null -> "Ошибка: $error"
            addresses.isEmpty() -> "Нет ответа для $hostname"
            else -> "${addresses.joinToString(", ")} ($resolverLabel)"
        }
}

object DnsPreviewProbe {
    suspend fun resolve(context: Context, hostnameRaw: String): DnsPreviewResult =
        withContext(Dispatchers.IO) {
            val hostname = hostnameRaw.trim()
                .removePrefix("http://")
                .removePrefix("https://")
                .substringBefore('/')
                .substringBefore(':')
            if (hostname.isBlank()) {
                return@withContext DnsPreviewResult("", emptyList(), "Android", "Пустой домен")
            }
            val cm = context.getSystemService(ConnectivityManager::class.java)
            val network = cm.activeNetwork
                ?: return@withContext DnsPreviewResult(hostname, emptyList(), "Android", "Нет сети")
            val resolver = BootstrapResolver()
            runCatching {
                val addresses = resolver.resolve(network, hostname)
                    .mapNotNull { it.hostAddress }
                    .distinct()
                DnsPreviewResult(
                    hostname = hostname,
                    addresses = addresses,
                    resolverLabel = "Android DNS",
                )
            }.getOrElse { error ->
                DnsPreviewResult(
                    hostname = hostname,
                    addresses = emptyList(),
                    resolverLabel = "Android DNS",
                    error = error.message?.take(160) ?: "resolve failed",
                )
            }
        }
}
