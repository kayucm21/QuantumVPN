package com.quantumvpn.diagnostics

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

data class LeakCheckResult(
    val vpnActive: Boolean,
    val ipv4: String?,
    val ipv6: String?,
    val dnsResolvesGoogle: Boolean,
    val httpsOk: Boolean,
    val notes: List<String>,
) {
    val summary: String
        get() = buildString {
            append(if (vpnActive) "VPN активен. " else "VPN не активен. ")
            append("IPv4: ${ipv4 ?: "—"}. ")
            append("IPv6: ${ipv6 ?: "—"}. ")
            append(if (httpsOk) "HTTPS OK. " else "HTTPS сбой. ")
            append(if (dnsResolvesGoogle) "DNS OK." else "DNS сбой.")
            if (notes.isNotEmpty()) append(' ').append(notes.joinToString(" "))
        }
}

/** Lightweight on-demand leak/smoke check — no background polling. */
object LeakChecker {
    suspend fun run(context: Context): LeakCheckResult = withContext(Dispatchers.IO) {
        withTimeout(12_000) {
            coroutineScope {
                val cm = context.getSystemService(ConnectivityManager::class.java)
                val network = cm.activeNetwork
                val caps = network?.let(cm::getNetworkCapabilities)
                val vpnActive = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

                val ipv4 = async {
                    runCatching { fetchText("https://api.ipify.org") }.getOrNull()
                }
                val ipv6 = async {
                    runCatching { fetchText("https://api64.ipify.org") }
                        .getOrNull()
                        ?.takeIf { ":" in it }
                }
                val dns = async {
                    runCatching {
                        InetAddress.getAllByName("dns.google").isNotEmpty()
                    }.getOrDefault(false)
                }
                val https = async {
                    runCatching {
                        val connection = URL("https://www.google.com/generate_204").openConnection() as HttpsURLConnection
                        try {
                            connection.connectTimeout = 4_000
                            connection.readTimeout = 4_000
                            connection.instanceFollowRedirects = false
                            connection.responseCode in 200..399
                        } finally {
                            connection.disconnect()
                        }
                    }.getOrDefault(false)
                }

                val v4 = ipv4.await()
                val v6 = ipv6.await()
                val notes = buildList {
                    if (!vpnActive) add("Включите VPN, чтобы проверить выход через туннель.")
                    if (v4 != null && v6 != null && v4 != v6) {
                        add("Одновременно видны IPv4 и IPv6 — проверьте маршрутизацию IPv6.")
                    }
                }
                LeakCheckResult(
                    vpnActive = vpnActive,
                    ipv4 = v4,
                    ipv6 = v6,
                    dnsResolvesGoogle = dns.await(),
                    httpsOk = https.await(),
                    notes = notes,
                )
            }
        }
    }

    private fun fetchText(url: String): String {
        val connection = URL(url).openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = 4_000
            connection.readTimeout = 4_000
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            check(connection.responseCode == 200) { "HTTP ${connection.responseCode}" }
            return connection.inputStream.bufferedReader().use { it.readText().trim() }
        } finally {
            connection.disconnect()
        }
    }
}
