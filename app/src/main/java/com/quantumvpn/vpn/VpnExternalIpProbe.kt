package com.quantumvpn.vpn

import java.io.InputStream
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

data class VpnExitIdentity(
    val ip: String,
    val location: ExitLocation?,
)

/** Fetches public IP and country through the established VPN. */
class VpnExternalIpProbe(
    private val vpnNetworks: VpnNetworkProvider,
) {
    suspend fun fetch(): String = fetchIdentity().ip

    suspend fun fetchIdentity(): VpnExitIdentity = withTimeout(HTTPS_TIMEOUT_MILLIS.toLong()) {
        val vpnNetwork = vpnNetworks.awaitActive()
        vpnNetworks.requireActive(vpnNetwork)
        withContext(Dispatchers.IO) {
            fetchWhoIs(vpnNetwork) ?: VpnExitIdentity(ip = fetchIpify(vpnNetwork), location = null)
        }
    }

    private fun fetchWhoIs(vpnNetwork: android.net.Network): VpnExitIdentity? {
        val connection = vpnNetwork.openConnection(URL(WHOIS_URL)) as HttpsURLConnection
        return try {
            connection.connectTimeout = HTTPS_TIMEOUT_MILLIS
            connection.readTimeout = HTTPS_TIMEOUT_MILLIS
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.setRequestProperty("Connection", "close")
            connection.setRequestProperty("Accept", "application/json")
            connection.requestMethod = "GET"
            if (connection.responseCode != 200) return null
            val body = connection.inputStream.use(::readBounded)
            parseWhoIs(body)
        } catch (_: Exception) {
            null
        } finally {
            connection.disconnect()
        }
    }

    private fun fetchIpify(vpnNetwork: android.net.Network): String {
        val connection = vpnNetwork.openConnection(URL(IPIFY_URL)) as HttpsURLConnection
        try {
            connection.connectTimeout = HTTPS_TIMEOUT_MILLIS
            connection.readTimeout = HTTPS_TIMEOUT_MILLIS
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.setRequestProperty("Connection", "close")
            connection.requestMethod = "GET"
            val status = connection.responseCode
            if (status != 200) error("IP endpoint вернул HTTP $status.")
            val value = connection.inputStream.use(::readBounded)
            return ExternalIpParser.parse(value) ?: error("IP endpoint вернул некорректный адрес.")
        } finally {
            connection.disconnect()
        }
    }

    private fun parseWhoIs(body: String): VpnExitIdentity? {
        val root = runCatching { JSON.parseToJsonElement(body) as? JsonObject }.getOrNull() ?: return null
        if (root["success"]?.jsonPrimitive?.booleanOrNull == false) return null
        val ip = root["ip"]?.jsonPrimitive?.contentOrNull?.let(ExternalIpParser::parse) ?: return null
        val location = ExitLocationResolver.fromGeo(
            countryName = root["country"]?.jsonPrimitive?.contentOrNull,
            countryCode = root["country_code"]?.jsonPrimitive?.contentOrNull,
        )
        return VpnExitIdentity(ip = ip, location = location)
    }

    private fun readBounded(input: InputStream): String {
        val buffer = ByteArray(MAX_RESPONSE_CHARS + 1)
        var count = 0
        while (count < buffer.size) {
            val read = input.read(buffer, count, buffer.size - count)
            if (read < 0) break
            count += read
        }
        require(count <= MAX_RESPONSE_CHARS) { "Geo endpoint вернул слишком длинный ответ." }
        return buffer.decodeToString(0, count)
    }

    private companion object {
        val JSON = Json { ignoreUnknownKeys = true }
        const val WHOIS_URL = "https://ipwho.is/"
        const val IPIFY_URL = "https://api64.ipify.org"
        const val HTTPS_TIMEOUT_MILLIS = 5_000
        const val MAX_RESPONSE_CHARS = 8_192
    }
}
