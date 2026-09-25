package com.quantumvpn.importer

import com.quantumvpn.config.JsonConfig
import com.quantumvpn.profiles.AndroidAtomicProfileWriter
import com.quantumvpn.profiles.AtomicProfileWriter
import com.quantumvpn.security.SecureVault
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

fun interface SubscriptionFetcher {
    fun fetch(url: String): SubscriptionPayload
}

data class SubscriptionPayload(
    val body: String,
    val routingHeader: String? = null,
    val userInfo: SubscriptionUserInfo? = null,
)

class HttpSubscriptionFetcher(
    private val deviceSerialProvider: () -> String = { "" },
) : SubscriptionFetcher {
    override fun fetch(url: String): SubscriptionPayload {
        var current = validatedUrl(url)
        val serial = deviceSerialProvider().trim()
        repeat(MAX_REDIRECTS + 1) { redirectIndex ->
            val connection = (URL(current).openConnection() as? HttpURLConnection)
                ?: throw ImportException("URL подписки не является HTTP(S).")
            try {
                connection.instanceFollowRedirects = false
                connection.connectTimeout = TIMEOUT_MILLIS
                connection.readTimeout = TIMEOUT_MILLIS
                connection.useCaches = false
                connection.setRequestProperty("Accept", "application/json, text/plain, */*")
                connection.setRequestProperty("User-Agent", "QuantumVPN-Android")
                if (serial.isNotEmpty()) {
                    connection.setRequestProperty("x-hwid", serial)
                    connection.setRequestProperty("x-device-os", "android")
                    connection.setRequestProperty("x-device-model", android.os.Build.MODEL ?: "")
                    connection.setRequestProperty("x-ver-os", android.os.Build.VERSION.RELEASE ?: "")
                }
                val status = connection.responseCode
                // Prefer encrypted transports only; reject cleartext redirect hops.
                if (status in REDIRECT_CODES) {
                    if (redirectIndex == MAX_REDIRECTS) {
                        throw ImportException("Слишком много перенаправлений подписки.")
                    }
                    val location = connection.getHeaderField("Location")
                        ?: throw ImportException("Сервер вернул перенаправление без адреса.")
                    val next = validatedUrl(URI(current).resolve(location).toString())
                    current = next
                    return@repeat
                }
                if (status == 429) {
                    throw ImportException("Сервер подписки вернул HTTP 429 (rate limit).", 429)
                }
                if (status !in 200..299) {
                    throw ImportException("Сервер подписки вернул HTTP $status.", status)
                }
                val declaredLength = connection.contentLengthLong
                if (declaredLength > MAX_IMPORT_BYTES) {
                    throw ImportException("Подписка больше 4 МБ.")
                }
                val routingHeader = connection.getHeaderField("routing")
                    ?: connection.headerFields.entries.firstOrNull { (key, _) ->
                        key.equals("routing", ignoreCase = true)
                    }?.value?.firstOrNull()
                val userInfoRaw = connection.getHeaderField("subscription-userinfo")
                    ?: connection.headerFields.entries.firstOrNull { (key, _) ->
                        key.equals("subscription-userinfo", ignoreCase = true)
                    }?.value?.firstOrNull()
                connection.inputStream.use { input ->
                    val output = ByteArrayOutputStream()
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    var total = 0
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        if (total > MAX_IMPORT_BYTES) throw ImportException("Подписка больше 4 МБ.")
                        output.write(buffer, 0, count)
                    }
                    return SubscriptionPayload(
                        body = output.toString(Charsets.UTF_8.name()),
                        routingHeader = routingHeader,
                        userInfo = SubscriptionUserInfo.parse(userInfoRaw),
                    )
                }
            } finally {
                connection.disconnect()
            }
        }
        throw ImportException("Не удалось получить подписку.")
    }

    companion object {
        fun validatedUrl(raw: String): String {
            val value = raw.trim()
            val uri = runCatching { URI(value) }
                .getOrElse { throw ImportException("Некорректный URL подписки.") }
            val scheme = uri.scheme?.lowercase()
            val host = uri.host?.lowercase().orEmpty()
            if (scheme !in setOf("https", "http") || host.isBlank()) {
                throw ImportException("Укажите HTTP или HTTPS URL подписки.")
            }
            // Drop accidental fragments; keep query and path intact.
            val normalized = URI(
                scheme,
                uri.userInfo,
                uri.host,
                uri.port,
                uri.path,
                uri.query,
                null,
            ).toASCIIString()
            return normalized
        }

        private const val TIMEOUT_MILLIS = 15_000
        private const val MAX_REDIRECTS = 3
        private const val MAX_IMPORT_BYTES = 4 * 1024 * 1024
        private val REDIRECT_CODES = setOf(301, 302, 303, 307, 308)
    }
}

/** Stores refresh URLs outside profiles/index.json, which remains credentials-free UI metadata. */
class SubscriptionSourceStore(
    private val root: File,
    private val writer: AtomicProfileWriter = AndroidAtomicProfileWriter(),
    private val vault: SecureVault = SecureVault(),
) {
    private val mutex = Mutex()

    suspend fun get(profileId: String): String? = withContext(Dispatchers.IO) {
        mutex.withLock { read()[profileId] }
    }

    suspend fun ids(): Set<String> = withContext(Dispatchers.IO) {
        mutex.withLock { read().keys }
    }

    suspend fun put(profileId: String, url: String) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val entries = read().toMutableMap()
            entries[profileId] = HttpSubscriptionFetcher.validatedUrl(url)
            write(entries)
        }
    }

    suspend fun remove(profileId: String) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val entries = read().toMutableMap()
            if (entries.remove(profileId) != null) write(entries)
        }
    }

    suspend fun retain(profileIds: Set<String>) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val entries = read()
            val retained = entries.filterKeys(profileIds::contains)
            if (retained.size != entries.size) write(retained)
        }
    }

    private fun read(): Map<String, String> {
        if (!file.isFile) return emptyMap()
        return try {
            val sealed = file.readBytes()
            val plain = vault.open(sealed)
            if (!vault.isSealed(sealed) && plain.isNotEmpty()) {
                runCatching { write(parseEntries(plain.toString(Charsets.UTF_8))) }
            }
            parseEntries(plain.toString(Charsets.UTF_8))
        } catch (error: ImportException) {
            throw error
        } catch (error: Exception) {
            throw ImportException("Не удалось прочитать источники подписок.", cause = error)
        }
    }

    private fun parseEntries(text: String): Map<String, String> {
        val rootObject = JsonConfig.parse(text) as? JsonObject
            ?: throw ImportException("Хранилище источников подписок повреждено.")
        return rootObject.mapNotNull { (id, value) ->
            (value as? JsonPrimitive)?.contentOrNull?.let { id to migrateLegacyHost(it) }
        }.toMap()
    }

    /**
     * Migrate subscriptions saved by pre-5.9 clients after the panel domain
     * rotation. The path/token stays unchanged; only the HTTPS host changes.
     * This makes the first refresh self-healing instead of requiring a manual
     * re-import of the subscription.
     */
    private fun migrateLegacyHost(raw: String): String {
        val uri = runCatching { URI(raw) }.getOrNull() ?: return raw
        val host = uri.host?.lowercase() ?: return raw
        if (host !in LEGACY_PANEL_HOSTS) return raw
        return runCatching {
            URI(
                uri.scheme,
                uri.userInfo,
                CURRENT_PANEL_HOST,
                uri.port,
                uri.path,
                uri.query,
                null,
            ).toASCIIString()
        }.getOrDefault(raw)
    }

    private fun write(entries: Map<String, String>) {
        val json = buildJsonObject {
            entries.toSortedMap().forEach { (id, url) -> put(id, url) }
        }
        writer.writeAtomic(file, vault.seal(JsonConfig.format(json).toByteArray(Charsets.UTF_8)))
    }

    private val file: File get() = File(root, "index.json")

    private companion object {
        const val CURRENT_PANEL_HOST = "pecaocek.ignorelist.com"
        val LEGACY_PANEL_HOSTS = setOf(
            "tepacom.o190.com",
            "tepcawen.chickenkiller.com",
        )
    }
}
