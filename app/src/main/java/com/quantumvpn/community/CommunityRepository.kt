package com.quantumvpn.community

import android.content.Context
import android.os.Build
import com.quantumvpn.BuildConfig
import com.quantumvpn.diagnostics.DiagnosticReportRedactor
import com.quantumvpn.policy.ClientPolicyRepository
import com.quantumvpn.profiles.ManagedSubscriptionEndpoint
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** On-demand authenticated client. No service, timer, or background polling. */
class CommunityRepository(context: Context) {
    private val app = context.applicationContext
    private val preferences = app.getSharedPreferences("quantum_community", Context.MODE_PRIVATE)
    private val credentialFile = File(app.noBackupFilesDir, "community-client-credential")
    private val mutex = Mutex()
    private val base = BuildConfig.PANEL_UPDATE_BASE_URL.trim().trimEnd('/')
    private val rawHwid get() = ClientPolicyRepository.resolveAndroidId(app)

    fun qualityConsent(): Boolean = preferences.getBoolean("quality_consent", false)

    fun setQualityConsent(enabled: Boolean) {
        preferences.edit().putBoolean("quality_consent", enabled).apply()
    }

    fun cachedInbox(): List<InboxEntry> = synchronized(CACHE_LOCK) {
        runCatching { parseInbox(JSONArray(preferences.getString("inbox", "[]"))) }.getOrDefault(emptyList())
    }

    private fun saveInbox(entries: List<InboxEntry>) {
        val array = JSONArray()
        entries.forEach { entry ->
            array.put(JSONObject().put("key", entry.key).put("kind", entry.kind)
                .put("title", entry.title).put("body", entry.body)
                .put("created_at", entry.createdAtSeconds).put("id", entry.serverId).put("read", entry.read))
        }
        preferences.edit().putString("inbox", array.toString()).apply()
    }

    /** Root wires this to an actual Available release, not every policy poll. */
    fun recordRelease(version: String, versionCode: Long) {
        if (versionCode <= 0 || version.isBlank()) return
        rememberLocal(InboxEntry("release:$versionCode", "release", "Доступно обновление $version",
            "Откройте обновления, чтобы скачать и установить новую версию.", now()))
    }

    /** Changes are retained offline and deduplicated across process restarts. */
    fun recordMaintenance(maintenance: Boolean, message: String) = synchronized(CACHE_LOCK) {
        val initialized = preferences.contains("maintenance")
        val prior = preferences.getBoolean("maintenance", false)
        preferences.edit().putBoolean("maintenance", maintenance).apply()
        if (initialized && prior == maintenance || !initialized && !maintenance) return@synchronized
        val timestamp = now()
        val kind = if (maintenance) "maintenance" else "recovery"
        rememberLocal(InboxEntry("$kind:$timestamp", kind,
            if (maintenance) "Технические работы" else "Сервис восстановлен",
            if (maintenance) message.take(1_200).ifBlank { "Работы завершатся — мы сообщим о восстановлении." }
            else "Работы завершены. Можно снова подключаться к VPN.", timestamp))
    }

    private fun rememberLocal(entry: InboxEntry) = synchronized(CACHE_LOCK) {
        val existing = cachedInbox()
        if (existing.any { it.key == entry.key }) return@synchronized
        saveInbox(InboxMerge.merge(existing, listOf(entry)))
    }

    suspend fun refreshInbox(): Result<List<InboxEntry>> = ioResult {
        var cursor = preferences.getLong("server_cursor", 0)
        val incoming = mutableListOf<InboxEntry>()
        var hasMore = true
        // Bounded catch-up per explicit refresh. Never drain an unbounded feed.
        repeat(4) {
            if (hasMore) {
                val root = request("/inbox?after=$cursor&limit=50")
                val readThrough = root.optLong("read_through", 0)
                incoming += parseInbox(root.optJSONArray("events") ?: JSONArray()).map {
                    it.copy(read = it.serverId <= readThrough)
                }
                cursor = maxOf(cursor, root.optLong("cursor", cursor))
                hasMore = root.optBoolean("has_more", false)
            }
        }
        val merged = synchronized(CACHE_LOCK) {
            InboxMerge.merge(cachedInbox(), incoming).also(::saveInbox)
        }
        preferences.edit().putLong("server_cursor", cursor).apply()
        merged
    }

    suspend fun markInboxRead(): Result<List<InboxEntry>> = ioResult {
        val cached = synchronized(CACHE_LOCK) {
            cachedInbox().also { saveInbox(it.map { entry -> entry.copy(read = true) }) }
        }
        val maxId = cached.maxOfOrNull { it.serverId } ?: 0
        if (maxId > 0) request("/inbox/read", JSONObject().put("event_id", maxId))
        cached.map { it.copy(read = true) }
    }

    suspend fun threads(): Result<List<SupportThread>> = ioResult {
        val array = request("/support").optJSONArray("threads") ?: JSONArray()
        (0 until array.length()).mapNotNull { index -> array.optJSONObject(index)?.let(::parseThread) }
    }

    suspend fun thread(id: Long): Result<SupportThread> = ioResult {
        require(id > 0)
        parseThread(request("/support/$id").getJSONObject("thread"))
    }

    suspend fun createSupport(
        subject: String,
        message: String,
        diagnostic: JSONObject? = null,
        diagnosticConsent: Boolean = false,
        requestId: String = UUID.randomUUID().toString(),
    ): Result<SupportThread> = ioResult {
        val body = supportBody(message, diagnostic, diagnosticConsent, requestId).put("subject", subject.take(120))
        parseThread(request("/support", body).getJSONObject("thread"))
    }

    suspend fun sendMessage(id: Long, message: String, requestId: String = UUID.randomUUID().toString()): Result<SupportThread> = ioResult {
        require(id > 0)
        parseThread(request("/support/$id/messages", supportBody(message, null, false, requestId)).getJSONObject("thread"))
    }

    private fun supportBody(message: String, diagnostic: JSONObject?, consent: Boolean, requestId: String): JSONObject {
        val body = JSONObject().put("body", message.take(4_000)).put("request_id", requestId)
        if (diagnostic != null) {
            require(consent) { "Нужно согласие на отправку диагностики" }
            val compact = JSONObject()
            listOf("app_version" to 32, "android_version" to 32, "last_error" to 600,
                "summary" to 2_000, "logs" to 4_000).forEach { (key, limit) ->
                if (diagnostic.has(key)) compact.put(key, DiagnosticReportRedactor.redact(diagnostic.optString(key)).take(limit))
            }
            body.put("diagnostic_consent", true).put("diagnostic", compact)
        }
        return body
    }

    suspend fun reportQuality(report: ClientQualityReport, eventId: String = UUID.randomUUID().toString()): Result<Unit> = ioResult {
        check(qualityConsent()) { "Отправка качества соединения выключена" }
        request("/quality", JSONObject().put("consent", true).put("event_id", eventId)
            .put("node_key", report.nodeKey.take(64)).put("protocol", report.protocol)
            .put("network", report.network).put("app_version", BuildConfig.VERSION_NAME)
            .put("connect_ms", report.connectMillis.coerceIn(0, 300_000))
            .put("ping_ms", report.pingMillis.coerceIn(0, 60_000))
            .put("disconnects", report.disconnects.coerceIn(0, 1_000)).put("success", report.success))
        Unit
    }

    suspend fun reportDelivery(versionCode: Long, stage: DeliveryMilestone): Result<Unit> = ioResult {
        require(versionCode > 0)
        val eventId = "${stage.wireValue}:$versionCode".replace(':', '_')
        request("/delivery", JSONObject().put("event_id", eventId).put("version_code", versionCode).put("stage", stage.wireValue))
        Unit
    }

    private suspend fun <T> ioResult(block: suspend () -> T): Result<T> = withContext(Dispatchers.IO) {
        try {
            Result.success(mutex.withLock { block() })
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            Result.failure(error)
        }
    }

    private fun request(path: String, body: JSONObject? = null): JSONObject {
        check(base.isNotBlank() && URL(base).protocol == "https") { "Защищённая панель не настроена" }
        var credential = runCatching { credentialFile.readText().trim() }.getOrDefault("")
        if (!TOKEN.matches(credential)) credential = bootstrapCredential()
        repeat(2) { attempt ->
            val connection = open(base + "/api/client/community" + path)
            try {
                connection.setRequestProperty(TOKEN_HEADER, credential)
                if (body != null) {
                    val bytes = body.toString().toByteArray(Charsets.UTF_8)
                    check(bytes.size <= 20_480) { "Сообщение слишком большое" }
                    connection.requestMethod = "POST"
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                    connection.setFixedLengthStreamingMode(bytes.size)
                    connection.outputStream.use { it.write(bytes) }
                }
                val code = connection.responseCode
                if (code == 401 && attempt == 0) {
                    credential = bootstrapCredential()
                } else {
                    val stream = if (code in 200..299) connection.inputStream else connection.errorStream
                    val raw = stream?.use { String(it.readNBytesBounded(512 * 1024), Charsets.UTF_8) }.orEmpty()
                    val json = runCatching { JSONObject(raw) }.getOrDefault(JSONObject())
                    check(code in 200..299) { friendlyError(code, json.optString("error")) }
                    return json
                }
            } finally {
                connection.disconnect()
            }
        }
        error("Не удалось подтвердить устройство")
    }

    private fun bootstrapCredential(): String {
        val endpoint = ManagedSubscriptionEndpoint.url
        check(URL(endpoint).protocol == "https" && URL(endpoint).host == URL(base).host) { "Некорректная подписка панели" }
        val connection = open(endpoint)
        try {
            check(connection.responseCode in 200..299) { "Сначала обновите действующую подписку VPN" }
            val token = connection.getHeaderField(TOKEN_HEADER).orEmpty().trim()
            check(TOKEN.matches(token)) { "Панель ещё не поддерживает защищённую поддержку" }
            connection.inputStream.use { it.readNBytesBounded(4 * 1024 * 1024) }
            // Kept out of Android backup/export. Credentials never enter logs,
            // diagnostic reports, URLs, public preferences, or profile files.
            credentialFile.writeText(token)
            return token
        } finally {
            connection.disconnect()
        }
    }

    private fun open(endpoint: String): HttpURLConnection = (URL(endpoint).openConnection() as HttpURLConnection).apply {
        connectTimeout = 10_000
        readTimeout = 15_000
        instanceFollowRedirects = false // Do not leak the bearer credential across redirects.
        setRequestProperty("Accept", "application/json")
        setRequestProperty("X-HWID", rawHwid)
        setRequestProperty("X-Device-Os", "android")
        setRequestProperty("X-Device-Model", Build.MODEL.take(120))
        setRequestProperty("X-Ver-Os", Build.VERSION.RELEASE.take(40))
        setRequestProperty("User-Agent", "QuantumVPN-Android/${BuildConfig.VERSION_NAME}")
    }

    private fun java.io.InputStream.readNBytesBounded(limit: Int): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8_192)
        var total = 0
        while (true) {
            val count = read(buffer)
            if (count < 0) break
            total += count
            check(total <= limit) { "Ответ панели слишком большой" }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private fun parseThread(root: JSONObject): SupportThread {
        val array = root.optJSONArray("messages") ?: JSONArray()
        return SupportThread(root.optLong("id"), root.optString("subject"), root.optString("state", "open"),
            root.optLong("updated_at"), (0 until array.length()).mapNotNull { index ->
                array.optJSONObject(index)?.let { item -> CommunityMessage(item.optLong("id"), item.optString("sender"),
                    item.optString("body"), item.optLong("created_at"), item.optBoolean("has_diagnostic")) }
            })
    }

    private fun parseInbox(array: JSONArray): List<InboxEntry> = (0 until array.length()).mapNotNull { index ->
        array.optJSONObject(index)?.let { item ->
            val id = item.optLong("id")
            InboxEntry(item.optString("key").ifBlank { "server:$id" }, item.optString("kind"),
                item.optString("title"), item.optString("body"), item.optLong("created_at"), id, item.optBoolean("read"))
        }
    }

    private fun friendlyError(code: Int, error: String): String = when (error) {
        "support_limit_reached" -> "Слишком много сообщений. Попробуйте позже."
        "thread_closed" -> "Обращение закрыто. Создайте новое, если нужна помощь."
        "subject_and_message_required", "message_required" -> "Напишите сообщение и тему обращения."
        else -> when (code) {
            401, 403 -> "Устройство не подтверждено. Обновите подписку и повторите."
            429 -> "Слишком много запросов. Попробуйте позже."
            else -> "Панель недоступна (HTTP $code). Сообщение не отправлено."
        }
    }

    private fun now(): Long = System.currentTimeMillis() / 1_000

    companion object {
        const val TOKEN_HEADER = "X-Quantum-Client-Token"
        private val TOKEN = Regex("[A-Za-z0-9_-]{40,96}")
        private val CACHE_LOCK = Any()
    }
}
