package com.quantumvpn.resources

import android.content.Context
import android.graphics.BitmapFactory
import android.util.AtomicFile
import com.quantumvpn.BuildConfig
import com.quantumvpn.policy.ClientPolicyRepository
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*

/** A two-generation, atomic last-good cache. All disk/network/image work is off the UI thread. */
class AppResourceRepository(context: Context) {
    private val app = context.applicationContext
    private val root = File(app.noBackupFilesDir, "presentation-resources")
    private val journal = AtomicFile(File(root, "state.json"))
    private val mutex = Mutex()
    private val mutable = MutableStateFlow<AppResources?>(null)
    val resources = mutable.asStateFlow()
    private val statusMutable = MutableStateFlow("Встроенные ресурсы")
    val status = statusMutable.asStateFlow()
    private var loaded = false
    private var highWater = 0L
    private var currentRaw: String? = null
    private var previousRaw: String? = null
    private var lastAttempt = 0L

    fun imageFile(role: String): File? = resources.value?.assets?.get(role)?.let { File(root, it.sha256) }

    suspend fun loadCache() = withContext(Dispatchers.IO) { mutex.withLock { loadLocked() } }

    private fun loadLocked() {
        if (loaded) return
        loaded = true
        root.mkdirs()
        root.listFiles()?.filter { it.name.endsWith(".part") }?.forEach { it.delete() }
        try {
            val bytes = journal.openRead().use { readBounded(it, 2 * AppResourceVerifier.MAX_MANIFEST + 4096) }
            val state = Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
            highWater = state.getValue("sequence").jsonPrimitive.long
            currentRaw = state["current"]?.jsonPrimitive?.contentOrNull
            previousRaw = state["previous"]?.jsonPrimitive?.contentOrNull
            for (raw in listOfNotNull(currentRaw, previousRaw)) {
                val verified = runCatching {
                    AppResourceVerifier.verify(raw, BuildConfig.VERSION_CODE.toLong()).also { checkImages(it) }
                }.getOrNull() ?: continue
                mutable.value = verified
                highWater = maxOf(highWater, verified.sequence)
                statusMutable.value = "Проверены · r${verified.revision} · публикация ${verified.sequence}"
                cleanupAssets()
                return
            }
            statusMutable.value = "Кэш не прошёл проверку · встроенные ресурсы"
        } catch (_: Exception) {
            statusMutable.value = "Встроенные ресурсы"
        }
    }

    suspend fun refresh(force: Boolean = false) = withContext(Dispatchers.IO) {
        mutex.withLock {
            loadLocked()
            val now = android.os.SystemClock.elapsedRealtime()
            if (!force && lastAttempt != 0L && now - lastAttempt < 300_000) return@withLock
            lastAttempt = now
            statusMutable.value = "Проверяем ресурсы…"
            try {
                val base = BuildConfig.PANEL_UPDATE_BASE_URL.trimEnd('/')
                val uri = URI(base)
                require(uri.scheme == "https" && uri.host != null && uri.userInfo == null)
                val raw = request("$base/api/client/resources?version_code=${BuildConfig.VERSION_CODE}", AppResourceVerifier.MAX_MANIFEST)
                    ?: run { statusMutable.value = "Публикаций для этого APK нет · текущие ресурсы сохранены"; return@withLock }
                val next = AppResourceVerifier.verify(raw.toString(Charsets.UTF_8), BuildConfig.VERSION_CODE.toLong(), highWater)
                // Equal sequence with different contents is ambiguous, never accept it.
                resources.value?.let { old -> require(next.sequence != old.sequence || next.digest == old.digest) }
                for (image in next.assets.values) {
                    kotlin.coroutines.coroutineContext.ensureActive()
                    val target = File(root, image.sha256)
                    if (validImage(target, image)) continue
                    val bytes = request("$base/api/client/resources/assets/${image.sha256}", image.size)
                        ?: error("Изображение недоступно")
                    require(bytes.size == image.size && AppResourceVerifier.sha256(bytes) == image.sha256)
                    val temporary = File(root, image.sha256 + ".part")
                    try {
                        temporary.outputStream().use { it.write(bytes); it.fd.sync() }
                        require(validImage(temporary, image))
                        require(temporary.renameTo(target))
                    } finally { temporary.delete() }
                }
                checkImages(next)
                kotlin.coroutines.coroutineContext.ensureActive()
                val old = resources.value?.envelope
                val previous = if (old != null && old != next.envelope) old else previousRaw
                val state = buildJsonObject {
                    put("sequence", next.sequence); put("current", next.envelope)
                    if (previous != null) put("previous", previous)
                }.toString().toByteArray(Charsets.UTF_8)
                val stream = journal.startWrite()
                try { stream.write(state); journal.finishWrite(stream) }
                catch (error: Throwable) { journal.failWrite(stream); throw error }
                highWater = next.sequence
                previousRaw = previous
                currentRaw = next.envelope
                mutable.value = next
                statusMutable.value = "Проверены · r${next.revision} · публикация ${next.sequence}"
                // Only our content-addressed assets, never personal gallery photos.
            } catch (cancelled: CancellationException) {
                lastAttempt = 0L
                statusMutable.value = "Проверим ресурсы при возвращении в приложение"
                throw cancelled
            }
            catch (_: Exception) { statusMutable.value = "Не удалось проверить ресурсы · последняя рабочая версия сохранена" }
            finally { cleanupAssets() }
        }
    }

    private fun cleanupAssets() {
        val keep = mutableSetOf<String>()
        for (raw in listOfNotNull(currentRaw, previousRaw)) {
            runCatching { AppResourceVerifier.verify(raw, BuildConfig.VERSION_CODE.toLong()).assets.values.mapTo(keep) { it.sha256 } }
        }
        root.listFiles()?.filter { it.name.matches(Regex("[0-9a-f]{64}")) && it.name !in keep }?.forEach { it.delete() }
    }

    private fun checkImages(bundle: AppResources) = bundle.assets.values.forEach { require(validImage(File(root, it.sha256), it)) }
    private fun validImage(file: File, descriptor: ResourceImage): Boolean = runCatching {
        if (!file.isFile || file.length() != descriptor.size.toLong()) return@runCatching false
        if (AppResourceVerifier.sha256(file.readBytes()) != descriptor.sha256) return@runCatching false
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, bounds)
        bounds.outWidth == descriptor.width && bounds.outHeight == descriptor.height && bounds.outMimeType == descriptor.mime
    }.getOrDefault(false)

    private fun request(url: String, limit: Int): ByteArray? {
        val connection = URL(url).openConnection() as HttpURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10_000; connection.readTimeout = 10_000
            connection.setRequestProperty("X-HWID", ClientPolicyRepository.resolveAndroidId(app))
            connection.setRequestProperty("Accept-Encoding", "identity")
            val code = connection.responseCode
            if (code == 204) return null
            require(code == 200 && connection.contentLengthLong <= limit)
            return connection.inputStream.use { readBounded(it, limit) }
        } finally { connection.disconnect() }
    }

    private fun readBounded(input: java.io.InputStream, limit: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            require(out.size() + read <= limit)
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }
}
