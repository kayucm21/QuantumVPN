package com.quantumvpn.updates

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.net.URI
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * HTTPS client for the operator panel update source.
 * APK downloads resume from existing .part bytes over a single durable stream.
 * Mid-transfer failures never delete progress; Range+200 no longer wipes a good .part.
 */
class PanelHttpsClient : UpdateHttpClient {
    override fun readText(url: String, maxBytes: Int): String = request(url, accepts = "application/json") { connection ->
        val declared = connection.contentLengthLong
        if (declared > maxBytes) throw UpdateException("Ответ панели слишком большой.")
        connection.inputStream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            var total = 0
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                if (total > maxBytes) throw UpdateException("Ответ панели слишком большой.")
                output.write(buffer, 0, count)
            }
            output.toString(Charsets.UTF_8.name())
        }
    }

    override fun download(
        url: String,
        target: File,
        expectedBytes: Long,
        onProgress: (Long) -> Unit,
    ) {
        if (expectedBytes <= 0 || expectedBytes > UpdateJson.MAX_APK_BYTES) {
            throw UpdateException("Некорректный размер APK.")
        }
        var lastError: Exception? = null
        repeat(MAX_ATTEMPTS) { attempt ->
            try {
                downloadResumable(url, target, expectedBytes, onProgress)
                return
            } catch (error: UpdateException) {
                if (!isResumable(error) && !error.retryViaVpn) throw error
                lastError = error
            } catch (error: IOException) {
                lastError = error
            }
            if (attempt < MAX_ATTEMPTS - 1) {
                Thread.sleep(500L * (attempt + 1).coerceAtMost(8))
            }
        }
        val cause = lastError
        if (cause is UpdateException) throw cause
        throw UpdateException("Не удалось загрузить APK после повторов.", cause = cause, retryViaVpn = false)
    }

    fun headSize(url: String): Long = requestHead(url)

    private fun downloadResumable(
        url: String,
        target: File,
        expectedBytes: Long,
        onProgress: (Long) -> Unit,
    ) {
        val existing = target.takeIf { it.isFile }?.length() ?: 0L
        val startAt = when {
            existing < 0L || existing > expectedBytes -> {
                target.delete()
                0L
            }
            existing == expectedBytes -> {
                onProgress(expectedBytes)
                return
            }
            else -> existing
        }
        if (startAt > 0L) onProgress(startAt)

        val connection = open(url)
        try {
            connection.instanceFollowRedirects = false
            connection.requestMethod = "GET"
            connection.connectTimeout = CONNECT_TIMEOUT_MILLIS
            connection.readTimeout = READ_TIMEOUT_MILLIS
            connection.useCaches = false
            // Prefer long-lived TCP; avoid intermediaries closing idle TLS mid-APK.
            connection.setRequestProperty("Connection", "Keep-Alive")
            connection.setRequestProperty("Accept", "application/octet-stream")
            connection.setRequestProperty("User-Agent", "QuantumVPN-Android-Updater")
            if (startAt > 0L) {
                connection.setRequestProperty("Range", "bytes=$startAt-")
            }
            when (val status = connection.responseCode) {
                200 -> {
                    if (startAt > 0L) {
                        // Server ignored Range. Keep the good .part until a full replacement succeeds.
                        val staging = File(target.parentFile, "${target.name}.full")
                        staging.delete()
                        try {
                            writeBody(
                                connection,
                                staging,
                                append = false,
                                expectedBytes = expectedBytes,
                                startAt = 0L,
                                onProgress = onProgress,
                            )
                            if (!staging.renameTo(target)) {
                                staging.copyTo(target, overwrite = true)
                                staging.delete()
                            }
                        } catch (error: Exception) {
                            staging.delete()
                            throw error
                        }
                    } else {
                        writeBody(
                            connection,
                            target,
                            append = false,
                            expectedBytes = expectedBytes,
                            startAt = 0L,
                            onProgress = onProgress,
                        )
                    }
                }
                206 -> {
                    val range = connection.getHeaderField("Content-Range").orEmpty()
                    val resumeFrom = parseContentRangeStart(range) ?: startAt
                    if (resumeFrom != startAt) {
                        if (resumeFrom == 0L) {
                            writeBody(
                                connection,
                                target,
                                append = false,
                                expectedBytes = expectedBytes,
                                startAt = 0L,
                                onProgress = onProgress,
                            )
                        } else {
                            throw UpdateException(
                                "Загрузка APK прервана, продолжим с того же места.",
                            )
                        }
                    } else {
                        writeBody(
                            connection,
                            target,
                            append = true,
                            expectedBytes = expectedBytes,
                            startAt = startAt,
                            onProgress = onProgress,
                        )
                    }
                }
                403, 451 -> throw UpdateException("Панель отклонила доступ к обновлению (HTTP $status).", retryViaVpn = true)
                404 -> throw UpdateException("Панель не опубликовала релиз.")
                in 500..599 -> throw UpdateException("Панель временно недоступна (HTTP $status).", retryViaVpn = true)
                else -> throw UpdateException("Панель вернула HTTP $status.")
            }
        } catch (error: UpdateException) {
            throw error
        } catch (error: IOException) {
            throw UpdateException("Загрузка APK прервана, продолжим с того же места.", cause = error, retryViaVpn = false)
        } finally {
            connection.disconnect()
        }
    }

    private fun writeBody(
        connection: HttpsURLConnection,
        target: File,
        append: Boolean,
        expectedBytes: Long,
        startAt: Long,
        onProgress: (Long) -> Unit,
    ) {
        val declared = connection.contentLengthLong
        if (!append && declared > 0 && declared != expectedBytes) {
            throw UpdateException("Размер ответа не совпадает с заявленным размером APK.")
        }
        target.parentFile?.mkdirs()
        RandomAccessFile(target, "rw").use { raf ->
            if (append) {
                raf.seek(startAt)
            } else {
                raf.setLength(0)
                raf.seek(0)
            }
            connection.inputStream.use { input ->
                val buffer = ByteArray(512 * 1024)
                var total = startAt
                var lastSync = startAt
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    raf.write(buffer, 0, count)
                    total += count
                    if (total > expectedBytes || total > UpdateJson.MAX_APK_BYTES) {
                        throw UpdateException("Ответ больше заявленного размера APK.")
                    }
                    if (total - lastSync >= SYNC_EVERY_BYTES) {
                        raf.fd.sync()
                        lastSync = total
                    }
                    onProgress(total)
                }
                raf.fd.sync()
                if (total != expectedBytes) {
                    throw UpdateException("Загрузка APK прервана, продолжим с того же места.")
                }
            }
        }
    }

    private fun requestHead(rawUrl: String): Long {
        val connection = open(rawUrl)
        try {
            connection.requestMethod = "HEAD"
            connection.connectTimeout = CONNECT_TIMEOUT_MILLIS
            connection.readTimeout = READ_TIMEOUT_MILLIS
            if (connection.responseCode !in 200..299) {
                throw UpdateException("Панель не вернула размер APK (HTTP ${connection.responseCode}).")
            }
            return connection.contentLengthLong
        } finally {
            connection.disconnect()
        }
    }

    private fun <T> request(rawUrl: String, accepts: String, block: (HttpsURLConnection) -> T): T {
        val connection = open(rawUrl)
        try {
            connection.instanceFollowRedirects = false
            connection.requestMethod = "GET"
            connection.connectTimeout = CONNECT_TIMEOUT_MILLIS
            connection.readTimeout = READ_TIMEOUT_MILLIS
            connection.useCaches = false
            connection.setRequestProperty("Accept", accepts)
            connection.setRequestProperty("User-Agent", "QuantumVPN-Android-Updater")
            when (val status = connection.responseCode) {
                in 200..299 -> return block(connection)
                403, 451 -> throw UpdateException("Панель отклонила доступ к обновлению (HTTP $status).", retryViaVpn = true)
                404 -> throw UpdateException("Панель не опубликовала релиз.")
                in 500..599 -> throw UpdateException("Панель временно недоступна (HTTP $status).", retryViaVpn = true)
                else -> throw UpdateException("Панель вернула HTTP $status.")
            }
        } catch (error: UpdateException) {
            throw error
        } catch (error: IOException) {
            throw UpdateException("Не удалось связаться с панелью.", cause = error, retryViaVpn = true)
        } finally {
            connection.disconnect()
        }
    }

    private fun open(rawUrl: String): HttpsURLConnection {
        val uri = try {
            URI(rawUrl)
        } catch (error: Exception) {
            throw UpdateException("Панель вернула некорректный URL.", error)
        }
        if (uri.scheme != "https" || uri.userInfo != null || uri.fragment != null ||
            uri.port !in setOf(-1, 443, 8443)
        ) {
            throw UpdateException("Обновления разрешены только по HTTPS с панели.")
        }
        return (URL(uri.toASCIIString()).openConnection() as? HttpsURLConnection)
            ?: throw UpdateException("Для обновлений панели разрешён только HTTPS.")
    }

    private companion object {
        const val CONNECT_TIMEOUT_MILLIS = 45_000
        const val READ_TIMEOUT_MILLIS = 300_000
        const val MAX_ATTEMPTS = 16
        const val SYNC_EVERY_BYTES = 4L * 1024L * 1024L

        fun isResumable(error: UpdateException): Boolean {
            val message = error.message.orEmpty()
            return message.contains("продолжим") || message.contains("прерван")
        }

        fun parseContentRangeStart(header: String): Long? {
            // bytes 123-456/789
            val match = Regex("""bytes\s+(\d+)-""", RegexOption.IGNORE_CASE).find(header) ?: return null
            return match.groupValues[1].toLongOrNull()
        }
    }
}
