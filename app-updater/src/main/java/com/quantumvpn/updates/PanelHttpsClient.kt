package com.quantumvpn.updates

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.net.URI
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * HTTPS client for the RosPanel update source. Unlike the GitHub client it does not
 * restrict the host to github.com (the operator's panel can live anywhere), but it still
 * enforces HTTPS and sane size limits. Used for both the release JSON and the APK download.
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
    ) = request(url, accepts = "application/octet-stream") { connection ->
        if (expectedBytes <= 0 || expectedBytes > UpdateJson.MAX_APK_BYTES) {
            throw UpdateException("Некорректный размер APK.")
        }
        val declared = connection.contentLengthLong
        if (declared > 0 && declared != expectedBytes) {
            throw UpdateException("Размер ответа не совпадает с заявленным размером APK.")
        }
        target.outputStream().buffered().use { output ->
            connection.inputStream.use { input ->
                val buffer = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > expectedBytes || total > UpdateJson.MAX_APK_BYTES) {
                        throw UpdateException("Ответ больше заявленного размера APK.")
                    }
                    output.write(buffer, 0, count)
                    onProgress(total)
                }
                output.flush()
                if (total != expectedBytes) throw UpdateException("Загрузка APK прервана.")
            }
        }
    }

    /** HEAD request to learn the APK size when the release metadata does not carry it. */
    fun headSize(url: String): Long = requestHead(url)

    private fun requestHead(rawUrl: String): Long {
        val connection = open(rawUrl)
        try {
            connection.requestMethod = "HEAD"
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
            connection.connectTimeout = TIMEOUT_MILLIS
            connection.readTimeout = TIMEOUT_MILLIS
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
        const val TIMEOUT_MILLIS = 30_000
    }
}
