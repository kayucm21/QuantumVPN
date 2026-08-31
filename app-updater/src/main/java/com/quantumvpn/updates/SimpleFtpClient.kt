package com.quantumvpn.updates

import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets

/**
 * Minimal passive-mode FTP client for update checks/downloads.
 * Prefers EPSV (same host as control) so NAT/PASV private-IP hangs are avoided.
 */
class SimpleFtpClient(
    private val host: String,
    private val port: Int = 21,
    private val username: String,
    private val password: String,
    private val connectTimeoutMs: Int = DEFAULT_CONNECT_MS,
    private val readTimeoutMs: Int = DEFAULT_READ_MS,
) {
    fun readText(remotePath: String, maxBytes: Int): String {
        val bytes = ByteArrayOutputStream()
        retrieve(remotePath, maxBytes.toLong()) { chunk, _ -> bytes.write(chunk) }
        return String(bytes.toByteArray(), StandardCharsets.UTF_8)
    }

    fun downloadFile(
        remotePath: String,
        target: File,
        expectedBytes: Long,
        onProgress: (Long) -> Unit,
    ) {
        if (expectedBytes <= 0 || expectedBytes > UpdateJson.MAX_APK_BYTES) {
            throw UpdateException("Некорректный размер файла FTP.")
        }
        target.parentFile?.mkdirs()
        val partial = File(target.parentFile, "${target.name}.ftp-tmp")
        try {
            FileOutputStream(partial).use { output ->
                retrieve(remotePath, expectedBytes) { chunk, total ->
                    output.write(chunk)
                    onProgress(total)
                }
            }
            if (partial.length() != expectedBytes) {
                throw UpdateException("Загрузка FTP прервана (${partial.length()} ≠ $expectedBytes).")
            }
            if (target.exists() && !target.delete()) {
                throw UpdateException("Не удалось заменить временный APK.")
            }
            if (!partial.renameTo(target)) {
                partial.copyTo(target, overwrite = true)
                partial.delete()
            }
        } catch (error: Throwable) {
            partial.delete()
            throw error
        }
    }

    private fun retrieve(
        remotePath: String,
        maxBytes: Long,
        onChunk: (ByteArray, Long) -> Unit,
    ) {
        val control = Socket()
        try {
            control.soTimeout = readTimeoutMs
            UpdateSocketProtection.bind(control)
            control.connect(InetSocketAddress(host, port), connectTimeoutMs)
            val controlRemote = control.remoteSocketAddress as? InetSocketAddress
            val controlHost = controlRemote?.address?.hostAddress?.takeIf { it.isNotBlank() } ?: host
            val reader = BufferedReader(InputStreamReader(control.getInputStream(), StandardCharsets.UTF_8))
            val writer = OutputStreamWriter(control.getOutputStream(), StandardCharsets.UTF_8)
            expect(reader, 220)
            command(writer, reader, "USER $username", 331)
            command(writer, reader, "PASS $password", 230)
            command(writer, reader, "TYPE I", 200)
            val (dataHost, dataPort) = openDataEndpoint(writer, reader, controlHost)
            val path = normalizeRemotePath(remotePath)
            command(writer, reader, "RETR $path", setOf(150, 125))
            val data = Socket()
            try {
                data.soTimeout = readTimeoutMs
                UpdateSocketProtection.bind(data)
                data.connect(InetSocketAddress(dataHost, dataPort), connectTimeoutMs)
                val buffer = ByteArray(64 * 1024)
                var total = 0L
                data.getInputStream().use { input ->
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        if (total > maxBytes || total > UpdateJson.MAX_APK_BYTES) {
                            throw UpdateException("Ответ FTP больше допустимого размера.")
                        }
                        onChunk(buffer.copyOf(count), total)
                    }
                }
                expect(reader, 226)
                runCatching { command(writer, reader, "QUIT", 221) }
            } finally {
                runCatching { data.close() }
            }
        } catch (error: UpdateException) {
            throw error
        } catch (error: IOException) {
            throw UpdateException("Не удалось связаться с FTP.", cause = error, retryViaVpn = true)
        } finally {
            runCatching { control.close() }
        }
    }

    private fun openDataEndpoint(
        writer: OutputStreamWriter,
        reader: BufferedReader,
        controlHost: String,
    ): Pair<String, Int> {
        // EPSV keeps the data channel on the same public host (avoids PASV private-IP hangs).
        runCatching {
            writer.write("EPSV\r\n")
            writer.flush()
            val line = readReply(reader)
            if (line.startsWith("229")) {
                val port = EPSV.find(line)?.groupValues?.get(1)?.toIntOrNull()
                    ?: throw UpdateException("Некорректный ответ EPSV.")
                return controlHost to port
            }
        }
        writer.write("PASV\r\n")
        writer.flush()
        val line = readReply(reader)
        if (!line.startsWith("227")) throw UpdateException("FTP PASV отклонён: ${line.take(80)}")
        val match = PASV.find(line) ?: throw UpdateException("Некорректный ответ PASV.")
        val parts = match.groupValues[1].split(',').map { it.trim().toInt() }
        if (parts.size != 6) throw UpdateException("Некорректный ответ PASV.")
        val pasvHost = parts.take(4).joinToString(".")
        val port = parts[4] * 256 + parts[5]
        val host = rewritePasvHost(pasvHost, controlHost)
        return host to port
    }

    /** Shared hosts often advertise 127.0.0.1 / 10.x / 192.168.x in PASV — use control IP instead. */
    internal fun rewritePasvHost(pasvHost: String, controlHost: String): String {
        if (pasvHost == "0.0.0.0" || pasvHost == "127.0.0.1" || pasvHost == "::1") {
            return controlHost
        }
        return try {
            val address = InetAddress.getByName(pasvHost)
            if (address.isAnyLocalAddress ||
                address.isLoopbackAddress ||
                address.isLinkLocalAddress ||
                address.isSiteLocalAddress
            ) {
                controlHost
            } else {
                pasvHost
            }
        } catch (_: Exception) {
            controlHost
        }
    }

    private fun normalizeRemotePath(remotePath: String): String {
        val trimmed = remotePath.trim()
        return if (trimmed.startsWith("/")) trimmed else "/$trimmed"
    }

    private fun command(
        writer: OutputStreamWriter,
        reader: BufferedReader,
        command: String,
        expected: Int,
    ) = command(writer, reader, command, setOf(expected))

    private fun command(
        writer: OutputStreamWriter,
        reader: BufferedReader,
        command: String,
        expected: Set<Int>,
    ) {
        writer.write("$command\r\n")
        writer.flush()
        expect(reader, expected)
    }

    private fun expect(reader: BufferedReader, code: Int) = expect(reader, setOf(code))

    private fun expect(reader: BufferedReader, codes: Set<Int>): String {
        val line = readReply(reader)
        val code = line.take(3).toIntOrNull()
            ?: throw UpdateException("Некорректный ответ FTP: ${line.take(80)}")
        if (code !in codes) {
            throw UpdateException("FTP ошибка $code: ${line.drop(4).take(120)}")
        }
        return line
    }

    private fun readReply(reader: BufferedReader): String {
        while (true) {
            val line = reader.readLine() ?: throw UpdateException("FTP закрыл соединение.")
            if (line.length >= 4 && line[3] == ' ' && line.take(3).all(Char::isDigit)) {
                return line
            }
            if (line.length >= 4 && line[3] == '-' && line.take(3).all(Char::isDigit)) {
                val code = line.take(3)
                while (true) {
                    val next = reader.readLine() ?: throw UpdateException("FTP закрыл соединение.")
                    if (next.startsWith("$code ")) return next
                }
            }
        }
    }

        companion object {
        const val DEFAULT_CONNECT_MS = 12_000
        const val DEFAULT_READ_MS = 20_000
        const val MANIFEST_CONNECT_MS = 10_000
        const val MANIFEST_READ_MS = 15_000
        val PASV = Regex("""\((\d+,\d+,\d+,\d+,\d+,\d+)\)""")
        val EPSV = Regex("""\|\|\|(\d+)\|""")
    }
}
