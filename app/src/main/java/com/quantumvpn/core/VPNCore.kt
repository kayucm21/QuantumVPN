package com.quantumvpn.core

import android.content.Context
import android.util.Log
import android.system.Os
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.concurrent.CopyOnWriteArrayList

object VPNCore {
    private const val TAG = "VPNCore"
    private var isRunning = false
    private var process: Process? = null
    private val logLines = CopyOnWriteArrayList<String>()
    var totalDownload = 0L
    var totalUpload = 0L

    fun getLastError(): String = logLines.takeLast(5).joinToString("\n").ifBlank {
        "sing-box завершился с ошибкой"
    }

    fun init(context: Context) {
        val arch = getArch()
        val archDir = File(File(context.filesDir, "libs"), arch)
        if (!archDir.exists()) archDir.mkdirs()
        val singBoxFile = File(archDir, "sing-box")
        if (!singBoxFile.exists() || singBoxFile.length() < 1_000_000L) {
            Log.d(TAG, "Copying sing-box binary for $arch...")
            try {
                context.assets.open("libs/$arch/sing-box").use { input ->
                    singBoxFile.outputStream().use { output -> input.copyTo(output) }
                }
                makeExecutable(singBoxFile)
                Log.d(TAG, "sing-box installed: ${singBoxFile.absolutePath} (${singBoxFile.length()} bytes)")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to copy sing-box: ${e.message}")
            }
        } else {
            makeExecutable(singBoxFile)
            Log.d(TAG, "sing-box exists: ${singBoxFile.absolutePath} (${singBoxFile.length()} bytes)")
        }
    }

    private fun makeExecutable(file: File) {
        try {
            Os.chmod(file.absolutePath, 493)
        } catch (e: Exception) {
            try {
                Runtime.getRuntime().exec(arrayOf("chmod", "755", file.absolutePath)).waitFor()
            } catch (_: Exception) {}
            Log.w(TAG, "chmod via Os failed: ${e.message}")
        }
    }

    fun start(configPath: String, context: Context, vpnFd: Int = -1): Boolean {
        try {
            if (isRunning) stop()
            logLines.clear()

            val singBox = getSingBoxBinary(context) ?: return false

            if (!validateConfig(singBox, configPath)) {
                Log.e(TAG, "Config validation failed: ${getLastError()}")
                return false
            }

            Log.d(TAG, "Starting sing-box: ${singBox.absolutePath} run -c $configPath (fd=$vpnFd)")

            val cmd = mutableListOf(singBox.absolutePath, "run", "-c", configPath)
            val pb = ProcessBuilder(cmd)
            pb.redirectErrorStream(true)
            pb.directory(context.filesDir)

            val env = pb.environment()
            env["TMPDIR"] = context.cacheDir.absolutePath
            env["HOME"] = context.filesDir.absolutePath
            if (vpnFd >= 0) {
                env["ANDROID_VPN_SERVICE_FD"] = vpnFd.toString()
            }

            process = pb.start()
            isRunning = true
            totalDownload = 0
            totalUpload = 0

            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val reader = BufferedReader(InputStreamReader(process!!.inputStream))
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        line?.let {
                            Log.d(TAG, "sing-box: $it")
                            logLines.add(it)
                            if (logLines.size > 50) logLines.removeAt(0)
                        }
                    }
                } catch (_: Exception) {}
            }

            Thread.sleep(2000)
            if (process?.isAlive != true) {
                val exitCode = try { process?.exitValue() } catch (_: Exception) { -1 }
                Log.e(TAG, "sing-box exited immediately with code: $exitCode, log: ${getLastError()}")
                isRunning = false
                return false
            }

            Log.d(TAG, "sing-box is running")
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start sing-box", e)
            logLines.add(e.message ?: "unknown error")
            return false
        }
    }

    private fun getSingBoxBinary(context: Context): File? {
        val arch = getArch()
        val singBox = File(File(context.filesDir, "libs/$arch"), "sing-box")
        if (!singBox.exists() || singBox.length() < 1_000_000L) {
            Log.e(TAG, "sing-box not found or too small: ${singBox.absolutePath}")
            init(context)
            if (!singBox.exists() || singBox.length() < 1_000_000L) {
                logLines.add("Бинарник sing-box не найден в APK")
                return null
            }
        }
        if (!singBox.canExecute()) {
            makeExecutable(singBox)
            if (!singBox.canExecute()) {
                logLines.add("Не удалось сделать sing-box исполняемым")
                return null
            }
        }
        return singBox
    }

    private fun validateConfig(singBox: File, configPath: String): Boolean {
        return try {
            val pb = ProcessBuilder(singBox.absolutePath, "check", "-c", configPath)
            pb.redirectErrorStream(true)
            val proc = pb.start()
            val output = proc.inputStream.bufferedReader().readText()
            val code = proc.waitFor()
            if (code != 0) {
                logLines.add(output.trim().ifBlank { "Неверный конфиг sing-box (код $code)" })
            }
            code == 0
        } catch (e: Exception) {
            logLines.add("Проверка конфига: ${e.message}")
            true
        }
    }

    fun stop() {
        isRunning = false
        try {
            process?.destroy()
            process?.waitFor()
            process = null
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop sing-box", e)
        }
        Log.d(TAG, "sing-box stopped")
    }

    fun isRunning(): Boolean = isRunning

    private fun getArch(): String = when (System.getProperty("os.arch")) {
        "aarch64" -> "arm64-v8a"
        "arm" -> "armeabi-v7a"
        "x86_64" -> "x86_64"
        "x86" -> "x86"
        else -> "arm64-v8a"
    }

    suspend fun testPing(host: String, port: Int, timeout: Int = 5000): Long = withContext(Dispatchers.IO) {
        try {
            val t = System.currentTimeMillis()
            java.net.Socket().use { it.connect(java.net.InetSocketAddress(host, port), timeout) }
            System.currentTimeMillis() - t
        } catch (e: Exception) { -1L }
    }
}
