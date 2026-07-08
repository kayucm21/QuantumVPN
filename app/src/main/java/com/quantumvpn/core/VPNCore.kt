package com.quantumvpn.core

import android.content.Context
import android.os.Build
import android.util.Log
import android.system.Os
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.concurrent.CopyOnWriteArrayList

object VPNCore {
    private const val TAG = "VPNCore"
    private const val LIB_NAME = "libsing-box.so"
    private var isRunning = false
    private var process: Process? = null
    private val logLines = CopyOnWriteArrayList<String>()
    var totalDownload = 0L
    var totalUpload = 0L

    fun getLastError(): String = logLines.takeLast(5).joinToString("\n").ifBlank {
        "sing-box завершился с ошибкой"
    }

    fun init(context: Context) {
        installSingBox(context)
    }

    fun start(configPath: String, context: Context, vpnFd: Int = -1): Boolean {
        try {
            if (isRunning) stop()
            logLines.clear()

            val singBox = installSingBox(context) ?: return false

            if (!validateConfig(singBox, configPath, context)) {
                Log.e(TAG, "Config validation failed: ${getLastError()}")
                return false
            }

            Log.d(TAG, "Starting sing-box: ${singBox.absolutePath} (fd=$vpnFd)")

            val cmd = buildCommand(singBox, "run", "-c", configPath)
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

            Thread {
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
            }.start()

            Thread.sleep(2000)
            if (process?.isAlive != true) {
                val exitCode = try { process?.exitValue() } catch (_: Exception) { -1 }
                Log.e(TAG, "sing-box exited with code: $exitCode, log: ${getLastError()}")
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

    private fun installSingBox(context: Context): File? {
        val candidates = listOfNotNull(
            context.applicationInfo.nativeLibraryDir?.let { File(it, LIB_NAME) },
            File(context.codeCacheDir, LIB_NAME)
        )

        for (target in candidates) {
            try {
                if (!target.exists() || target.length() < 1_000_000L) {
                    val arch = getArch()
                    Log.d(TAG, "Installing sing-box to ${target.absolutePath} for $arch")
                    context.assets.open("libs/$arch/sing-box").use { input ->
                        target.parentFile?.mkdirs()
                        target.outputStream().use { output -> input.copyTo(output) }
                    }
                }
                makeExecutable(target)
                if (target.exists() && target.length() >= 1_000_000L) {
                    Log.d(TAG, "sing-box ready: ${target.absolutePath} (${target.length()} bytes)")
                    return target
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to install sing-box to ${target.absolutePath}: ${e.message}")
            }
        }

        logLines.add("Не удалось установить sing-box. Переустановите приложение.")
        return null
    }

    private fun makeExecutable(file: File) {
        file.setReadable(true, false)
        file.setWritable(true, false)
        file.setExecutable(true, false)
        try {
            Os.chmod(file.absolutePath, 493)
        } catch (e: Exception) {
            try {
                Runtime.getRuntime().exec(arrayOf("chmod", "755", file.absolutePath)).waitFor()
            } catch (_: Exception) {}
            Log.w(TAG, "chmod failed: ${e.message}")
        }
    }

    private fun buildCommand(singBox: File, vararg args: String): List<String> {
        val linker64 = File("/system/bin/linker64")
        val linker = File("/system/bin/linker")
        val argList = args.toList()
        return when {
            linker64.exists() -> listOf(linker64.absolutePath, singBox.absolutePath) + argList
            linker.exists() && Build.SUPPORTED_ABIS.firstOrNull()?.contains("64") != true ->
                listOf(linker.absolutePath, singBox.absolutePath) + argList
            else -> listOf(singBox.absolutePath) + argList
        }
    }

    private fun validateConfig(singBox: File, configPath: String, context: Context): Boolean {
        return try {
            val cmd = buildCommand(singBox, "check", "-c", configPath)
            val pb = ProcessBuilder(cmd)
            pb.redirectErrorStream(true)
            pb.directory(context.filesDir)
            val proc = pb.start()
            val output = proc.inputStream.bufferedReader().readText()
            val code = proc.waitFor()
            if (code != 0) {
                logLines.add(output.trim().ifBlank { "Неверный конфиг sing-box (код $code)" })
                return false
            }
            true
        } catch (e: Exception) {
            logLines.add("Проверка конфига: ${e.message}")
            false
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

    private fun getArch(): String {
        val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"
        return when {
            abi.contains("arm64") -> "arm64-v8a"
            abi.contains("armeabi") -> "armeabi-v7a"
            abi.contains("x86_64") -> "x86_64"
            abi.contains("x86") -> "x86"
            else -> "arm64-v8a"
        }
    }

    suspend fun testPing(host: String, port: Int, timeout: Int = 5000): Long = withContext(Dispatchers.IO) {
        try {
            val t = System.currentTimeMillis()
            java.net.Socket().use { it.connect(java.net.InetSocketAddress(host, port), timeout) }
            System.currentTimeMillis() - t
        } catch (e: Exception) { -1L }
    }
}
