package com.quantumvpn.core

import android.content.Context
import android.util.Log
import android.system.Os
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

object VPNCore {
    private const val TAG = "VPNCore"
    private var isRunning = false
    private var process: Process? = null
    var totalDownload = 0L
    var totalUpload = 0L

    fun init(context: Context) {
        val arch = getArch()
        val archDir = File(File(context.filesDir, "libs"), arch)
        if (!archDir.exists()) archDir.mkdirs()
        val singBoxFile = File(archDir, "sing-box")
        if (!singBoxFile.exists()) {
            Log.d(TAG, "Copying sing-box binary for $arch...")
            try {
                context.assets.open("libs/$arch/sing-box").use { input ->
                    singBoxFile.outputStream().use { output -> input.copyTo(output) }
                }
                try {
                    Os.chmod(singBoxFile.absolutePath, 493)
                } catch (e: Exception) {
                    try {
                        Runtime.getRuntime().exec(arrayOf("chmod", "755", singBoxFile.absolutePath)).waitFor()
                    } catch (_: Exception) {}
                    Log.w(TAG, "chmod via Os failed, tried shell: ${e.message}")
                }
                Log.d(TAG, "sing-box installed: ${singBoxFile.absolutePath} (${singBoxFile.length()} bytes)")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to copy sing-box: ${e.message}")
            }
        } else {
            Log.d(TAG, "sing-box exists: ${singBoxFile.absolutePath} (${singBoxFile.length()} bytes)")
        }
    }

    fun start(configPath: String, context: Context, vpnFd: Int = -1): Boolean {
        try {
            if (isRunning) stop()

            val arch = getArch()
            val singBox = File(File(context.filesDir, "libs/$arch"), "sing-box")
            if (!singBox.exists() || singBox.length() == 0L) {
                Log.e(TAG, "sing-box not found: ${singBox.absolutePath}")
                init(context)
                if (!singBox.exists() || singBox.length() == 0L) return false
            }

            if (!singBox.canExecute()) {
                try {
                    Os.chmod(singBox.absolutePath, 493)
                } catch (e: Exception) {
                    Log.e(TAG, "Cannot make sing-box executable", e)
                    return false
                }
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
                        Log.d(TAG, "sing-box: $line")
                    }
                } catch (_: Exception) {}
            }

            Thread.sleep(1500)
            if (process?.isAlive != true) {
                val exitCode = try { process?.exitValue() } catch (_: Exception) { -1 }
                Log.e(TAG, "sing-box exited immediately with code: $exitCode")
                isRunning = false
                return false
            }

            Log.d(TAG, "sing-box is running (pid=${process.toString()})")
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start sing-box", e)
            return false
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
