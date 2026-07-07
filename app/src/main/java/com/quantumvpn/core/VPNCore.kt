package com.quantumvpn.core

import android.content.Context
import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

object VPNCore {
    private const val TAG = "VPNCore"
    private var isRunning = false
    private var process: Process? = null
    private var vpnService: VpnService? = null
    var totalDownload = 0L; private set
    var totalUpload = 0L; private set

    fun setVpnService(s: VpnService) { vpnService = s }

    fun init(context: Context) {
        val arch = getArch()
        val libsDir = File(context.filesDir, "libs")
        if (!libsDir.exists()) libsDir.mkdirs()
        val archDir = File(libsDir, arch)
        if (!archDir.exists()) archDir.mkdirs()
        val singBoxFile = File(archDir, "sing-box")
        if (!singBoxFile.exists()) {
            Log.d(TAG, "sing-box binary not found, copying from assets...")
            try {
                context.assets.open("libs/$arch/sing-box").use { input ->
                    singBoxFile.outputStream().use { output -> input.copyTo(output) }
                }
                Runtime.getRuntime().exec(arrayOf("chmod", "755", singBoxFile.absolutePath))
                Log.d(TAG, "sing-box binary installed for $arch")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to copy sing-box: ${e.message}")
            }
        }
    }

    fun start(configPath: String, context: Context): Boolean {
        try {
            if (isRunning) stop()
            val arch = getArch()
            val singBox = File(File(context.filesDir, "libs/$arch"), "sing-box")
            if (!singBox.exists()) {
                Log.e(TAG, "sing-box binary not found at ${singBox.absolutePath}")
                return false
            }

            val pb = ProcessBuilder(singBox.absolutePath, "run", "-c", configPath)
            pb.redirectErrorStream(true)
            pb.environment()["TMPDIR"] = context.cacheDir.absolutePath
            process = pb.start()

            isRunning = true
            totalDownload = 0
            totalUpload = 0

            CoroutineScope(Dispatchers.IO).launch {
                val reader = BufferedReader(InputStreamReader(process!!.inputStream))
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    Log.d(TAG, "sing-box: $line")
                }
            }

            Log.d(TAG, "sing-box started with config: $configPath")
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
