package com.quantumvpn.core

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

object SingBoxCore {
    private const val TAG = "SingBoxCore"
    private var isInitialized = false
    private var isRunning = false
    private var process: Process? = null

    fun init(context: Context) {
        if (isInitialized) return
        try {
            extractBinary(context, "arm64-v8a")
            extractBinary(context, "armeabi-v7a")
            extractBinary(context, "x86_64")
            isInitialized = true
            Log.d(TAG, "sing-box core initialized")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to init sing-box", e)
        }
    }

    private fun extractBinary(context: Context, arch: String) {
        val dir = File(context.filesDir, "libs/$arch")
        if (!dir.exists()) dir.mkdirs()

        val binaryFile = File(dir, "sing-box")
        if (!binaryFile.exists()) {
            try {
                context.assets.open("libs/$arch/sing-box").use { input ->
                    binaryFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                Runtime.getRuntime().exec(arrayOf("chmod", "755", binaryFile.absolutePath"))
            } catch (e: Exception) {
                Log.w(TAG, "Could not extract binary for $arch: ${e.message}")
            }
        }
    }

    suspend fun start(configPath: String, context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            if (isRunning) stop()

            val arch = System.getProperty("os.arch") ?: "arm64-v8a"
            val libsDir = File(context.filesDir, "libs/$arch")
            val binary = File(libsDir, "sing-box")

            if (!binary.exists()) {
                Log.e(TAG, "sing-box binary not found")
                return@withContext false
            }

            val processBuilder = ProcessBuilder(
                binary.absolutePath,
                "run",
                "-c", configPath
            )
            processBuilder.redirectErrorStream(true)
            process = processBuilder.start()

            isRunning = true
            Log.d(TAG, "sing-box started with config: $configPath")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start sing-box", e)
            false
        }
    }

    suspend fun stop() = withContext(Dispatchers.IO) {
        try {
            process?.destroy()
            process = null
            isRunning = false
            Log.d(TAG, "sing-box stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop sing-box", e)
        }
    }

    fun isRunning(): Boolean = isRunning

    suspend fun testConnection(host: String, port: Int, timeout: Int = 5000): Long {
        return withContext(Dispatchers.IO) {
            try {
                val startTime = System.currentTimeMillis()
                val socket = java.net.Socket()
                socket.connect(java.net.InetSocketAddress(host, port), timeout)
                val latency = System.currentTimeMillis() - startTime
                socket.close()
                latency
            } catch (e: Exception) {
                -1L
            }
        }
    }

    fun generateConfig(
        inboundPort: Int = 10808,
        outboundHost: String,
        outboundPort: Int,
        outboundProtocol: String,
        outboundSettings: Map<String, Any>
    ): String {
        val settingsJson = buildString {
            append("{")
            outboundSettings.entries.forEachIndexed { index, (key, value) ->
                if (index > 0) append(",")
                append("\"$key\": \"$value\"")
            }
            append("}")
        }

        return """
        {
            "log": {
                "level": "info",
                "timestamp": true
            },
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "tun0",
                    "inet4_address": "172.19.0.1/30",
                    "auto_route": true,
                    "strict_route": true,
                    "stack": "system",
                    "sniff": true
                },
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": $inboundPort
                }
            ],
            "outbounds": [
                {
                    "type": "$outboundProtocol",
                    "tag": "proxy",
                    $settingsJson
                },
                {
                    "type": "direct",
                    "tag": "direct"
                },
                {
                    "type": "block",
                    "tag": "block"
                },
                {
                    "type": "dns",
                    "tag": "dns-out"
                }
            ],
            "route": {
                "rules": [
                    {
                        "protocol": "dns",
                        "outbound": "dns-out"
                    },
                    {
                        "ip_is_private": true,
                        "outbound": "direct"
                    }
                ],
                "final": "proxy"
            },
            "dns": {
                "servers": [
                    {
                        "address": "https://dns.google/dns-query",
                        "detour": "proxy"
                    },
                    {
                        "address": "223.5.5.5",
                        "detour": "direct"
                    }
                ]
            }
        }
        """.trimIndent()
    }
}
