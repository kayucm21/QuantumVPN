package com.quantumvpn.updates

import android.os.Build
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

/**
 * Best-effort reporter that pushes Android app errors/health events to the RosPanel admin
 * API (POST <base>/api/app/report). The endpoint is unauthenticated and CSRF-exempt by
 * design, so the app needs no admin session. Calls are fire-and-forget on a background
 * thread and never throw into the caller.
 *
 * Levels: "info" | "warn" | "error". Used both by the global crash handler and by the
 * diagnostics screen so an operator can see client-side failures without a support ticket.
 */
object PanelDiagnosticReporter {
    fun report(
        baseUrl: String,
        appVersion: String,
        device: String,
        level: String,
        message: String,
        detail: String,
    ) {
        if (baseUrl.isBlank()) return
        thread(name = "panel-diag") {
            try {
                val endpoint = "${baseUrl.trimEnd('/')}/api/app/report"
                val payload = JSONObject().apply {
                    put("app_version", appVersion)
                    put("device", device)
                    put("level", level)
                    put("message", message)
                    put("detail", detail)
                }.toString()
                val connection = (URL(endpoint).openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = 20_000
                    readTimeout = 20_000
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json")
                    setRequestProperty("Accept", "application/json")
                    setRequestProperty("User-Agent", "QuantumVPN-Android")
                }
                try {
                    connection.outputStream.use { out ->
                        out.write(payload.toByteArray(Charsets.UTF_8))
                    }
                    connection.responseCode
                } finally {
                    connection.disconnect()
                }
            } catch (_: Throwable) {
                // Best-effort: never break the app because reporting failed.
            }
        }
    }

    fun deviceLabel(): String = "${Build.MANUFACTURER} ${Build.MODEL} (SDK ${Build.VERSION.SDK_INT})"
}
