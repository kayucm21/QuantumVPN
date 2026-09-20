package com.quantumvpn.diagnostics

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.provider.Settings
import com.quantumvpn.BuildConfig
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** Sends a compact redacted report only after the person explicitly taps the UI action. */
class VoluntaryDiagnosticReporter(private val context: Context) {
    suspend fun send(state: DiagnosticState): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val endpoint = BuildConfig.PANEL_UPDATE_BASE_URL.trimEnd('/') + "/api/client/diagnostic"
            val logs = state.logs.takeLast(80).joinToString("\n") { line ->
                SecretRedactor.redact("${line.source}: ${line.message}")
            }.take(12_000)
            val body = JSONObject().apply {
                put("consent", true)
                put("app_version", BuildConfig.VERSION_NAME)
                put("device", Build.MODEL.take(120))
                put("android_id_hash", androidIdHash())
                put("last_error", state.lastFailure?.let { SecretRedactor.redact(it.message) }.orEmpty())
                put("logs", logs)
            }.toString().toByteArray(Charsets.UTF_8)
            val connection = (URL(endpoint).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 12_000
                readTimeout = 20_000
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
                setRequestProperty("Accept", "application/json")
                setRequestProperty("x-device-model", Build.MODEL.take(120))
                setRequestProperty("x-hwid", androidIdHash())
            }
            try {
                connection.outputStream.use { it.write(body) }
                check(connection.responseCode in 200..299) { "Server returned ${connection.responseCode}" }
            } finally { connection.disconnect() }
        }
    }

    @SuppressLint("HardwareIds")
    private fun androidIdHash(): String {
        val raw = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID).orEmpty()
        return MessageDigest.getInstance("SHA-256").digest(raw.toByteArray()).joinToString("") { "%02x".format(it) }.take(16)
    }
}
